//! Node-backed end-to-end gate for the **deposit → withdrawal** round-trip of a
//! Bitcoin federation wallet, run against a live `bitcoind` regtest node.
//!
//! Until now the customer-facing receive/spend flow was only exercised
//! *implicitly*, folded into the larger migration e2e
//! (`tests/bitcoin_batched_migration_e2e.rs`) and the examples. This gate makes
//! it first-class and minimal: it proves, against the live chain backend, that
//!
//!   1. **Deposit** — funds sent to a federation's external address land in the
//!      node's UTXO set at the exact deposited value (`gettxout` → the deposit),
//!      i.e. the on-chain balance the app would display is real.
//!   2. **Withdrawal** — a send-max/drain transaction, built and signed by the
//!      2-of-3 federation and broadcast to the node, is accepted by a real
//!      mempool (consensus-valid 2-of-3 P2WSH witnesses), and after mining the
//!      deposit outpoint is **spent** (`gettxout` → null) while the withdrawal
//!      destination holds the balance minus the on-chain mining fee.
//!
//! The federation is an in-process `wsh(sortedmulti(2, ..))` software wallet —
//! identical construction to the migration gates — so the whole round-trip runs
//! with no PKCS#11 handle, exercising the receive/spend mechanic BDK and the
//! node share with the HSM path.
//!
//! Skips gracefully when `BITCOIN_RPC_URL` (or `BITCOIN_RPC_HOST`/`PORT`) and the
//! RPC credentials are unset, matching the migration e2e's skip idiom exactly.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::similar_names
)]

use emvault::core::bdk_wallet::bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use emvault::core::bdk_wallet::bitcoin::{
    Address, FeeRate, Network, OutPoint, Transaction, TxOut, Weight, bip32::Xpriv,
};
use emvault::core::bdk_wallet::miniscript::psbt::PsbtExt;
use emvault::core::bdk_wallet::{KeychainKind, SignOptions, Wallet, bitcoin};
use emvault::core::bitcoincore_rpc::{Auth, Client, RpcApi};
use serde_json::{Value, json};

const NETWORK: Network = Network::Regtest;

// ---------------------------------------------------------------------------
// Software federation + funded-input helpers (mirror the migration e2e so this
// gate exercises the identical receive/spend mechanic, only now a single-hop
// deposit → drain instead of a chained batch).
// ---------------------------------------------------------------------------

/// A 2-of-3 `wsh(sortedmulti(2, ..))` software federation whose three secret
/// keys are held in-process so BDK can derive its scripts *and* sign for it.
struct SoftFed {
    external: String,
    internal: String,
}

impl SoftFed {
    fn new(seeds: [u8; 3]) -> Self {
        let xprvs: Vec<Xpriv> = seeds
            .iter()
            .map(|s| Xpriv::new_master(NETWORK, &[*s; 32]).expect("valid master xprv"))
            .collect();
        let branch = |chain: u8| {
            let keys: Vec<String> = xprvs.iter().map(|x| format!("{x}/{chain}/*")).collect();
            format!("wsh(sortedmulti(2,{}))", keys.join(","))
        };
        Self {
            external: branch(0),
            internal: branch(1),
        }
    }

    fn wallet(&self) -> Wallet {
        Wallet::create(self.external.clone(), self.internal.clone())
            .network(NETWORK)
            .create_wallet_no_persist()
            .expect("valid software descriptors")
    }

    fn address(&self, index: u32) -> Address {
        self.wallet()
            .peek_address(KeychainKind::External, index)
            .address
    }

    /// Sign every input of `psbt` belonging to this federation (all three keys
    /// present → one call satisfies the 2-of-3). Finalization is done globally.
    fn sign(&self, psbt: &mut bitcoin::Psbt) {
        let opts = SignOptions {
            trust_witness_utxo: true,
            try_finalize: false,
            ..Default::default()
        };
        self.wallet().sign(psbt, opts).expect("software sign");
    }
}

/// A spendable input: outpoint + enriched PSBT input + satisfaction weight.
struct Funded {
    op: OutPoint,
    input: bitcoin::psbt::Input,
    weight: Weight,
}

/// 2-of-3 P2WSH satisfaction-weight estimate.
fn sat_weight() -> Weight {
    Weight::from_witness_data_size(260)
}

/// Rebuild the PSBT input for `op` (an output of `tx`) from `fed`'s descriptor
/// via a throwaway wallet: apply the tx to a temp wallet and read the UTXO back
/// out so the enriched input carries the witness script + BIP-32 derivations the
/// federation needs to sign.
fn enrich(fed: &SoftFed, tx: &Transaction, op: OutPoint) -> Funded {
    let mut tw = fed.wallet();
    let _ = tw.reveal_next_address(KeychainKind::External);
    tw.apply_unconfirmed_txs(vec![(tx.clone(), 0)]);
    let local = tw
        .get_utxo(op)
        .expect("utxo present in temp wallet after insert");
    let input = tw
        .get_psbt_input(local, None, false)
        .expect("build psbt input for utxo");
    Funded {
        op,
        input,
        weight: sat_weight(),
    }
}

/// Build, sign, finalize and extract a single drain transaction: every `input`
/// is spent and the entire remaining value (less fee) is sent to `dest` via
/// `drain_to` (send-max). The federations in `signers` each sign their inputs.
fn build_drain_tx(
    builder_fed: &SoftFed,
    inputs: &[Funded],
    dest: &Address,
    signers: &[&SoftFed],
) -> Transaction {
    let mut wallet = builder_fed.wallet();
    let mut psbt = {
        let mut builder = wallet.build_tx();
        builder.manually_selected_only();
        for f in inputs {
            builder
                .add_foreign_utxo(f.op, f.input.clone(), f.weight)
                .expect("add foreign utxo");
        }
        builder.drain_to(dest.script_pubkey());
        builder.fee_rate(FeeRate::from_sat_per_vb(2).expect("valid fee rate"));
        builder.finish().expect("psbt construction")
    };

    for fed in signers {
        fed.sign(&mut psbt);
    }

    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    psbt.finalize_mut(&secp).expect("finalize all inputs");

    let tx = psbt.extract_tx().expect("extract tx");
    for inp in &tx.input {
        assert!(
            inp.witness.len() >= 4,
            "each input finalized with a 2-of-3 P2WSH witness"
        );
    }
    tx
}

fn fee_of(tx: &Transaction, input_total: u64) -> u64 {
    let out: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    input_total - out
}

fn outpoint_at(tx: &Transaction, addr: &Address) -> OutPoint {
    let spk = addr.script_pubkey();
    let vout = tx
        .output
        .iter()
        .position(|o| o.script_pubkey == spk)
        .expect("expected output present");
    OutPoint::new(
        tx.compute_txid(),
        u32::try_from(vout).expect("vout fits u32"),
    )
}

fn value_at(tx: &Transaction, addr: &Address) -> u64 {
    let spk = addr.script_pubkey();
    let matches: Vec<&TxOut> = tx
        .output
        .iter()
        .filter(|o| o.script_pubkey == spk)
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "exactly one output at the expected address"
    );
    matches[0].value.to_sat()
}

// ---------------------------------------------------------------------------
// Node plumbing (identical idiom to the migration e2e).
// ---------------------------------------------------------------------------

struct NodeEnv {
    rpc_url: String,
    user: String,
    pass: String,
}

/// Read the node connection from the environment. Prefers `BITCOIN_RPC_URL`;
/// otherwise composes it from `BITCOIN_RPC_HOST` + `BITCOIN_RPC_PORT`. Returns
/// `None` (→ skip) when credentials are missing.
fn env() -> Option<NodeEnv> {
    let user = std::env::var("BITCOIN_RPC_USER").ok()?;
    let pass = std::env::var("BITCOIN_RPC_PASSWORD").ok()?;
    let rpc_url = std::env::var("BITCOIN_RPC_URL").ok().or_else(|| {
        let host = std::env::var("BITCOIN_RPC_HOST").ok()?;
        let port = std::env::var("BITCOIN_RPC_PORT").ok()?;
        Some(format!("http://{host}:{port}"))
    })?;
    Some(NodeEnv {
        rpc_url,
        user,
        pass,
    })
}

fn client(env: &NodeEnv, path: &str) -> Client {
    Client::new(
        &format!("{}{path}", env.rpc_url),
        Auth::UserPass(env.user.clone(), env.pass.clone()),
    )
    .expect("rpc client")
}

/// Fund `fed`'s external address `index` with `btc` coins from the node wallet,
/// then enrich the resulting UTXO into a foreign-spendable PSBT input. The
/// funding tx is the **real** on-chain deposit.
fn fund_onchain(wallet_rpc: &Client, fed: &SoftFed, index: u32, btc: f64) -> Funded {
    let addr = fed.address(index);
    let txid: String = wallet_rpc
        .call(
            "sendtoaddress",
            &[
                json!(addr.to_string()),
                json!(btc),
                json!(""),
                json!(""),
                json!(false),
                json!(true),
                Value::Null,
                json!("unset"),
                json!(false),
                json!(10), // sat/vB
            ],
        )
        .expect("sendtoaddress");
    let info: Value = wallet_rpc
        .call("gettransaction", &[json!(txid)])
        .expect("gettransaction");
    let raw_hex = info["hex"].as_str().expect("tx hex");
    let funding: Transaction = deserialize_hex(raw_hex).expect("decode funding tx");
    let spk = addr.script_pubkey();
    let vout = funding
        .output
        .iter()
        .position(|o| o.script_pubkey == spk)
        .expect("funding output paying our address");
    let op = OutPoint::new(
        funding.compute_txid(),
        u32::try_from(vout).expect("vout fits u32"),
    );
    enrich(fed, &funding, op)
}

/// Broadcast `tx`, asserting the node accepts it and echoes the expected txid.
fn broadcast(node: &Client, tx: &Transaction, label: &str) {
    let hex = serialize_hex(tx);
    let txid: String = node
        .call("sendrawtransaction", &[json!(hex)])
        .unwrap_or_else(|e| panic!("{label}: node rejected broadcast: {e}"));
    assert_eq!(
        txid,
        tx.compute_txid().to_string(),
        "{label}: node echoed the broadcast txid"
    );
}

/// `gettxout(txid, vout)` → `Some(value_sat)` if the output is in the confirmed
/// UTXO set, `None` if spent or unknown.
fn txout_value(node: &Client, op: OutPoint) -> Option<u64> {
    let v: Value = node
        .call(
            "gettxout",
            &[json!(op.txid.to_string()), json!(op.vout), json!(false)],
        )
        .expect("gettxout");
    if v.is_null() {
        None
    } else {
        Some((v["value"].as_f64().expect("value") * 1e8).round() as u64)
    }
}

#[test]
fn bitcoin_deposit_withdrawal_e2e() {
    // 0.05 BTC deposit — comfortably covers the drain's on-chain fee.
    const DEPOSIT: u64 = 5_000_000;

    let Some(env) = env() else {
        eprintln!(
            "skipping bitcoin_deposit_withdrawal_e2e: BITCOIN_RPC_URL/HOST + credentials unset"
        );
        return;
    };

    let node = client(&env, "");
    let wallet_rpc = client(&env, "/wallet/default");

    // Sanity: the node is reachable and on regtest.
    let info: Value = node
        .call("getblockchaininfo", &[])
        .expect("getblockchaininfo");
    assert_eq!(
        info["chain"].as_str(),
        Some("regtest"),
        "this e2e only runs against a regtest node"
    );
    let mine_addr: String = wallet_rpc
        .call("getnewaddress", &[])
        .expect("getnewaddress");

    // The customer's federation wallet (holds the deposit, signs the
    // withdrawal) and a separate destination federation standing in for the
    // withdrawal target (the "cash-out" address the drain sends to). Fixed
    // seeds → deterministic addresses; re-runs only spend the UTXO they fund.
    let fed = SoftFed::new([0xd1, 0xd2, 0xd3]);
    let sink = SoftFed::new([0xe1, 0xe2, 0xe3]);
    let withdraw_addr = sink.address(0);

    // --- Deposit: fund the federation address on-chain and confirm. ---------
    let deposit = fund_onchain(&wallet_rpc, &fed, 0, DEPOSIT as f64 / 1e8);
    let deposit_op = deposit.op;
    let _: Vec<String> = node
        .call("generatetoaddress", &[json!(1), json!(mine_addr.clone())])
        .expect("mine deposit block");

    // The deposit is in the node's UTXO set at the exact deposited value —
    // this is the balance the chain backend reports for the federation.
    assert_eq!(
        txout_value(&node, deposit_op),
        Some(DEPOSIT),
        "deposit present in the UTXO set at the funded value"
    );

    // --- Withdrawal: drain the deposit (send-max) back to the sink. ---------
    let withdrawal = build_drain_tx(&fed, &[deposit], &withdraw_addr, &[&fed]);
    broadcast(&node, &withdrawal, "withdrawal (send-max drain)");
    assert_eq!(
        withdrawal.output.len(),
        1,
        "send-max drain: single withdrawal output"
    );
    let fee = fee_of(&withdrawal, DEPOSIT);
    let withdrawn = value_at(&withdrawal, &withdraw_addr);
    assert_eq!(
        withdrawn + fee,
        DEPOSIT,
        "withdrawal drained the deposit less exactly the mining fee"
    );

    // Confirm the withdrawal.
    let _: Vec<String> = node
        .call("generatetoaddress", &[json!(2), json!(mine_addr)])
        .expect("mine confirmation blocks");

    // The deposit outpoint is now spent (drained); the withdrawal destination
    // holds the balance minus the mining fee.
    assert_eq!(
        txout_value(&node, deposit_op),
        None,
        "deposit outpoint spent by the withdrawal"
    );
    assert_eq!(
        txout_value(&node, outpoint_at(&withdrawal, &withdraw_addr)),
        Some(withdrawn),
        "withdrawal output present in the UTXO set"
    );
}
