//! Node-backed end-to-end gate for the Bitcoin `account-for-account-batched`
//! federation migration with **decision (b)** fee-change routing, run against a
//! live `bitcoind` regtest node.
//!
//! This is the Bitcoin analogue of `elements_batched_migration_e2e`
//! (`tests/elements_migration_e2e.rs`) and the live-node counterpart of the
//! offline gate `bitcoin_batched_migration_chains_fee_change_old_fed_offline`
//! (`tests/bitcoin_batched_migration_offline.rs`).
//!
//! The offline gate proves the *logic* Phase B changed — rebuild the chained
//! fee input from the fee account's **OLD** descriptor, route intermediate
//! fee-change to the old-fed address and only the final tx to new-fed — with
//! in-process software keys and **no node**. It asserts witness *structure*
//! (≥4-item 2-of-3 P2WSH witnesses) but cannot prove those witnesses are
//! *consensus-valid*, nor that a real mempool accepts a three-deep chain of
//! partly-unconfirmed transactions.
//!
//! This e2e closes exactly that gap. It funds the old-fed addresses with real
//! regtest coins, then broadcasts the same three-transaction batch to the node:
//!   * tx0: customer C1 + the fee account's real UTXO  → C1 exact, change → fee OLD
//!   * tx1: customer C2 + the chained change from tx0  → C2 exact, change → fee OLD
//!   * tx2: the chained change from tx1 (fee-only)      → drain → fee NEW (final)
//!
//! and asserts, against the live node:
//!   1. **The node accepts all three broadcasts**, including tx1/tx2 which spend
//!      still-unconfirmed chained change (a real mempool ancestor chain). This is
//!      the proof the old-fed-signed witnesses are consensus-valid.
//!   2. Every intermediate fee-change output is locked to the fee account's
//!      **old-fed** address; the fee account's **new-fed** address appears only
//!      in the final tx (and old-fed only in the intermediates).
//!   3. After mining, the customer outputs and the final fee output are present
//!      in the node's UTXO set (`gettxout`), while each intermediate fee-change
//!      output has been **spent** by the next hop (`gettxout` → null) — proving
//!      the chain linked on-chain.
//!   4. Value is conserved: the fee account's initial balance lands at the new
//!      federation, less the cumulative on-chain mining fee.
//!
//! Skips gracefully when `BITCOIN_RPC_URL` (or `BITCOIN_RPC_HOST`/`PORT`) and the
//! RPC credentials are unset, matching the Elements e2e's skip idiom.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::similar_names
)]

use emvault::core::bdk_wallet::bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use emvault::core::bdk_wallet::bitcoin::{
    Address, Amount, FeeRate, Network, OutPoint, Transaction, TxOut, Weight, bip32::Xpriv,
};
use emvault::core::bdk_wallet::miniscript::psbt::PsbtExt;
use emvault::core::bdk_wallet::{KeychainKind, SignOptions, Wallet, bitcoin};
use emvault::core::bitcoincore_rpc::{Auth, Client, RpcApi};
use serde_json::{Value, json};

const NETWORK: Network = Network::Regtest;

// ---------------------------------------------------------------------------
// Software federation + funded-input helpers (mirror the offline gate so this
// e2e exercises the identical chained mechanic, only now broadcasting it).
// ---------------------------------------------------------------------------

/// A 2-of-3 `wsh(sortedmulti(2, ..))` software federation whose three secret
/// keys are held in-process so BDK can derive its scripts *and* sign for it —
/// the same construction the offline gate uses.
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

/// 2-of-3 P2WSH satisfaction-weight estimate (matches the executor's chained
/// input weight at `federation_migration.rs:2355`).
fn sat_weight() -> Weight {
    Weight::from_witness_data_size(260)
}

/// Rebuild the PSBT input for `op` (an output of `tx`) from `fed`'s descriptor
/// via a throwaway wallet — the literal Phase B mechanic
/// (`federation_migration.rs:2339-2360`): the chained change is an unconfirmed
/// output no synced wallet has seen, so apply the tx to a temp wallet and read
/// the UTXO back out. Used here for both the real funding UTXOs and the chained
/// change.
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

/// Build, sign, finalize and extract one batch transaction (identical to the
/// offline gate's `run_tx`). The resulting tx is returned for broadcast.
fn build_tx(
    builder_fed: &SoftFed,
    inputs: &[Funded],
    customers: &[(Address, u64)],
    fee_dest: &Address,
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
        for (addr, amount) in customers {
            builder.add_recipient(addr.script_pubkey(), Amount::from_sat(*amount));
        }
        builder.drain_to(fee_dest.script_pubkey());
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

fn count_at(tx: &Transaction, addr: &Address) -> usize {
    let spk = addr.script_pubkey();
    tx.output.iter().filter(|o| o.script_pubkey == spk).count()
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
// Node plumbing.
// ---------------------------------------------------------------------------

struct NodeEnv {
    rpc_url: String,
    user: String,
    pass: String,
}

/// Read the node connection from the environment. Prefers `BITCOIN_RPC_URL`;
/// otherwise composes it from `BITCOIN_RPC_HOST` + `BITCOIN_RPC_PORT` so the
/// test runs directly off the same `.env` the web app uses. Returns `None`
/// (→ skip) when credentials are missing.
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
/// funding tx is the **real** on-chain tx, so its txid threads through to the
/// migration inputs and the node validates the spend.
fn fund_onchain(wallet_rpc: &Client, fed: &SoftFed, index: u32, btc: f64) -> Funded {
    let addr = fed.address(index);
    // This regtest node has `fallbackfee` disabled and `settxfee` removed, so
    // pass an explicit `fee_rate` (sat/vB) positional arg to `sendtoaddress`:
    // [address, amount, comment, comment_to, subtractfeefromamount, replaceable,
    //  conf_target, estimate_mode, avoid_reuse, fee_rate].
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
    // `gettransaction` returns the raw hex for a wallet tx regardless of txindex.
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

/// `gettxout(txid, vout)` → `Some(value_sat)` if the output is in the UTXO set
/// (confirmed & unspent), `None` if spent or unknown.
fn txout_value(node: &Client, op: OutPoint) -> Option<u64> {
    // include_mempool = false: only count confirmed UTXO-set entries.
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
fn bitcoin_batched_migration_e2e() {
    // 0.01 BTC fee account; small customer balances. Matches the offline gate's
    // proportions, scaled so on-chain fees are comfortably covered.
    const INITIAL_FEE: u64 = 1_000_000; // 0.01 BTC
    const C1_BAL: u64 = 200_000; // 0.002
    const C2_BAL: u64 = 300_000; // 0.003

    let Some(env) = env() else {
        eprintln!(
            "skipping bitcoin_batched_migration_e2e: BITCOIN_RPC_URL/HOST + credentials unset"
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

    // Fee account: an OLD federation (holds funds, signs every hop) and a NEW
    // federation (only the final destination). Each customer has an OLD fed
    // (holds funds) and a NEW fed (migration destination). Seeds are fixed, so
    // each federation's addresses are deterministic; re-runs spend only the
    // specific UTXOs they fund, so leftover state from a prior run is harmless.
    let fee_old = SoftFed::new([0xa1, 0xa2, 0xa3]);
    let fee_new = SoftFed::new([0xa4, 0xa5, 0xa6]);
    let c1_old = SoftFed::new([0xb1, 0xb2, 0xb3]);
    let c1_new = SoftFed::new([0xb4, 0xb5, 0xb6]);
    let c2_old = SoftFed::new([0xc1, 0xc2, 0xc3]);
    let c2_new = SoftFed::new([0xc4, 0xc5, 0xc6]);

    let fee_old_addr = fee_old.address(0);
    let fee_new_addr = fee_new.address(0);
    let c1_dest = c1_new.address(5);
    let c2_dest = c2_new.address(5);

    // Fund the OLD federations on-chain and confirm.
    let fee_utxo = fund_onchain(&wallet_rpc, &fee_old, 0, INITIAL_FEE as f64 / 1e8);
    let c1_utxo = fund_onchain(&wallet_rpc, &c1_old, 0, C1_BAL as f64 / 1e8);
    let c2_utxo = fund_onchain(&wallet_rpc, &c2_old, 0, C2_BAL as f64 / 1e8);
    let _: Vec<String> = node
        .call("generatetoaddress", &[json!(1), json!(mine_addr)])
        .expect("mine funding block");

    // --- tx0: C1 + real fee utxo → C1 exact, change back to fee OLD. ---------
    let tx0 = build_tx(
        &fee_old,
        &[c1_utxo, fee_utxo],
        &[(c1_dest.clone(), C1_BAL)],
        &fee_old_addr,
        &[&c1_old, &fee_old],
    );
    broadcast(&node, &tx0, "tx0");
    assert_eq!(value_at(&tx0, &c1_dest), C1_BAL, "C1 exact");
    let fee0 = fee_of(&tx0, C1_BAL + INITIAL_FEE);
    let change0_value = value_at(&tx0, &fee_old_addr);
    assert_eq!(
        change0_value,
        INITIAL_FEE - fee0,
        "after tx0 the fee account holds its balance minus fee0 (C1 untouched)"
    );
    assert_eq!(
        count_at(&tx0, &fee_new_addr),
        0,
        "fee account's NEW-fed address must not appear in an intermediate tx"
    );
    let change0_op = outpoint_at(&tx0, &fee_old_addr);
    // Rebuild the chained change from the fee account's OLD descriptor — the
    // unconfirmed-UTXO temp-wallet path Phase B reworked.
    let chained0 = enrich(&fee_old, &tx0, change0_op);

    // --- tx1: C2 + chained change → C2 exact, change back to fee OLD. -------
    let tx1 = build_tx(
        &fee_old,
        &[c2_utxo, chained0],
        &[(c2_dest.clone(), C2_BAL)],
        &fee_old_addr,
        &[&c2_old, &fee_old],
    );
    broadcast(
        &node,
        &tx1,
        "tx1 (spends unconfirmed chained change from tx0)",
    );
    assert_eq!(value_at(&tx1, &c2_dest), C2_BAL, "C2 exact");
    let fee1 = fee_of(&tx1, C2_BAL + change0_value);
    let change1_value = value_at(&tx1, &fee_old_addr);
    assert_eq!(
        change1_value,
        INITIAL_FEE - fee0 - fee1,
        "after tx1 the fee account holds its balance minus fees so far"
    );
    assert_eq!(
        count_at(&tx1, &fee_new_addr),
        0,
        "fee account's NEW-fed address must not appear in an intermediate tx"
    );
    let change1_op = outpoint_at(&tx1, &fee_old_addr);
    let chained1 = enrich(&fee_old, &tx1, change1_op);

    // --- tx2: fee-only final tx → drain to fee NEW. The chained input is still
    // OLD-fed-locked, so the OLD federation signs it; only the OUTPUT crosses to
    // the new federation. ----------------------------------------------------
    let tx2 = build_tx(&fee_old, &[chained1], &[], &fee_new_addr, &[&fee_old]);
    broadcast(
        &node,
        &tx2,
        "tx2 (final, spends unconfirmed chained change from tx1)",
    );
    assert_eq!(
        tx2.output.len(),
        1,
        "final fee-only tx: single drain output"
    );
    let fee2 = fee_of(&tx2, change1_value);
    let final_value = value_at(&tx2, &fee_new_addr);
    assert_eq!(
        count_at(&tx2, &fee_old_addr),
        0,
        "the final tx routes the fee account to the NEW federation, not OLD"
    );

    // Value conservation across the whole chain.
    assert_eq!(
        final_value + fee0 + fee1 + fee2,
        INITIAL_FEE,
        "fee account paid exactly the cumulative fee; customers got full balances"
    );

    // Confirm the chain and verify the on-chain UTXO set.
    let _: Vec<String> = node
        .call("generatetoaddress", &[json!(2), json!(mine_addr)])
        .expect("mine confirmation blocks");

    // Customer destinations and the final fee output are confirmed & unspent.
    assert_eq!(
        txout_value(&node, outpoint_at(&tx0, &c1_dest)),
        Some(C1_BAL),
        "C1 migrated balance present in the UTXO set"
    );
    assert_eq!(
        txout_value(&node, outpoint_at(&tx1, &c2_dest)),
        Some(C2_BAL),
        "C2 migrated balance present in the UTXO set"
    );
    assert_eq!(
        txout_value(&node, outpoint_at(&tx2, &fee_new_addr)),
        Some(final_value),
        "fee account's final new-fed output present in the UTXO set"
    );

    // The intermediate fee-change outputs were consumed by the next hop, so they
    // are no longer in the UTXO set — proving the chain linked on-chain.
    assert_eq!(
        txout_value(&node, change0_op),
        None,
        "tx0's intermediate fee-change was spent by tx1"
    );
    assert_eq!(
        txout_value(&node, change1_op),
        None,
        "tx1's intermediate fee-change was spent by tx2"
    );
}
