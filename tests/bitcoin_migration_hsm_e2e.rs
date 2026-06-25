//! P4 (Phase D) — **node-backed dev-HSM** Bitcoin `account-for-account-batched`
//! federation migration e2e with **decision (b)** fee-change routing.
//!
//! This is the live-node analogue of `bitcoin_migration_hsm_signing.rs`. Where
//! that gate proves the chained three-transaction batch signs correctly against
//! real dev-HSM tokens *node-free* (synthetic UTXOs, never broadcast), this
//! drives the full pipeline against a live `bitcoind` regtest node:
//!
//!   fund (bitcoind) → enrich (the Phase B temp-wallet + `apply_unconfirmed_txs`
//!   + `get_psbt_input` mechanic) → **dev-HSM sign** (real cryptoki ECDSA) →
//!   finalize → **broadcast (bitcoind accepts, including the chained
//!   partly-unconfirmed spends)**.
//!
//! The old-federation (signed) accounts use `Pkcs11Signer`s over
//! `libasterism_dev_hsm.so`; the new-federation destinations are dev-HSM
//! federations too but are never signed here (their outputs are spent by a
//! *future* migration) — only their addresses matter.
//!
//! Decision (b) is asserted end to end: every intermediate fee-change output is
//! locked to the fee account's **old-fed** address and the fee account's
//! **new-fed** address appears **only** in the final tx; bitcoind accepts all
//! three chained broadcasts; customers receive their exact balances; the fee
//! account pays exactly the cumulative mining fee.
//!
//! Skips cleanly when either layer is unavailable:
//!   * the live node — activated only when `BITCOIN_RPC_URL` is explicitly
//!     exported (with `BITCOIN_RPC_USER` / `BITCOIN_RPC_PASSWORD`; optional
//!     `BITCOIN_WALLET_NAME`, default `asterism-pkcs11` to match `config.rs`),
//!     mirroring how the sibling Elements e2es gate on `ELEMENTS_RPC_URL`, or
//!   * `PKCS11_LIB` + `APP_HSM_{5,6,7}_LABEL`/`_PIN` (the dev-HSM federation,
//!     loaded from `.env`).
//!
//! Run with (from `test-app-pkcs11/`, with `.env` providing the HSM + node vars):
//! ```bash
//! cargo test --test bitcoin_migration_hsm_e2e -- --nocapture --test-threads=1
//! ```

#![allow(
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::doc_lazy_continuation,
    clippy::cast_precision_loss
)]

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use asterism_core::descriptor::{to_multipath_string, KeyMode};
use asterism_core::federation::Federation;
use asterism_core::network::NetworkType;
use bdk_wallet::bitcoin::bip32::DerivationPath as BtcDerivationPath;
use bdk_wallet::bitcoin::consensus::Encodable;
use bdk_wallet::bitcoin::{
    self, Address, Amount, FeeRate, Network, OutPoint, Transaction, TxOut, Weight,
};
use bdk_wallet::miniscript::psbt::PsbtExt;
use bdk_wallet::signer::SignerOrdering;
use bdk_wallet::{KeychainKind, SignOptions, Wallet};

use asterism_dev_signer::DevBackend;
use asterism_pkcs11::{key_ops, Pkcs11Config, Pkcs11Session, Pkcs11Signer, SlotIdentifier};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use serde_json::json;
use test_app_pkcs11::wallet::NetworkPatchedSigner;

const NETWORK: Network = Network::Regtest;
const NETWORK_TYPE: NetworkType = NetworkType::Bitcoin(Network::Regtest);

/// Serialize the test(s) in this binary: the dev-HSM shim is process-global
/// (one `C_Initialize`/`C_Finalize` per process). The node-backed test is the
/// only one here today, but keep the lock so future additions stay safe.
fn hsm_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

/// 2-of-3 P2WSH satisfaction weight estimate (matches the executor's chained
/// input weight at `federation_migration.rs:2355`). Offline fee math only.
fn sat_weight() -> Weight {
    Weight::from_witness_data_size(260)
}

// ---------------------------------------------------------------------------
// Node environment
// ---------------------------------------------------------------------------

struct NodeEnv {
    rpc_url: String,
    rpc_user: String,
    rpc_pass: String,
    wallet_name: String,
}

fn node_env() -> Option<NodeEnv> {
    // Opt-in gate: the live layer activates only when `BITCOIN_RPC_URL` is
    // **explicitly exported** (e.g. `http://127.0.0.1:18443`), signalling "the
    // regtest node is up, run the e2e". We deliberately do not load `.env` or
    // compose from `BITCOIN_RPC_HOST/PORT`, so the test skips cleanly under a
    // plain `cargo test` even though `.env` exists. `BITCOIN_WALLET_NAME`
    // defaults to `asterism-pkcs11`, matching `config.rs`.
    Some(NodeEnv {
        rpc_url: std::env::var("BITCOIN_RPC_URL").ok()?,
        rpc_user: std::env::var("BITCOIN_RPC_USER").ok()?,
        rpc_pass: std::env::var("BITCOIN_RPC_PASSWORD").ok()?,
        wallet_name: std::env::var("BITCOIN_WALLET_NAME")
            .unwrap_or_else(|_| "asterism-pkcs11".to_string()),
    })
}

/// A wallet-scoped RPC client (for `sendtoaddress` / `getnewaddress` /
/// `gettransaction` / `generatetoaddress`).
fn node_client(env: &NodeEnv) -> Client {
    Client::new(
        &format!("{}/wallet/{}", env.rpc_url, env.wallet_name),
        Auth::UserPass(env.rpc_user.clone(), env.rpc_pass.clone()),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// Dev-HSM environment (mirrors bitcoin_migration_hsm_signing.rs)
// ---------------------------------------------------------------------------

const FED_TOKEN_INDICES: [u8; 3] = [5, 6, 7];

struct DevEnv {
    lib: PathBuf,
    tokens: Vec<(String, String)>,
}

fn dev_env() -> Option<DevEnv> {
    let _ = dotenvy::from_path(concat!(env!("CARGO_MANIFEST_DIR"), "/.env"));
    let lib = PathBuf::from(std::env::var("PKCS11_LIB").ok()?);
    if !lib.exists() {
        eprintln!("skipping: PKCS11_LIB {} does not exist", lib.display());
        return None;
    }
    let mut tokens = Vec::new();
    for i in FED_TOKEN_INDICES {
        let label = std::env::var(format!("APP_HSM_{i}_LABEL")).ok()?;
        let pin = std::env::var(format!("APP_HSM_{i}_PIN")).ok()?;
        tokens.push((label, pin));
    }
    Some(DevEnv { lib, tokens })
}

fn reset_label(session: &Pkcs11Session, label: &str) {
    let _ = key_ops::delete_key(session, label);
}

/// A dev-HSM 2-of-3 Bitcoin federation: its public `wsh(sortedmulti(2,..))`
/// multipath descriptor (for address derivation / enrichment) plus the three
/// real `Pkcs11Signer`s that satisfy it.
struct HsmFed {
    descriptor: bdk_wallet::miniscript::Descriptor<bdk_wallet::miniscript::DescriptorPublicKey>,
    signers: Vec<Pkcs11Signer>,
}

impl HsmFed {
    fn new(env: &DevEnv, key_tag: &str, acct: u32) -> Self {
        let path = BtcDerivationPath::from_str(&format!("m/48'/1'/{acct}'/2'")).unwrap();
        let signers: Vec<Pkcs11Signer> = env
            .tokens
            .iter()
            .enumerate()
            .map(|(pos, (token_label, pin))| {
                let key_label = format!("hsmbtce2e-{key_tag}-a{acct}-m{pos}");
                let cfg = Pkcs11Config::new(
                    &env.lib,
                    SlotIdentifier::label(token_label),
                    pin.clone(),
                    path.clone(),
                    Box::new(DevBackend),
                );
                let session = Pkcs11Session::open(&cfg, &SlotIdentifier::label(token_label), pin)
                    .expect("open dev HSM session");
                reset_label(&session, &key_label);
                Pkcs11Signer::derive_from_seed(
                    session,
                    &key_label,
                    &path,
                    NETWORK,
                    Box::new(DevBackend),
                    &[],
                )
                .expect("derive dev HSM key")
            })
            .collect();

        let patched: Vec<NetworkPatchedSigner> = signers
            .iter()
            .map(|s| NetworkPatchedSigner::new(s.clone(), NETWORK))
            .collect();
        let fed = Federation::with_key_mode(2, patched, NETWORK_TYPE, KeyMode::Ranged)
            .expect("federation construction");
        let desc_str = to_multipath_string(fed.try_descriptor().expect("descriptor"));
        let descriptor = desc_str.parse().expect("valid multipath descriptor");

        Self { descriptor, signers }
    }

    fn wallet(&self) -> Wallet {
        Wallet::create_from_two_path_descriptor(self.descriptor.clone())
            .network(NETWORK)
            .create_wallet_no_persist()
            .expect("wallet from public descriptor")
    }

    fn signing_wallet(&self) -> Wallet {
        let mut w = self.wallet();
        for s in &self.signers {
            let arc: Arc<Pkcs11Signer> = Arc::new(s.clone());
            w.add_signer(KeychainKind::External, SignerOrdering::default(), arc.clone());
            w.add_signer(KeychainKind::Internal, SignerOrdering::default(), arc);
        }
        w
    }

    fn address(&self, index: u32) -> Address {
        self.wallet().peek_address(KeychainKind::External, index).address
    }

    /// Index-scoped signing: clear `bip32_derivation` on inputs this federation
    /// does **not** own (so its shared-fingerprint signers skip them), run the
    /// HSM signers, then restore. Mirrors the executor's per-account scoping.
    fn sign_scoped(&self, psbt: &mut bitcoin::Psbt, owned: &[OutPoint]) {
        let owned_set: std::collections::HashSet<OutPoint> = owned.iter().copied().collect();
        let mut saved = Vec::new();
        for (i, inp) in psbt.inputs.iter_mut().enumerate() {
            let op = psbt.unsigned_tx.input[i].previous_output;
            if !owned_set.contains(&op) {
                saved.push((i, std::mem::take(&mut inp.bip32_derivation)));
            }
        }
        let opts = SignOptions {
            trust_witness_utxo: true,
            try_finalize: false,
            ..Default::default()
        };
        self.signing_wallet().sign(psbt, opts).expect("HSM sign");
        for (i, d) in saved {
            psbt.inputs[i].bip32_derivation = d;
        }
    }
}

/// A spendable input: outpoint + enriched PSBT input + satisfaction weight.
struct Funded {
    op: OutPoint,
    input: bitcoin::psbt::Input,
    weight: Weight,
}

/// Rebuild the PSBT input for `op` (an output of `tx`) from `fed`'s public
/// descriptor via a throwaway wallet — the literal Phase B chained mechanic
/// (`federation_migration.rs:2342-2360`). Works for confirmed funding outputs
/// and for unconfirmed chained change alike.
fn enrich(fed: &HsmFed, tx: &Transaction, op: OutPoint) -> Funded {
    let mut tw = fed.wallet();
    let _ = tw.reveal_next_address(KeychainKind::External);
    tw.apply_unconfirmed_txs(vec![(tx.clone(), 0)]);
    let local = tw.get_utxo(op).expect("utxo present in temp wallet after insert");
    let input = tw.get_psbt_input(local, None, false).expect("build psbt input");
    Funded {
        op,
        input,
        weight: sat_weight(),
    }
}

/// Fund `fed`'s address at `index` with `amount` sats from the node wallet, mine
/// one block to confirm, then enrich the funding output into a foreign-spendable
/// PSBT input — the real-node replacement for the offline gate's synthetic
/// `fund()`.
fn fund_via_node(node: &Client, fed: &HsmFed, index: u32, amount: u64, mine_to: &str) -> Funded {
    let addr = fed.address(index);
    let amount_btc = amount as f64 / 100_000_000.0;
    // Pass an explicit `fee_rate` (sat/vB) positional arg so funding works on a
    // regtest node with `fallbackfee` disabled (and `settxfee` removed):
    // [address, amount, comment, comment_to, subtractfeefromamount, replaceable,
    //  conf_target, estimate_mode, avoid_reuse, fee_rate].
    let txid: String = node
        .call(
            "sendtoaddress",
            &[
                json!(addr.to_string()),
                json!(amount_btc),
                json!(""),
                json!(""),
                json!(false),
                json!(true),
                serde_json::Value::Null,
                json!("unset"),
                json!(false),
                json!(10), // sat/vB
            ],
        )
        .expect("sendtoaddress");
    let _: Vec<String> = node
        .call("generatetoaddress", &[json!(1), json!(mine_to)])
        .expect("mine funding");

    // Pull the funding tx back from the wallet (no -txindex needed: it is a
    // wallet tx) and decode into a bdk_wallet::bitcoin::Transaction.
    let gettx: serde_json::Value = node.call("gettransaction", &[json!(txid)]).expect("gettransaction");
    let hex = gettx["hex"].as_str().expect("tx hex present");
    let funding: Transaction =
        bitcoin::consensus::encode::deserialize_hex(hex).expect("decode funding tx");

    let spk = addr.script_pubkey();
    let vout = funding
        .output
        .iter()
        .position(|o| o.script_pubkey == spk)
        .expect("funding output to our address present");
    let op = OutPoint::new(funding.compute_txid(), u32::try_from(vout).expect("vout fits u32"));
    enrich(fed, &funding, op)
}

/// Build → sign (index-scoped per owning federation) → finalize → extract one
/// batch transaction (not yet broadcast).
fn build_tx(
    builder_fed: &HsmFed,
    inputs: &[Funded],
    customers: &[(Address, u64)],
    fee_dest: &Address,
    signers: &[(&HsmFed, Vec<OutPoint>)],
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

    for (fed, owned) in signers {
        fed.sign_scoped(&mut psbt, owned);
    }

    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    psbt.finalize_mut(&secp).expect("finalize all inputs");

    let tx = psbt.extract_tx().expect("extract tx");
    for inp in &tx.input {
        assert!(
            inp.witness.len() >= 4,
            "each input finalized with a real 2-of-3 P2WSH witness"
        );
    }
    tx
}

/// Broadcast a fully-signed tx to the node; the node accepting it (returning a
/// txid) is the node-backed signal. Returns the node-reported txid.
fn broadcast(node: &Client, tx: &Transaction) -> bitcoin::Txid {
    let mut raw = Vec::new();
    tx.consensus_encode(&mut raw).expect("encode tx");
    node.send_raw_transaction(&raw[..]).expect("node accepts broadcast")
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
    OutPoint::new(tx.compute_txid(), u32::try_from(vout).expect("vout fits u32"))
}

fn count_at(tx: &Transaction, addr: &Address) -> usize {
    let spk = addr.script_pubkey();
    tx.output.iter().filter(|o| o.script_pubkey == spk).count()
}

fn value_at(tx: &Transaction, addr: &Address) -> u64 {
    let spk = addr.script_pubkey();
    let matches: Vec<&TxOut> = tx.output.iter().filter(|o| o.script_pubkey == spk).collect();
    assert_eq!(matches.len(), 1, "exactly one output at the expected address");
    matches[0].value.to_sat()
}

#[test]
fn bitcoin_batched_migration_chains_fee_change_old_fed_hsm_e2e() {
    const INITIAL_FEE: u64 = 1_000_000;
    const C1_BAL: u64 = 200_000;
    const C2_BAL: u64 = 300_000;

    let Some(nenv) = node_env() else {
        eprintln!("skipping bitcoin_batched_migration_*_hsm_e2e: BITCOIN_RPC_URL unset");
        return;
    };
    let Some(env) = dev_env() else {
        eprintln!("skipping bitcoin_batched_migration_*_hsm_e2e: dev HSM unavailable");
        return;
    };
    let _serial = hsm_lock().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let key_tag = format!("{:x}", std::process::id());

    let node = node_client(&nenv);
    let mine_to: String = node.call("getnewaddress", &[]).expect("getnewaddress");

    // Fee account: OLD fed (holds funds, signs every hop) + NEW fed (final
    // destination only). Customers each: OLD fed (funds) + NEW fed (destination).
    let fee_old = HsmFed::new(&env, &key_tag, 910_001);
    let fee_new = HsmFed::new(&env, &key_tag, 910_002);
    let c1_old = HsmFed::new(&env, &key_tag, 910_003);
    let c1_new = HsmFed::new(&env, &key_tag, 910_004);
    let c2_old = HsmFed::new(&env, &key_tag, 910_005);
    let c2_new = HsmFed::new(&env, &key_tag, 910_006);

    let fee_old_addr = fee_old.address(0);
    let fee_new_addr = fee_new.address(0);
    let c1_dest = c1_new.address(5);
    let c2_dest = c2_new.address(5);

    // Fund the old-fed accounts on the live node.
    let fee_utxo = fund_via_node(&node, &fee_old, 0, INITIAL_FEE, &mine_to);
    let c1_utxo = fund_via_node(&node, &c1_old, 0, C1_BAL, &mine_to);
    let c2_utxo = fund_via_node(&node, &c2_old, 0, C2_BAL, &mine_to);

    // --- tx0: C1 + real fee utxo → C1 exact, change back to fee OLD. --------
    let (c1_op, fee_op) = (c1_utxo.op, fee_utxo.op);
    let tx0 = build_tx(
        &fee_old,
        &[c1_utxo, fee_utxo],
        &[(c1_dest.clone(), C1_BAL)],
        &fee_old_addr,
        &[(&c1_old, vec![c1_op]), (&fee_old, vec![fee_op])],
    );
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
    let txid0 = broadcast(&node, &tx0);
    assert_eq!(txid0, tx0.compute_txid(), "node accepted tx0");
    // Rebuild the chained change from the fee account's OLD descriptor.
    let chained0 = enrich(&fee_old, &tx0, outpoint_at(&tx0, &fee_old_addr));

    // --- tx1: C2 + chained change → C2 exact, change back to fee OLD. -------
    let (c2_op, chained0_op) = (c2_utxo.op, chained0.op);
    let tx1 = build_tx(
        &fee_old,
        &[c2_utxo, chained0],
        &[(c2_dest.clone(), C2_BAL)],
        &fee_old_addr,
        &[(&c2_old, vec![c2_op]), (&fee_old, vec![chained0_op])],
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
    let txid1 = broadcast(&node, &tx1);
    assert_eq!(txid1, tx1.compute_txid(), "node accepted tx1 (spends unconfirmed chained change)");
    let chained1 = enrich(&fee_old, &tx1, outpoint_at(&tx1, &fee_old_addr));

    // --- tx2: fee-only final tx → drain to fee NEW. The chained input is
    // still OLD-fed-locked, so the OLD federation signs it; only the OUTPUT
    // crosses to the new federation. ----------------------------------------
    let chained1_op = chained1.op;
    let tx2 = build_tx(
        &fee_old,
        &[chained1],
        &[],
        &fee_new_addr,
        &[(&fee_old, vec![chained1_op])],
    );
    assert_eq!(tx2.output.len(), 1, "final fee-only tx: single drain output");
    let fee2 = fee_of(&tx2, change1_value);
    let final_value = value_at(&tx2, &fee_new_addr);
    assert_eq!(
        count_at(&tx2, &fee_old_addr),
        0,
        "the final tx routes the fee account to the NEW federation, not OLD"
    );
    let txid2 = broadcast(&node, &tx2);
    assert_eq!(txid2, tx2.compute_txid(), "node accepted tx2");

    // Confirm the chain.
    let _: Vec<String> = node
        .call("generatetoaddress", &[json!(1), json!(mine_to)])
        .expect("confirm batch");

    assert_eq!(
        final_value + fee0 + fee1 + fee2,
        INITIAL_FEE,
        "fee account paid exactly the cumulative fee; customers got full balances"
    );
    eprintln!(
        "bitcoin batched dev-HSM e2e OK: node accepted 3 chained txs \
         ({txid0}, {txid1}, {txid2}); final_value={final_value}, total_fees={}",
        fee0 + fee1 + fee2
    );
}
