//! Node-free **dev-HSM signing gate** for the Elements federation migration.
//!
//! This is the dev-HSM analog of `emvault-elements`'s offline software gates
//! (`migration_fee_account_pays_and_multi_account_signs` and
//! `batched_migration_chains_fee_change_offline`). Where those prove the
//! migration *logic* with in-memory `SoftwareSigner`s, this proves the same
//! flows sign correctly when every old-federation input is signed by a **real
//! PKCS#11 signer** (`Pkcs11Signer` over the `libemvault_dev_hsm.so` shim) —
//! i.e. actual cryptoki ECDSA, not software keys.
//!
//! The novel signal over the software gates: all accounts share the same three
//! dev-HSM tokens (app-5/6/7) and therefore share *master fingerprints*,
//! differing only by BIP-48 account path. That is exactly the production
//! condition that forces the migration executor to **index-scope** signing
//! (clear other accounts' `bip32_derivation` before running an account's
//! signers). This test reproduces that scoping against real tokens.
//!
//! No Elements node and no Postgres: inputs are synthetic [`CapturedUtxo`]s
//! built directly against each account's derived address (same trick the
//! `emvault-elements` offline gates use), and transactions are signed +
//! finalized + extracted but never broadcast.
//!
//! Skips cleanly when `PKCS11_LIB` / the shim / the dev tokens are unavailable.
//!
//! Run with (from `test-app-pkcs11/`, with `.env` providing the HSM vars):
//! ```bash
//! cargo test --test elements_migration_hsm_signing -- --nocapture
//! ```

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::similar_names
)]

use emvault::elements::elements;
use std::path::PathBuf;
use std::str::FromStr;

use emvault::core::bitcoin::Network;
use emvault::core::bitcoin::bip32::DerivationPath;
use emvault::core::signer::Signer;
use emvault::dev_signer::DevBackend;
use emvault::elements::descriptor::{CtDescriptorBuilder, CtKeyMode};
use emvault::elements::elements::confidential::{
    Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor,
};
use emvault::elements::elements::{AssetId, OutPoint, Script, TxOut, TxOutSecrets, TxOutWitness};
use emvault::elements::signer::ElementsSigner;
use emvault::elements::sync::{CapturedUtxo, KeychainKind, WalletId};
use emvault::elements::{
    ElementsNetwork, ElementsWalletHandle, ElementsWollet, build_migration_pset,
    captured_from_output, finalize_p2wsh_pset,
};
use emvault::pkcs11::{Pkcs11Config, Pkcs11Session, Pkcs11Signer, SlotIdentifier, key_ops};

const LBTC_SAT: u64 = 100_000_000;

/// The dev-HSM shim is **process-global** (one `C_Initialize`/`C_Finalize` for
/// the whole process), so HSM-backed tests in this binary must not run
/// concurrently — a finishing test's context drop calls `C_Finalize` and breaks
/// an in-flight one (`CryptokiNotInitialized`). Serialize them with this lock.
fn hsm_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

// ---------------------------------------------------------------------------
// Dev-HSM environment
// ---------------------------------------------------------------------------

/// The three dev tokens that form the migration federation. These are the
/// automated-testing pool (HSMs 5–15) reserved by `test-app-pkcs11/.env`;
/// resettable via `reset-test-hsms.sh` without touching the manual 1–4.
const FED_TOKEN_INDICES: [u8; 3] = [5, 6, 7];

struct DevEnv {
    lib: PathBuf,
    /// `(token_label, pin)` for each federation member.
    tokens: Vec<(String, String)>,
}

/// Load `.env` and resolve the dev-HSM federation tokens. Returns `None`
/// (test skips) when the shim or any token's env vars are missing.
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

/// Defensively delete any prior key stored under `label` so a re-run derives
/// cleanly. Labels are already per-run unique (pid + account + member), so this
/// is belt-and-suspenders; periodic full cleanup is `reset-test-hsms.sh`.
fn reset_label(session: &Pkcs11Session, label: &str) {
    let _ = key_ops::delete_key(session, label);
}

/// A migration account: its old-federation wollet + the three dev-HSM signers
/// that control it (one per token, all at the same per-account BIP-48 path).
struct HsmAccount {
    wollet: ElementsWollet,
    signers: Vec<Pkcs11Signer>,
}

/// Derive a real dev-HSM 2-of-3 federation for `acct` at `m/48'/1'/{acct}'/2'`
/// and build its confidential wollet (node-free, via `from_handle`).
///
/// All accounts reuse the same three tokens, so their signers share master
/// fingerprints and differ only by account path — the production condition
/// that makes index-scoped signing necessary.
fn hsm_account(env: &DevEnv, key_tag: &str, acct: i32, blinding_byte: u8) -> HsmAccount {
    let path = DerivationPath::from_str(&format!("m/48'/1'/{acct}'/2'")).unwrap();

    let signers: Vec<Pkcs11Signer> = env
        .tokens
        .iter()
        .enumerate()
        .map(|(pos, (token_label, pin))| {
            let key_label = format!("hsmsig-{key_tag}-a{acct}-m{pos}");
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
                Network::Testnet,
                Box::new(DevBackend),
                // Empty seed: the shim supplies the token's configured seed.
                &[],
            )
            .expect("derive dev HSM key")
        })
        .collect();

    let blinding = [blinding_byte; 32];
    let mut builder = CtDescriptorBuilder::new(2, &blinding)
        .unwrap()
        .key_mode(CtKeyMode::Ranged);
    for s in &signers {
        builder.add_signer(s as &dyn Signer).unwrap();
    }
    let ct = builder.build().unwrap();
    let handle = ElementsWalletHandle::new(ct, blinding);
    let wollet = ElementsWollet::from_handle(&handle, ElementsNetwork::ElementsRegtest).unwrap();

    HsmAccount { wollet, signers }
}

// ---------------------------------------------------------------------------
// Synthetic (node-free) UTXOs — same approach as the emvault-elements gates
// ---------------------------------------------------------------------------

fn lbtc() -> AssetId {
    *ElementsNetwork::ElementsRegtest.to_lwk().policy_asset()
}

fn explicit_txout(spk: Script, value: u64) -> TxOut {
    TxOut {
        asset: Asset::Explicit(lbtc()),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey: spk,
        witness: TxOutWitness::default(),
    }
}

/// A synthetic `CapturedUtxo` that pays this wollet's external address at
/// `index`, with an explicit (unblinded) value — so `build_migration_pset`'s
/// enrichment produces a consistent `witness_script` + `bip32_derivation`.
fn funding_utxo(wollet: &ElementsWollet, index: u32, value: u64, txid_seed: u8) -> CapturedUtxo {
    let addr = wollet.address(KeychainKind::External, index).unwrap();
    let mut outpoint = OutPoint::null();
    outpoint.vout = u32::from(txid_seed);
    CapturedUtxo {
        wallet_id: WalletId::from_bytes([1; 16]),
        outpoint,
        txout: explicit_txout(addr.script_pubkey(), value),
        secrets: TxOutSecrets::new(
            lbtc(),
            AssetBlindingFactor::zero(),
            value,
            ValueBlindingFactor::zero(),
        ),
        chain: KeychainKind::External,
        wildcard_index: index,
        height: 1,
        is_spent: false,
    }
}

/// Index-scoped per-account signing: clear `bip32_derivation` on the inputs
/// this account does not own, run the account's HSM signers, then restore.
/// Necessary because every account shares the same three tokens' fingerprints.
fn sign_account(
    pset: &mut elements::pset::PartiallySignedTransaction,
    owned: &[CapturedUtxo],
    signers: &[Pkcs11Signer],
) {
    let owned_set: std::collections::HashSet<OutPoint> = owned.iter().map(|u| u.outpoint).collect();
    let indices: Vec<usize> = pset
        .inputs()
        .iter()
        .enumerate()
        .filter(|(_, i)| {
            owned_set.contains(&OutPoint::new(i.previous_txid, i.previous_output_index))
        })
        .map(|(i, _)| i)
        .collect();
    let mut saved = Vec::new();
    for (i, inp) in pset.inputs_mut().iter_mut().enumerate() {
        if !indices.contains(&i) {
            saved.push((i, std::mem::take(&mut inp.bip32_derivation)));
        }
    }
    for s in signers {
        let _ = s.sign_pset(pset);
    }
    for (i, d) in saved {
        pset.inputs_mut()[i].bip32_derivation = d;
    }
}

fn val_at(tx: &elements::Transaction, w: &ElementsWollet, addr: &elements::Address) -> u64 {
    let spk = addr.script_pubkey();
    let o = tx
        .output
        .iter()
        .find(|o| o.script_pubkey == spk)
        .expect("destination output present");
    w.unblind(o).unwrap().value
}

fn fee_of(tx: &elements::Transaction) -> u64 {
    tx.output
        .iter()
        .find(|o| o.script_pubkey.is_empty())
        .and_then(|o| o.value.explicit())
        .expect("explicit fee output")
}

/// Assert every input finalized with a real (>=4-item) P2WSH multisig witness —
/// proof that the dev HSM genuinely signed, not a trivial pass.
fn assert_finalized_witnesses(tx: &elements::Transaction, n_inputs: usize) {
    assert_eq!(tx.input.len(), n_inputs, "input count");
    for inp in &tx.input {
        assert!(
            inp.witness.script_witness.len() >= 4,
            "each input finalized with a 2-of-3 P2WSH witness (got {} items)",
            inp.witness.script_witness.len()
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Account-for-account (single tx): fee account + two customers, all old-fed
/// inputs signed by real dev HSMs. Customers get exact balances, the fee
/// account drains the remainder (paying the mining fee), and each account's
/// 2-of-3 signs only its own inputs via index-scoping.
#[test]
fn elements_a2a_hsm_signing_offline() {
    let Some(env) = dev_env() else {
        eprintln!("skipping elements_a2a_hsm_signing_offline: dev HSM unavailable");
        return;
    };
    let _serial = hsm_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let key_tag = format!("{:x}", std::process::id());

    let fee = hsm_account(&env, &key_tag, 700_001, 0xa0);
    let c1 = hsm_account(&env, &key_tag, 700_002, 0xa1);
    let c2 = hsm_account(&env, &key_tag, 700_003, 0xa2);

    // Fee account holds 100k (pays the fee); customers hold 1.0 L-BTC each.
    let fee_utxo = funding_utxo(&fee.wollet, 0, 100_000, 1);
    let c1_utxo = funding_utxo(&c1.wollet, 0, LBTC_SAT, 2);
    let c2_utxo = funding_utxo(&c2.wollet, 0, LBTC_SAT, 3);

    // New-fed destinations (own index-5 addr so we can unblind to verify).
    let c1_dest = c1.wollet.address(KeychainKind::External, 5).unwrap();
    let c2_dest = c2.wollet.address(KeychainKind::External, 5).unwrap();
    let fee_dest = fee.wollet.address(KeychainKind::External, 5).unwrap();

    let inputs = vec![
        (fee_utxo.clone(), &fee.wollet),
        (c1_utxo.clone(), &c1.wollet),
        (c2_utxo.clone(), &c2.wollet),
    ];
    let blinded = build_migration_pset(
        &fee.wollet,
        &inputs,
        &[(c1_dest.clone(), LBTC_SAT), (c2_dest.clone(), LBTC_SAT)],
        &fee_dest,
        2000.0,
    )
    .unwrap();
    let mut pset = blinded.into_pset();

    sign_account(&mut pset, std::slice::from_ref(&fee_utxo), &fee.signers);
    sign_account(&mut pset, std::slice::from_ref(&c1_utxo), &c1.signers);
    sign_account(&mut pset, std::slice::from_ref(&c2_utxo), &c2.signers);

    finalize_p2wsh_pset(&mut pset).unwrap();
    let tx = pset.extract_tx().unwrap();

    assert_finalized_witnesses(&tx, 3);
    assert_eq!(
        val_at(&tx, &c1.wollet, &c1_dest),
        LBTC_SAT,
        "customer 1 exact"
    );
    assert_eq!(
        val_at(&tx, &c2.wollet, &c2_dest),
        LBTC_SAT,
        "customer 2 exact"
    );
    let fee_change = val_at(&tx, &fee.wollet, &fee_dest);
    let fee_paid = fee_of(&tx);
    assert!(fee_paid > 0, "fee account paid a non-zero fee");
    assert_eq!(
        fee_change + fee_paid,
        100_000,
        "fee account: drain change + fee == its old balance (it paid for everyone)"
    );
    eprintln!("a2a dev-HSM signing OK: 3 inputs, real cryptoki witnesses, fee_paid={fee_paid}");
}

/// Batched migration with **chained confidential fee-change** (decision (b)):
/// large customer (tx0) → small bundle (tx1) → fee-only final (tx2). The fee
/// account's intermediate change is routed back to its OWN old-fed address each
/// hop (captured via `captured_from_output`, fed into the next tx) and crosses
/// to the new-fed address only in the final tx. Every old-fed input is signed
/// by a real dev HSM.
#[test]
fn elements_batched_hsm_signing_offline() {
    const LARGE: u64 = LBTC_SAT;
    const SMALL1: u64 = 200_000;
    const SMALL2: u64 = 100_000;
    const INITIAL_FEE: u64 = 1_000_000;

    let Some(env) = dev_env() else {
        eprintln!("skipping elements_batched_hsm_signing_offline: dev HSM unavailable");
        return;
    };
    let _serial = hsm_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let key_tag = format!("{:x}b", std::process::id());

    let fee = hsm_account(&env, &key_tag, 800_001, 0xc0);
    let cl = hsm_account(&env, &key_tag, 800_002, 0xc1);
    let cs1 = hsm_account(&env, &key_tag, 800_003, 0xc2);
    let cs2 = hsm_account(&env, &key_tag, 800_004, 0xc3);

    let fee_utxo = funding_utxo(&fee.wollet, 0, INITIAL_FEE, 1);
    let cl_utxo = funding_utxo(&cl.wollet, 0, LARGE, 2);
    let cs1_utxo = funding_utxo(&cs1.wollet, 0, SMALL1, 3);
    let cs2_utxo = funding_utxo(&cs2.wollet, 0, SMALL2, 4);

    let cl_dest = cl.wollet.address(KeychainKind::External, 5).unwrap();
    let cs1_dest = cs1.wollet.address(KeychainKind::External, 5).unwrap();
    let cs2_dest = cs2.wollet.address(KeychainKind::External, 5).unwrap();
    // Fee account: OLD-fed change sink (index 0) for the hops; NEW-fed (index 6)
    // only for the final tx.
    let fee_old = fee.wollet.address(KeychainKind::External, 0).unwrap();
    let fee_new = fee.wollet.address(KeychainKind::External, 6).unwrap();

    // Capture the fee account's change output (at fee_old) as a chained UTXO.
    let chain_change = |tx: &elements::Transaction| -> CapturedUtxo {
        let spk = fee_old.script_pubkey();
        let (vout, txout) = tx
            .output
            .iter()
            .enumerate()
            .find(|(_, o)| o.script_pubkey == spk)
            .map(|(i, o)| (u32::try_from(i).unwrap(), o.clone()))
            .expect("fee change output present");
        captured_from_output(
            &fee.wollet,
            tx.txid(),
            vout,
            &txout,
            WalletId::from_bytes([1; 16]),
            0,
        )
        .unwrap()
    };

    // --- tx0: large customer + fee seed → change back to fee OLD. ---
    let inputs = vec![
        (cl_utxo.clone(), &cl.wollet),
        (fee_utxo.clone(), &fee.wollet),
    ];
    let blinded = build_migration_pset(
        &fee.wollet,
        &inputs,
        &[(cl_dest.clone(), LARGE)],
        &fee_old,
        2000.0,
    )
    .unwrap();
    let mut pset = blinded.into_pset();
    sign_account(&mut pset, std::slice::from_ref(&cl_utxo), &cl.signers);
    sign_account(&mut pset, std::slice::from_ref(&fee_utxo), &fee.signers);
    finalize_p2wsh_pset(&mut pset).unwrap();
    let tx0 = pset.extract_tx().unwrap();
    assert_finalized_witnesses(&tx0, 2);
    let large_at_new = val_at(&tx0, &cl.wollet, &cl_dest);
    // Intermediate fee change must live at the OLD-fed address, not the new one.
    assert!(
        tx0.output
            .iter()
            .any(|o| o.script_pubkey == fee_old.script_pubkey()),
        "tx0 fee change at OLD-fed address"
    );
    assert!(
        !tx0.output
            .iter()
            .any(|o| o.script_pubkey == fee_new.script_pubkey()),
        "tx0 must NOT touch the new-fed address"
    );
    let chained0 = chain_change(&tx0);

    // --- tx1: small bundle + chained change → change back to fee OLD. ---
    let inputs = vec![
        (cs1_utxo.clone(), &cs1.wollet),
        (cs2_utxo.clone(), &cs2.wollet),
        (chained0.clone(), &fee.wollet),
    ];
    let blinded = build_migration_pset(
        &fee.wollet,
        &inputs,
        &[(cs1_dest.clone(), SMALL1), (cs2_dest.clone(), SMALL2)],
        &fee_old,
        2000.0,
    )
    .unwrap();
    let mut pset = blinded.into_pset();
    sign_account(&mut pset, std::slice::from_ref(&cs1_utxo), &cs1.signers);
    sign_account(&mut pset, std::slice::from_ref(&cs2_utxo), &cs2.signers);
    sign_account(&mut pset, std::slice::from_ref(&chained0), &fee.signers);
    finalize_p2wsh_pset(&mut pset).unwrap();
    let tx1 = pset.extract_tx().unwrap();
    assert_finalized_witnesses(&tx1, 3);
    let small1_at_new = val_at(&tx1, &cs1.wollet, &cs1_dest);
    let small2_at_new = val_at(&tx1, &cs2.wollet, &cs2_dest);
    assert!(
        !tx1.output
            .iter()
            .any(|o| o.script_pubkey == fee_new.script_pubkey()),
        "tx1 must NOT touch the new-fed address"
    );
    let chained1 = chain_change(&tx1);

    // --- tx2: fee account migrates last → drain to fee NEW dest. ---
    let inputs = vec![(chained1.clone(), &fee.wollet)];
    let blinded = build_migration_pset(&fee.wollet, &inputs, &[], &fee_new, 2000.0).unwrap();
    let mut pset = blinded.into_pset();
    sign_account(&mut pset, std::slice::from_ref(&chained1), &fee.signers);
    finalize_p2wsh_pset(&mut pset).unwrap();
    let tx2 = pset.extract_tx().unwrap();
    assert_finalized_witnesses(&tx2, 1);
    let fee_at_new = val_at(&tx2, &fee.wollet, &fee_new);

    // Customers exact.
    assert_eq!(large_at_new, LARGE, "large customer exact");
    assert_eq!(small1_at_new, SMALL1, "small customer 1 exact");
    assert_eq!(small2_at_new, SMALL2, "small customer 2 exact");

    // Value conserved across the chain: only mining fees leak from the fee acct.
    let total_fees = fee_of(&tx0) + fee_of(&tx1) + fee_of(&tx2);
    assert!(total_fees > 0, "non-zero cumulative fee");
    assert_eq!(
        fee_at_new + total_fees,
        INITIAL_FEE,
        "fee account: final new-fed balance + cumulative fee == its initial balance"
    );
    eprintln!(
        "batched dev-HSM signing OK: 3 chained txs, real cryptoki witnesses, \
         fee_at_new={fee_at_new}, total_fees={total_fees}"
    );
}
