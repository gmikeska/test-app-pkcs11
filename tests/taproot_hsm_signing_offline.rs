//! Node-free **dev-HSM Taproot signing gate** driving the real
//! [`SigningCoordinator`] over a `tr(NUMS, multi_a(2, …))` 2-of-3 federation.
//!
//! This is the runtime companion to the `emvault-core` F1 unit tests: where
//! those forge BIP-340 signatures by hand, this drives *actual* PKCS#11 Schnorr
//! signatures (three dev-HSM `Pkcs11Signer`s over `libemvault_dev_hsm.so`)
//! through the coordinator's Taproot bookkeeping — the exact code paths the F1
//! fix touched (`signers_with_sigs` counting + `is_complete`).
//!
//! It proves, at runtime through the app stack, the two F1 guarantees for
//! Taproot:
//!   1. **No over-count** — after *one* real HSM Taproot signature the
//!      coordinator reports exactly one signer and is NOT complete (the old bug
//!      flipped `is_complete` to true after a single sig in a 2-of-3).
//!   2. **Correct completion** — a second distinct signature reaches threshold,
//!      and the PSBT finalizes to a real Taproot script-path witness.
//!
//! No node, Postgres, or `UserWallet`: a synthetic UTXO is funded to the
//! federation address and the spend is signed + finalized + extracted, never
//! broadcast. Skips cleanly when `PKCS11_LIB` / the shim / the dev tokens are
//! unavailable.
//!
//! Run (from `test-app-pkcs11/`, with `.env` providing the HSM vars):
//! ```bash
//! cargo test --test taproot_hsm_signing_offline -- --nocapture
//! ```

#![allow(clippy::too_many_lines)]

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use emvault::core::ScriptType;
use emvault::core::bdk_wallet::bitcoin::bip32::DerivationPath as BtcDerivationPath;
use emvault::core::bdk_wallet::bitcoin::hashes::Hash;
use emvault::core::bdk_wallet::bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute::LockTime, transaction::Version,
};
use emvault::core::bdk_wallet::signer::SignerOrdering;
use emvault::core::bdk_wallet::{KeychainKind, SignOptions, Wallet};
use emvault::core::descriptor::KeyMode;
use emvault::core::federation::Federation;
use emvault::core::network::NetworkType;
use emvault::core::psbt::{SigningCoordinator, UnsignedPsbt};

use emvault::pkcs11::{Pkcs11Config, Pkcs11Session, Pkcs11Signer, SlotIdentifier, key_ops};
use emvault_dev_signer::DevBackend;
use test_app_pkcs11::wallet::NetworkPatchedSigner;

const NETWORK: Network = Network::Regtest;
const NETWORK_TYPE: NetworkType = NetworkType::Bitcoin(Network::Regtest);
const FUND_SATS: u64 = 100_000;
const FEE_SATS: u64 = 1_000;

/// Automated-testing token pool (HSMs 5–15) reserved by `test-app-pkcs11/.env`.
const FED_TOKEN_INDICES: [u8; 3] = [5, 6, 7];

struct DevEnv {
    lib: PathBuf,
    tokens: Vec<(String, String)>, // (token_label, pin)
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

/// Derive the three dev-HSM Taproot signers at a shared BIP-86 account path.
fn taproot_signers(env: &DevEnv, key_tag: &str) -> Vec<Pkcs11Signer> {
    let path = BtcDerivationPath::from_str("m/86'/1'/0'").unwrap();
    env.tokens
        .iter()
        .enumerate()
        .map(|(pos, (token_label, pin))| {
            let key_label = format!("hsmtap-{key_tag}-m{pos}");
            let cfg = Pkcs11Config::new(
                &env.lib,
                SlotIdentifier::label(token_label),
                pin.clone(),
                path.clone(),
            );
            let session = Pkcs11Session::open(&cfg, &SlotIdentifier::label(token_label), pin)
                .expect("open dev HSM session");
            let _ = key_ops::delete_key(&session, &key_label);
            Pkcs11Signer::derive_from_seed(
                session,
                &key_label,
                &path,
                NETWORK,
                Box::new(DevBackend),
                &[],
            )
            .expect("derive dev HSM taproot key")
        })
        .collect()
}

#[test]
fn taproot_coordinator_counts_hsm_sigs_and_completes_at_threshold() {
    let Some(env) = dev_env() else {
        eprintln!(
            "skipping taproot_coordinator_counts_hsm_sigs_and_completes_at_threshold: dev HSM unavailable"
        );
        return;
    };
    let key_tag = format!("{:x}", std::process::id());
    let signers = taproot_signers(&env, &key_tag);

    // 2-of-3 tr(NUMS, multi_a(2, …)) federation. Taproot requires Fixed mode.
    // NetworkPatchedSigner makes the dev xpub's network kind match regtest.
    let patched: Vec<NetworkPatchedSigner> = signers
        .iter()
        .map(|s| NetworkPatchedSigner::new(s.clone(), NETWORK))
        .collect();
    let federation =
        Federation::with_config(2, patched, NETWORK_TYPE, KeyMode::Fixed, ScriptType::Tr)
            .expect("taproot federation construction");
    let descriptor = federation.descriptor().to_string();
    assert!(
        descriptor.starts_with("tr("),
        "want taproot descriptor: {descriptor}"
    );
    assert!(
        descriptor.contains("multi_a(2,"),
        "want multi_a(2,...): {descriptor}"
    );

    // Public wallet from the single-path taproot descriptor.
    let mut wallet = Wallet::create_single(descriptor)
        .network(NETWORK)
        .create_wallet_no_persist()
        .expect("wallet from taproot descriptor");
    let address = wallet.reveal_next_address(KeychainKind::External).address;
    assert!(
        address.script_pubkey().is_p2tr(),
        "federation address is P2TR"
    );

    // Fund it with a synthetic confirmed-looking UTXO.
    let funding = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([7u8; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(FUND_SATS),
            script_pubkey: address.script_pubkey(),
        }],
    };
    let funded_op = OutPoint::new(funding.compute_txid(), 0);
    wallet.apply_unconfirmed_txs(vec![(funding, 0)]);
    assert!(
        wallet.get_utxo(funded_op).is_some(),
        "wallet registered the synthetic funding UTXO"
    );

    // Build an unsigned spend draining back to the same address minus fee.
    let unsigned = {
        let mut b = wallet.build_tx();
        b.drain_wallet()
            .drain_to(address.script_pubkey())
            .fee_absolute(Amount::from_sat(FEE_SATS));
        b.finish().expect("build unsigned taproot spend")
    };
    let coordinator_psbt = UnsignedPsbt::new(unsigned).expect("zero-sig unsigned psbt");
    let mut coord = SigningCoordinator::new(&federation, coordinator_psbt);

    let sign_opts = SignOptions {
        trust_witness_utxo: true,
        try_finalize: false,
        ..Default::default()
    };

    // --- One HSM signature: exactly one signer counted, NOT complete. --------
    let mut w1 = wallet_with_signers(&federation, &signers[..1]);
    coord
        .request_signatures(&w1, sign_opts.clone())
        .expect("first HSM taproot signature");
    assert_eq!(
        coord.signatures_collected(),
        1,
        "one real HSM Taproot sig must credit exactly one signer (F1 no-over-count)"
    );
    assert!(
        !coord.is_complete(),
        "a single signature must NOT complete a 2-of-3 (the F1 bug)"
    );
    assert_eq!(
        coord.psbt().inputs[0].tap_script_sigs.len(),
        1,
        "exactly one tap_script_sig present after one signer"
    );

    // --- Second HSM signature: threshold reached. ---------------------------
    add_signer(&mut w1, &signers[1]);
    coord
        .request_signatures(&w1, sign_opts)
        .expect("second HSM taproot signature");
    assert_eq!(
        coord.signatures_collected(),
        2,
        "two distinct HSM Taproot sigs → two signers"
    );
    assert!(coord.is_complete(), "2-of-3 threshold met");

    // --- Finalize to a real Taproot script-path witness. --------------------
    let finalized = coord
        .finalize(&w1, SignOptions::default())
        .expect("finalize the 2-of-3 taproot spend");
    let tx = finalized.transaction();
    assert!(
        !tx.input[0].witness.is_empty(),
        "finalized taproot tx carries a non-empty script-path witness"
    );
    eprintln!(
        "taproot dev-HSM coordinator OK: 2-of-3 tr(NUMS,multi_a) signed through SigningCoordinator, \
         real Schnorr witnesses, finalized txid {}",
        tx.compute_txid()
    );
}

/// A wallet from the federation's taproot descriptor with the given HSM signers
/// registered on both keychains.
fn wallet_with_signers(
    federation: &Federation<NetworkPatchedSigner>,
    signers: &[Pkcs11Signer],
) -> Wallet {
    let mut w = Wallet::create_single(federation.descriptor().to_string())
        .network(NETWORK)
        .create_wallet_no_persist()
        .expect("signing wallet");
    for s in signers {
        add_signer(&mut w, s);
    }
    w
}

fn add_signer(wallet: &mut Wallet, signer: &Pkcs11Signer) {
    let arc: Arc<Pkcs11Signer> = Arc::new(signer.clone());
    wallet.add_signer(
        KeychainKind::External,
        SignerOrdering::default(),
        arc.clone(),
    );
    wallet.add_signer(KeychainKind::Internal, SignerOrdering::default(), arc);
}
