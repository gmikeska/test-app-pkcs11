//! Node-free **dev-HSM signing gate** for the Bitcoin `account-for-account-
//! batched` federation migration with **decision (b)** fee-change routing.
//!
//! This is the dev-HSM analogue of `bitcoin_batched_migration_offline.rs`.
//! Where that gate proves the Phase B chained-fee-change *logic* with BDK's
//! in-memory software signer, this proves the same three-transaction batch
//! signs correctly when every old-federation input is signed by a **real
//! PKCS#11 signer** (`Pkcs11Signer` over `libemvault_dev_hsm.so`) — actual
//! cryptoki ECDSA, not software keys.
//!
//! The novel signal: every account reuses the same three dev-HSM tokens
//! (app-5/6/7) and therefore shares *master fingerprints*, differing only by
//! BIP-48 account path. The Bitcoin `Pkcs11Signer` derives **relative** to its
//! own federation path (`signer.rs:457`), so a fee-account signer asked to sign
//! a customer input would derive the wrong child. This gate reproduces the
//! production fix — **index-scope** each account's signing by clearing other
//! accounts' `bip32_derivation` before running its signers — against real
//! tokens.
//!
//! No node, Postgres, or `UserWallet`: funding/chained UTXOs are synthesized and
//! enriched through throwaway BDK wallets (the same `apply_unconfirmed_txs` +
//! `get_psbt_input` machinery `run_bitcoin_migration` uses for the unconfirmed
//! chained change), and transactions are signed + finalized + extracted but
//! never broadcast.
//!
//! Skips cleanly when `PKCS11_LIB` / the shim / the dev tokens are unavailable.
//!
//! Run with (from `test-app-pkcs11/`, with `.env` providing the HSM vars):
//! ```bash
//! cargo test --test bitcoin_migration_hsm_signing -- --nocapture
//! ```

#![allow(clippy::too_many_lines, clippy::similar_names)]

use emvault::core::bdk_wallet;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use emvault::core::bdk_wallet::bitcoin::bip32::DerivationPath as BtcDerivationPath;
use emvault::core::bdk_wallet::bitcoin::hashes::Hash;
use emvault::core::bdk_wallet::bitcoin::{
    self, Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Weight, Witness, absolute::LockTime, transaction::Version,
};
use emvault::core::bdk_wallet::miniscript::psbt::PsbtExt;
use emvault::core::bdk_wallet::signer::SignerOrdering;
use emvault::core::bdk_wallet::{KeychainKind, SignOptions, Wallet};
use emvault::core::descriptor::{KeyMode, to_multipath_string};
use emvault::core::federation::Federation;
use emvault::core::network::NetworkType;

use emvault::dev_signer::DevBackend;
use emvault::pkcs11::{Pkcs11Config, Pkcs11Session, Pkcs11Signer, SlotIdentifier, key_ops};
use test_app_pkcs11::wallet::NetworkPatchedSigner;

const NETWORK: Network = Network::Regtest;
const NETWORK_TYPE: NetworkType = NetworkType::Bitcoin(Network::Regtest);

/// 2-of-3 P2WSH satisfaction weight estimate (matches the executor's chained
/// input weight at `federation_migration.rs:2355`). Offline fee math only.
fn sat_weight() -> Weight {
    Weight::from_witness_data_size(260)
}

// ---------------------------------------------------------------------------
// Dev-HSM environment
// ---------------------------------------------------------------------------

/// Automated-testing token pool (HSMs 5–15) reserved by `test-app-pkcs11/.env`.
const FED_TOKEN_INDICES: [u8; 3] = [5, 6, 7];

struct DevEnv {
    lib: PathBuf,
    tokens: Vec<(String, String)>, // (token_label, pin) per federation member
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
    /// Derive a 2-of-3 federation for `acct` at `m/48'/1'/{acct}'/2'` across the
    /// shared tokens. All accounts share the tokens' master fingerprints.
    fn new(env: &DevEnv, key_tag: &str, acct: u32) -> Self {
        let path = BtcDerivationPath::from_str(&format!("m/48'/1'/{acct}'/2'")).unwrap();
        let signers: Vec<Pkcs11Signer> = env
            .tokens
            .iter()
            .enumerate()
            .map(|(pos, (token_label, pin))| {
                let key_label = format!("hsmbtc-{key_tag}-a{acct}-m{pos}");
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

        // Build the public descriptor via network-patched signers (the xpub's
        // network kind must match regtest for the descriptor builder).
        let patched: Vec<NetworkPatchedSigner> = signers
            .iter()
            .map(|s| NetworkPatchedSigner::new(s.clone(), NETWORK))
            .collect();
        let fed = Federation::with_key_mode(2, patched, NETWORK_TYPE, KeyMode::Ranged)
            .expect("federation construction");
        let desc_str = to_multipath_string(fed.try_descriptor().expect("descriptor"));
        let descriptor = desc_str.parse().expect("valid multipath descriptor");

        Self {
            descriptor,
            signers,
        }
    }

    /// A throwaway public wallet (derive / enrich). Stateless and cheap.
    fn wallet(&self) -> Wallet {
        Wallet::create_from_two_path_descriptor(self.descriptor.clone())
            .network(NETWORK)
            .create_wallet_no_persist()
            .expect("wallet from public descriptor")
    }

    /// A wallet with all three HSM signers registered, ready to sign.
    fn signing_wallet(&self) -> Wallet {
        let mut w = self.wallet();
        for s in &self.signers {
            let arc: Arc<Pkcs11Signer> = Arc::new(s.clone());
            w.add_signer(
                KeychainKind::External,
                SignerOrdering::default(),
                arc.clone(),
            );
            w.add_signer(KeychainKind::Internal, SignerOrdering::default(), arc);
        }
        w
    }

    fn address(&self, index: u32) -> Address {
        self.wallet()
            .peek_address(KeychainKind::External, index)
            .address
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

/// Synthesize a confirmed-looking funding UTXO paying `value` to `fed`'s
/// address at `index`, enriched into a foreign-spendable PSBT input.
fn fund(fed: &HsmFed, index: u32, value: u64, seed: u8) -> Funded {
    let spk = fed.address(index).script_pubkey();
    let funding = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([seed; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: spk,
        }],
    };
    let op = OutPoint::new(funding.compute_txid(), 0);
    enrich(fed, &funding, op)
}

/// Rebuild the PSBT input for `op` (an output of `tx`) from `fed`'s public
/// descriptor via a throwaway wallet — the literal Phase B chained mechanic
/// (`federation_migration.rs:2342-2360`).
fn enrich(fed: &HsmFed, tx: &Transaction, op: OutPoint) -> Funded {
    let mut tw = fed.wallet();
    let _ = tw.reveal_next_address(KeychainKind::External);
    tw.apply_unconfirmed_txs(vec![(tx.clone(), 0)]);
    let local = tw
        .get_utxo(op)
        .expect("utxo present in temp wallet after insert");
    let input = tw
        .get_psbt_input(local, None, false)
        .expect("build psbt input");
    Funded {
        op,
        input,
        weight: sat_weight(),
    }
}

/// Build, sign (index-scoped per owning federation), finalize, and extract one
/// batch transaction.
fn run_tx(
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

#[test]
fn bitcoin_batched_migration_chains_fee_change_old_fed_hsm() {
    const INITIAL_FEE: u64 = 1_000_000;
    const C1_BAL: u64 = 200_000;
    const C2_BAL: u64 = 300_000;

    let Some(env) = dev_env() else {
        eprintln!(
            "skipping bitcoin_batched_migration_chains_fee_change_old_fed_hsm: dev HSM unavailable"
        );
        return;
    };
    let key_tag = format!("{:x}", std::process::id());

    // Fee account: OLD fed (holds funds, signs every hop) + NEW fed (final
    // destination only). Customers each: OLD fed (funds) + NEW fed (destination).
    let fee_old = HsmFed::new(&env, &key_tag, 900_001);
    let fee_new = HsmFed::new(&env, &key_tag, 900_002);
    let c1_old = HsmFed::new(&env, &key_tag, 900_003);
    let c1_new = HsmFed::new(&env, &key_tag, 900_004);
    let c2_old = HsmFed::new(&env, &key_tag, 900_005);
    let c2_new = HsmFed::new(&env, &key_tag, 900_006);

    let fee_old_addr = fee_old.address(0);
    let fee_new_addr = fee_new.address(0);
    let c1_dest = c1_new.address(5);
    let c2_dest = c2_new.address(5);

    let fee_utxo = fund(&fee_old, 0, INITIAL_FEE, 0x11);
    let c1_utxo = fund(&c1_old, 0, C1_BAL, 0x22);
    let c2_utxo = fund(&c2_old, 0, C2_BAL, 0x33);

    // --- tx0: C1 + real fee utxo → C1 exact, change back to fee OLD. --------
    let (c1_op, fee_op) = (c1_utxo.op, fee_utxo.op);
    let tx0 = run_tx(
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
    // Rebuild the chained change from the fee account's OLD descriptor.
    let chained0 = enrich(&fee_old, &tx0, outpoint_at(&tx0, &fee_old_addr));

    // --- tx1: C2 + chained change → C2 exact, change back to fee OLD. -------
    let (c2_op, chained0_op) = (c2_utxo.op, chained0.op);
    let tx1 = run_tx(
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
    let chained1 = enrich(&fee_old, &tx1, outpoint_at(&tx1, &fee_old_addr));

    // --- tx2: fee-only final tx → drain to fee NEW. The chained input is
    // still OLD-fed-locked, so the OLD federation signs it; only the OUTPUT
    // crosses to the new federation. ----------------------------------------
    let chained1_op = chained1.op;
    let tx2 = run_tx(
        &fee_old,
        &[chained1],
        &[],
        &fee_new_addr,
        &[(&fee_old, vec![chained1_op])],
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

    assert_eq!(
        final_value + fee0 + fee1 + fee2,
        INITIAL_FEE,
        "fee account paid exactly the cumulative fee; customers got full balances"
    );
    eprintln!(
        "bitcoin batched dev-HSM signing OK: 3 chained txs, real cryptoki witnesses, \
         final_value={final_value}, total_fees={}",
        fee0 + fee1 + fee2
    );
}
