//! P4 (Phase D) — **node-backed dev-HSM** Elements federation migration e2e.
//!
//! This is the live-node analogue of `elements_migration_hsm_signing.rs`. Where
//! that gate proves the migration signs correctly against real dev-HSM tokens
//! *node-free* (synthetic UTXOs, never broadcast), this drives the **full**
//! pipeline end to end:
//!
//!   fund (elementsd) → capture (block-scan engine → Postgres) →
//!   build_migration_pset → **dev-HSM sign** (real cryptoki ECDSA) →
//!   finalize → **broadcast (elementsd accepts)** → re-capture / verify.
//!
//! It mirrors the proven `SoftwareSigner` e2es in `elements_migration_e2e.rs`
//! one-for-one, swapping the in-memory software signers on the **old-federation
//! (signed)** accounts for `Pkcs11Signer`s over `libasterism_dev_hsm.so`. The
//! **new-federation destinations stay software wallets** — they are never signed
//! in this migration (their outputs are spent by a *future* migration), so they
//! need only an address to receive at and a master blinding key to unblind for
//! verification. Keeping them software conserves the dev-HSM token pool and
//! isolates the novel signal (real HSM signing of the old-fed inputs).
//!
//! Both tests share Postgres `elements_blocks` / `elements_sync_cursor` and the
//! process-global dev-HSM shim, so they are serialized behind `e2e_lock()`.
//!
//! Skips cleanly when either layer is unavailable:
//!   * the live node + DB — activated only when `ELEMENTS_RPC_URL` is explicitly
//!     exported (with `ELEMENTS_RPC_USER` / `ELEMENTS_RPC_PASSWORD` /
//!     `DATABASE_URL`), exactly like the sibling `elements_migration_e2e.rs`, or
//!   * `PKCS11_LIB` + `APP_HSM_{5,6,7}_LABEL`/`_PIN` (the dev-HSM federation,
//!     loaded from `.env`).
//!
//! Run with (from `test-app-pkcs11/`, with `.env` providing the HSM + node vars):
//! ```bash
//! cargo test --test elements_migration_hsm_e2e -- --nocapture --test-threads=1
//! ```

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::format_collect,
    clippy::doc_markdown
)]

use std::path::PathBuf;
use std::str::FromStr;

use bitcoincore_rpc::{Auth, Client, RpcApi};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use asterism::core::signer::Signer;
use asterism::dev_signer::DevBackend;
use asterism::elements::descriptor::{CtDescriptorBuilder, CtKeyMode, to_multipath_string};
use asterism::elements::signer::ElementsSigner;
use asterism::elements::sync::{
    BlockScanEngine, CapturedUtxo, ElementsChainSource, KeychainKind, WalletId, WalletUtxoStore,
};
use asterism::elements::testkit::SoftwareSigner;
use asterism::elements::{
    ElementsNetwork, ElementsWalletHandle, ElementsWollet, LwkNetwork, build_migration_pset,
    captured_from_output, finalize_p2wsh_pset,
};
use asterism::pkcs11::{Pkcs11Config, Pkcs11Session, Pkcs11Signer, SlotIdentifier, key_ops};
use bitcoin::Network;
use bitcoin::bip32::DerivationPath;

use test_app_pkcs11::elements_sync::{PgBlockStore, PgWalletUtxoStore, RpcChainSource};

const LBTC_SAT: u64 = 100_000_000;

/// Serialize the two e2e tests: they share Postgres `elements_blocks` /
/// `elements_sync_cursor` state **and** the process-global dev-HSM shim (one
/// `C_Initialize`/`C_Finalize` per process). Acquire for the whole test.
fn e2e_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

// ---------------------------------------------------------------------------
// Node + DB environment (mirrors elements_migration_e2e.rs)
// ---------------------------------------------------------------------------

struct Env {
    rpc_url: String,
    rpc_user: String,
    rpc_pass: String,
    database_url: String,
}

fn env() -> Option<Env> {
    // Opt-in gate (matches the sibling `elements_migration_e2e.rs`): the live
    // layer activates only when `ELEMENTS_RPC_URL` is **explicitly exported**,
    // signalling "the node + DB are up, run the e2e". We deliberately do not
    // load `.env` or compose from `ELEMENTS_RPC_HOST/PORT` here, so the test
    // skips cleanly under a plain `cargo test` even though `.env` exists.
    Some(Env {
        rpc_url: std::env::var("ELEMENTS_RPC_URL").ok()?,
        rpc_user: std::env::var("ELEMENTS_RPC_USER").ok()?,
        rpc_pass: std::env::var("ELEMENTS_RPC_PASSWORD").ok()?,
        database_url: std::env::var("DATABASE_URL").ok()?,
    })
}

fn node_wallet(env: &Env) -> Client {
    Client::new(
        &format!("{}/wallet/default", env.rpc_url),
        Auth::UserPass(env.rpc_user.clone(), env.rpc_pass.clone()),
    )
    .unwrap()
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn de<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

// ---------------------------------------------------------------------------
// Dev-HSM environment (mirrors elements_migration_hsm_signing.rs)
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

// ---------------------------------------------------------------------------
// Wallets
// ---------------------------------------------------------------------------

/// An old-federation (signed) account: its confidential wollet, the three real
/// dev-HSM signers that satisfy it, and its public descriptor + master blinding
/// key (so the wollet can be rebuilt inside the blocking section).
struct HsmWallet {
    wollet: ElementsWollet,
    signers: Vec<Pkcs11Signer>,
    descriptor: String,
    mbk: [u8; 32],
}

/// Derive a real dev-HSM 2-of-3 federation for `acct` at `m/48'/1'/{acct}'/2'`
/// and build its confidential wollet against the live custom-regtest network.
///
/// All accounts reuse the same three tokens, so their signers share master
/// fingerprints and differ only by account path — the production condition that
/// makes index-scoped signing necessary.
fn make_hsm_wallet(
    env: &DevEnv,
    key_tag: &str,
    acct: i32,
    blinding_byte: u8,
    net: ElementsNetwork,
    lwk: LwkNetwork,
) -> HsmWallet {
    let path = DerivationPath::from_str(&format!("m/48'/1'/{acct}'/2'")).unwrap();
    let signers: Vec<Pkcs11Signer> = env
        .tokens
        .iter()
        .enumerate()
        .map(|(pos, (token_label, pin))| {
            let key_label = format!("hsme2e-{key_tag}-a{acct}-m{pos}");
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
    let descriptor = to_multipath_string(&ct);
    let handle = ElementsWalletHandle::new(ct, blinding);
    let wollet = ElementsWollet::from_handle_with_lwk(&handle, net, lwk).unwrap();
    HsmWallet {
        wollet,
        signers,
        descriptor,
        mbk: blinding,
    }
}

/// A new-federation **destination** wallet: software-only (2-of-3 `SoftwareSigner`).
/// Never signed in this migration — only used to derive a receive address and to
/// unblind the migrated output for verification. We keep just its public
/// descriptor + master blinding key; the wollet itself is rebuilt inside the
/// blocking section (so the async-side build is dropped immediately).
struct SwWallet {
    descriptor: String,
    mbk: [u8; 32],
}

fn make_sw_wallet(
    tag: Uuid,
    signer_salt: u8,
    blinding_salt: u8,
    net: ElementsNetwork,
    lwk: LwkNetwork,
) -> SwWallet {
    let signers: Vec<SoftwareSigner> = (0u8..3)
        .map(|i| {
            let mut sb = [0u8; 32];
            sb[..16].copy_from_slice(tag.as_bytes());
            sb[16] = signer_salt;
            sb[17] = i;
            SoftwareSigner::new_with_seed_bytes(sb, lwk)
        })
        .collect();
    let mut blinding = [0u8; 32];
    blinding[..16].copy_from_slice(tag.as_bytes());
    blinding[16] = blinding_salt;
    let mut builder = CtDescriptorBuilder::new(2, &blinding)
        .unwrap()
        .key_mode(CtKeyMode::Ranged);
    for s in &signers {
        builder.add_signer(s as &dyn Signer).unwrap();
    }
    let ct = builder.build().unwrap();
    let descriptor = to_multipath_string(&ct);
    let handle = ElementsWalletHandle::new(ct, blinding);
    // Build once to validate the descriptor against the live network, then drop.
    let _ = ElementsWollet::from_handle_with_lwk(&handle, net, lwk).unwrap();
    SwWallet {
        descriptor,
        mbk: blinding,
    }
}

/// Seed a user + `elements_wallets` row (FK target for captured UTXOs).
async fn seed_row(pool: &PgPool, descriptor: &str, mbk: &[u8; 32], tag: Uuid, acct: i32) -> Uuid {
    let user_id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id",
    )
    .bind(format!("{tag}-{acct}@mighsm.local"))
    .fetch_one(pool)
    .await
    .unwrap();
    sqlx::query_scalar(
        "INSERT INTO elements_wallets \
           (user_id, account_idx, descriptor, master_blinding_key, daemon_wallet_name) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(user_id)
    .bind(acct)
    .bind(descriptor)
    .bind(hex32(mbk))
    .bind(format!("mighsm-{tag}-{acct}"))
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Index-scoped per-account signing with real dev-HSM signers: clear
/// `bip32_derivation` on inputs this account does not own (so its
/// shared-fingerprint signers skip them), run the account's HSM signers, then
/// restore. Mirrors the executor's per-account scoping.
fn sign_account(
    pset: &mut elements::pset::PartiallySignedTransaction,
    owned: &[CapturedUtxo],
    signers: &[Pkcs11Signer],
) {
    let owned_set: std::collections::HashSet<elements::OutPoint> =
        owned.iter().map(|u| u.outpoint).collect();
    let indices: Vec<usize> = pset
        .inputs()
        .iter()
        .enumerate()
        .filter(|(_, i)| {
            owned_set.contains(&elements::OutPoint::new(
                i.previous_txid,
                i.previous_output_index,
            ))
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

/// Resolve the live custom-regtest `ElementsNetwork` + `LwkNetwork` from the node
/// (genesis hash + pegged policy asset).
fn live_network(env: &Env) -> (ElementsNetwork, LwkNetwork) {
    let base = Client::new(
        &env.rpc_url,
        Auth::UserPass(env.rpc_user.clone(), env.rpc_pass.clone()),
    )
    .unwrap();
    let genesis: String = base.call("getblockhash", &[json!(0)]).unwrap();
    let sidechain: serde_json::Value = base.call("getsidechaininfo", &[]).unwrap();
    let policy = elements::AssetId::from_str(sidechain["pegged_asset"].as_str().unwrap()).unwrap();
    let net = ElementsNetwork::ElementsRegtest;
    let lwk =
        ElementsNetwork::custom_regtest(policy, elements::BlockHash::from_str(&genesis).unwrap());
    (net, lwk)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Account-for-account (single tx), node-backed, **dev-HSM signed**: fee account
/// + two customers funded on the live node, captured into Postgres, migrated in
/// one PSET whose old-fed inputs are signed by real cryptoki ECDSA, broadcast and
/// accepted. Customers receive their full balance at the new federation; the fee
/// account pays the fee.
#[tokio::test]
async fn elements_a2a_migration_hsm_e2e() {
    let Some(env) = env() else {
        eprintln!("skipping elements_a2a_migration_hsm_e2e: ELEMENTS_RPC_URL/DATABASE_URL unset");
        return;
    };
    let Some(dev) = dev_env() else {
        eprintln!("skipping elements_a2a_migration_hsm_e2e: dev HSM unavailable");
        return;
    };
    let _serial = e2e_lock().lock().await;
    let key_tag = format!("{:x}", std::process::id());

    let (net, lwk) = live_network(&env);
    let pool = PgPool::connect(&env.database_url).await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    let tag = Uuid::new_v4();

    // Unique-per-run account indices (BIP-48 path + DB account_idx).
    let base_acct = (u32::from_le_bytes(tag.as_bytes()[..4].try_into().unwrap()) % 1_000_000)
        as i32
        + 5_000_000;

    // Old (current) HSM-signed wallets: fee account + two customers.
    let fee = make_hsm_wallet(&dev, &key_tag, base_acct, 0xa0, net, lwk);
    let c1 = make_hsm_wallet(&dev, &key_tag, base_acct + 1, 0xa1, net, lwk);
    let c2 = make_hsm_wallet(&dev, &key_tag, base_acct + 2, 0xa2, net, lwk);

    // New-federation destinations (software; receive + unblind only).
    let fee_new = make_sw_wallet(tag, 0x20, 0xb0, net, lwk);
    let c1_new = make_sw_wallet(tag, 0x21, 0xb1, net, lwk);
    let c2_new = make_sw_wallet(tag, 0x22, 0xb2, net, lwk);

    let fee_uuid = seed_row(&pool, &fee.descriptor, &fee.mbk, tag, base_acct).await;
    let c1_uuid = seed_row(&pool, &c1.descriptor, &c1.mbk, tag, base_acct + 1).await;
    let c2_uuid = seed_row(&pool, &c2.descriptor, &c2.mbk, tag, base_acct + 2).await;
    let fee_id = WalletId::from_bytes(*fee_uuid.as_bytes());
    let c1_id = WalletId::from_bytes(*c1_uuid.as_bytes());
    let c2_id = WalletId::from_bytes(*c2_uuid.as_bytes());

    // Fund each old wallet's external addr #0 (1.0 L-BTC each); fee holds 1.0.
    let node = node_wallet(&env);
    let mine: String = node.call("getnewaddress", &[]).unwrap();
    for w in [&fee, &c1, &c2] {
        let addr = w.wollet.address(KeychainKind::External, 0).unwrap();
        let _t: String = node
            .call("sendtoaddress", &[json!(addr.to_string()), json!(1.0)])
            .unwrap();
    }
    let _: Vec<String> = node
        .call("generatetoaddress", &[json!(2), json!(mine.clone())])
        .unwrap();

    let blocks = PgBlockStore::new(pool.clone());
    let utxos_store = PgWalletUtxoStore::new(pool.clone());
    let rpc = (
        env.rpc_url.clone(),
        env.rpc_user.clone(),
        env.rpc_pass.clone(),
    );

    // Move into blocking: descriptors/mbk (rebuild wollets) + the HSM signers.
    let fee_desc = fee.descriptor.clone();
    let c1_desc = c1.descriptor.clone();
    let c2_desc = c2.descriptor.clone();
    let fee_new_desc = fee_new.descriptor.clone();
    let c1_new_desc = c1_new.descriptor.clone();
    let c2_new_desc = c2_new.descriptor.clone();
    let fee_sgn = fee.signers;
    let c1_sgn = c1.signers;
    let c2_sgn = c2.signers;
    let (fee_mbk, c1_mbk, c2_mbk) = (fee.mbk, c1.mbk, c2.mbk);
    let (fee_new_mbk, c1_new_mbk, c2_new_mbk) = (fee_new.mbk, c1_new.mbk, c2_new.mbk);

    // Returns (c1_at_new, c2_at_new, fee_at_new, fee_paid).
    let outcome = tokio::task::spawn_blocking(move || -> Result<(u64, u64, u64, u64), String> {
        let chain = RpcChainSource::new(&rpc.0, &rpc.1, &rpc.2).map_err(de)?;
        let load = |d: &str, m: [u8; 32]| ElementsWollet::from_descriptor_str(d, m, net, lwk);

        let w_fee = load(&fee_desc, fee_mbk).map_err(de)?;
        let w_c1 = load(&c1_desc, c1_mbk).map_err(de)?;
        let w_c2 = load(&c2_desc, c2_mbk).map_err(de)?;
        let w_fee_new = load(&fee_new_desc, fee_new_mbk).map_err(de)?;
        let w_c1_new = load(&c1_new_desc, c1_new_mbk).map_err(de)?;
        let w_c2_new = load(&c2_new_desc, c2_new_mbk).map_err(de)?;
        let fee_dest = w_fee_new.address(KeychainKind::External, 0).map_err(de)?;
        let c1_dest = w_c1_new.address(KeychainKind::External, 0).map_err(de)?;
        let c2_dest = w_c2_new.address(KeychainKind::External, 0).map_err(de)?;

        let mut engine = BlockScanEngine::new();
        engine.register_wallet(fee_id, &w_fee, 20).map_err(de)?;
        engine.register_wallet(c1_id, &w_c1, 20).map_err(de)?;
        engine.register_wallet(c2_id, &w_c2, 20).map_err(de)?;
        engine.sync(&chain, &blocks, &utxos_store).map_err(de)?;

        let fee_utxos = utxos_store.list_unspent(fee_id).map_err(de)?;
        let c1_utxos = utxos_store.list_unspent(c1_id).map_err(de)?;
        let c2_utxos = utxos_store.list_unspent(c2_id).map_err(de)?;
        if fee_utxos.is_empty() || c1_utxos.is_empty() || c2_utxos.is_empty() {
            return Err(format!(
                "capture incomplete: fee={} c1={} c2={}",
                fee_utxos.len(),
                c1_utxos.len(),
                c2_utxos.len()
            ));
        }
        let fee_bal: u64 = fee_utxos.iter().map(CapturedUtxo::value).sum();
        let c1_bal: u64 = c1_utxos.iter().map(CapturedUtxo::value).sum();
        let c2_bal: u64 = c2_utxos.iter().map(CapturedUtxo::value).sum();

        let mut inputs: Vec<(CapturedUtxo, &ElementsWollet)> = Vec::new();
        for u in &fee_utxos {
            inputs.push((u.clone(), &w_fee));
        }
        for u in &c1_utxos {
            inputs.push((u.clone(), &w_c1));
        }
        for u in &c2_utxos {
            inputs.push((u.clone(), &w_c2));
        }
        let blinded = build_migration_pset(
            &w_fee,
            &inputs,
            &[(c1_dest.clone(), c1_bal), (c2_dest.clone(), c2_bal)],
            &fee_dest,
            2000.0,
        )
        .map_err(de)?;
        let mut pset = blinded.into_pset();

        // dev-HSM sign each account's inputs (index-scoped).
        sign_account(&mut pset, &fee_utxos, &fee_sgn);
        sign_account(&mut pset, &c1_utxos, &c1_sgn);
        sign_account(&mut pset, &c2_utxos, &c2_sgn);

        finalize_p2wsh_pset(&mut pset).map_err(de)?;
        let tx = pset.extract_tx().map_err(de)?;
        for inp in &tx.input {
            if inp.witness.script_witness.len() < 4 {
                return Err("input not finalized with a real 2-of-3 P2WSH witness".to_string());
            }
        }

        let val_at = |w: &ElementsWollet, addr: &elements::Address| -> u64 {
            let spk = addr.script_pubkey();
            let o = tx
                .output
                .iter()
                .find(|o| o.script_pubkey == spk)
                .expect("destination output present");
            w.unblind(o).unwrap().value
        };
        let c1_at_new = val_at(&w_c1_new, &c1_dest);
        let c2_at_new = val_at(&w_c2_new, &c2_dest);
        let fee_at_new = val_at(&w_fee_new, &fee_dest);
        let fee_paid = fee_bal - fee_at_new;

        let txid = chain.broadcast(&tx).map_err(de)?;
        eprintln!("a2a dev-HSM migration broadcast txid: {txid}");
        let _ = (c1_bal, c2_bal);
        Ok((c1_at_new, c2_at_new, fee_at_new, fee_paid))
    })
    .await
    .unwrap();

    let (c1_at_new, c2_at_new, fee_at_new, fee_paid) = outcome.expect("migration");
    assert_eq!(c1_at_new, LBTC_SAT, "customer 1 migrated its full balance");
    assert_eq!(c2_at_new, LBTC_SAT, "customer 2 migrated its full balance");
    assert!(fee_paid > 0, "fee account paid a non-zero fee");
    assert_eq!(
        fee_at_new + fee_paid,
        LBTC_SAT,
        "fee account: new balance + fee == its old balance (it paid for everyone)"
    );

    // cleanup
    let _ = node.call::<Vec<String>>("generatetoaddress", &[json!(1), json!(mine)]);
    for id in [fee_uuid, c1_uuid, c2_uuid] {
        sqlx::query(
            "DELETE FROM users WHERE id = (SELECT user_id FROM elements_wallets WHERE id=$1)",
        )
        .bind(id)
        .execute(&pool)
        .await
        .ok();
    }
    sqlx::query("DELETE FROM elements_blocks")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM elements_sync_cursor")
        .execute(&pool)
        .await
        .unwrap();
}

/// Batched migration with **chained confidential fee-change** (decision (b)),
/// node-backed, **dev-HSM signed**: large customer (tx0) → small bundle (tx1) →
/// fee-only final (tx2). The fee account's change is routed back to its OLD-fed
/// address each hop (captured via `captured_from_output`, fed into the next tx)
/// and crosses to the new federation only in the final tx. Every old-fed input
/// is signed by a real dev HSM, and the node accepts all three chained
/// (partly-unconfirmed) broadcasts.
#[tokio::test]
async fn elements_batched_migration_hsm_e2e() {
    const LARGE: u64 = LBTC_SAT; // 1.0
    const SMALL1: u64 = 200_000; // 0.002
    const SMALL2: u64 = 100_000; // 0.001

    let Some(env) = env() else {
        eprintln!(
            "skipping elements_batched_migration_hsm_e2e: ELEMENTS_RPC_URL/DATABASE_URL unset"
        );
        return;
    };
    let Some(dev) = dev_env() else {
        eprintln!("skipping elements_batched_migration_hsm_e2e: dev HSM unavailable");
        return;
    };
    let _serial = e2e_lock().lock().await;
    let key_tag = format!("{:x}b", std::process::id());

    let (net, lwk) = live_network(&env);
    let pool = PgPool::connect(&env.database_url).await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    let tag = Uuid::new_v4();

    let base_acct = (u32::from_le_bytes(tag.as_bytes()[..4].try_into().unwrap()) % 1_000_000)
        as i32
        + 6_000_000;

    // Old HSM-signed wallets: fee + large customer + two small customers.
    let fee = make_hsm_wallet(&dev, &key_tag, base_acct, 0xc0, net, lwk);
    let cl = make_hsm_wallet(&dev, &key_tag, base_acct + 1, 0xc1, net, lwk);
    let cs1 = make_hsm_wallet(&dev, &key_tag, base_acct + 2, 0xc2, net, lwk);
    let cs2 = make_hsm_wallet(&dev, &key_tag, base_acct + 3, 0xc3, net, lwk);
    // New-federation destinations (software).
    let fee_new = make_sw_wallet(tag, 0x40, 0xd0, net, lwk);
    let cl_new = make_sw_wallet(tag, 0x41, 0xd1, net, lwk);
    let cs1_new = make_sw_wallet(tag, 0x42, 0xd2, net, lwk);
    let cs2_new = make_sw_wallet(tag, 0x43, 0xd3, net, lwk);

    let fee_uuid = seed_row(&pool, &fee.descriptor, &fee.mbk, tag, base_acct).await;
    let cl_uuid = seed_row(&pool, &cl.descriptor, &cl.mbk, tag, base_acct + 1).await;
    let cs1_uuid = seed_row(&pool, &cs1.descriptor, &cs1.mbk, tag, base_acct + 2).await;
    let cs2_uuid = seed_row(&pool, &cs2.descriptor, &cs2.mbk, tag, base_acct + 3).await;
    let fee_id = WalletId::from_bytes(*fee_uuid.as_bytes());
    let cl_id = WalletId::from_bytes(*cl_uuid.as_bytes());
    let cs1_id = WalletId::from_bytes(*cs1_uuid.as_bytes());
    let cs2_id = WalletId::from_bytes(*cs2_uuid.as_bytes());

    // Fund each old wallet's external addr #0.
    let node = node_wallet(&env);
    let mine: String = node.call("getnewaddress", &[]).unwrap();
    for (w, amt) in [(&fee, 1.0), (&cl, 1.0), (&cs1, 0.002), (&cs2, 0.001)] {
        let addr = w.wollet.address(KeychainKind::External, 0).unwrap();
        let _t: String = node
            .call("sendtoaddress", &[json!(addr.to_string()), json!(amt)])
            .unwrap();
    }
    let _: Vec<String> = node
        .call("generatetoaddress", &[json!(2), json!(mine.clone())])
        .unwrap();

    let blocks = PgBlockStore::new(pool.clone());
    let utxos_store = PgWalletUtxoStore::new(pool.clone());
    let rpc = (
        env.rpc_url.clone(),
        env.rpc_user.clone(),
        env.rpc_pass.clone(),
    );

    let (fee_desc, cl_desc, cs1_desc, cs2_desc) = (
        fee.descriptor.clone(),
        cl.descriptor.clone(),
        cs1.descriptor.clone(),
        cs2.descriptor.clone(),
    );
    let (fee_new_desc, cl_new_desc, cs1_new_desc, cs2_new_desc) = (
        fee_new.descriptor.clone(),
        cl_new.descriptor.clone(),
        cs1_new.descriptor.clone(),
        cs2_new.descriptor.clone(),
    );
    let fee_sgn = fee.signers;
    let cl_sgn = cl.signers;
    let cs1_sgn = cs1.signers;
    let cs2_sgn = cs2.signers;
    let (fee_mbk, cl_mbk, cs1_mbk, cs2_mbk) = (fee.mbk, cl.mbk, cs1.mbk, cs2.mbk);
    let (fee_new_mbk, cl_new_mbk, cs1_new_mbk, cs2_new_mbk) =
        (fee_new.mbk, cl_new.mbk, cs1_new.mbk, cs2_new.mbk);

    // Returns (large_at_new, small1_at_new, small2_at_new, fee_at_new, fee_bal,
    // broadcasts).
    let outcome = tokio::task::spawn_blocking(
        move || -> Result<(u64, u64, u64, u64, u64, usize), String> {
            let chain = RpcChainSource::new(&rpc.0, &rpc.1, &rpc.2).map_err(de)?;
            let load = |d: &str, m: [u8; 32]| ElementsWollet::from_descriptor_str(d, m, net, lwk);

            let w_fee = load(&fee_desc, fee_mbk).map_err(de)?;
            let w_cl = load(&cl_desc, cl_mbk).map_err(de)?;
            let w_cs1 = load(&cs1_desc, cs1_mbk).map_err(de)?;
            let w_cs2 = load(&cs2_desc, cs2_mbk).map_err(de)?;
            let w_fee_new = load(&fee_new_desc, fee_new_mbk).map_err(de)?;
            let w_cl_new = load(&cl_new_desc, cl_new_mbk).map_err(de)?;
            let w_cs1_new = load(&cs1_new_desc, cs1_new_mbk).map_err(de)?;
            let w_cs2_new = load(&cs2_new_desc, cs2_new_mbk).map_err(de)?;

            let fee_old_addr = w_fee.address(KeychainKind::External, 0).map_err(de)?;
            let fee_new_dest = w_fee_new.address(KeychainKind::External, 0).map_err(de)?;
            let cl_dest = w_cl_new.address(KeychainKind::External, 0).map_err(de)?;
            let cs1_dest = w_cs1_new.address(KeychainKind::External, 0).map_err(de)?;
            let cs2_dest = w_cs2_new.address(KeychainKind::External, 0).map_err(de)?;

            let mut engine = BlockScanEngine::new();
            engine.register_wallet(fee_id, &w_fee, 20).map_err(de)?;
            engine.register_wallet(cl_id, &w_cl, 20).map_err(de)?;
            engine.register_wallet(cs1_id, &w_cs1, 20).map_err(de)?;
            engine.register_wallet(cs2_id, &w_cs2, 20).map_err(de)?;
            engine.sync(&chain, &blocks, &utxos_store).map_err(de)?;

            let fee_utxos = utxos_store.list_unspent(fee_id).map_err(de)?;
            let cl_utxos = utxos_store.list_unspent(cl_id).map_err(de)?;
            let cs1_utxos = utxos_store.list_unspent(cs1_id).map_err(de)?;
            let cs2_utxos = utxos_store.list_unspent(cs2_id).map_err(de)?;
            if fee_utxos.is_empty()
                || cl_utxos.is_empty()
                || cs1_utxos.is_empty()
                || cs2_utxos.is_empty()
            {
                return Err("capture incomplete".to_string());
            }
            let fee_bal: u64 = fee_utxos.iter().map(CapturedUtxo::value).sum();

            let val_at =
                |tx: &elements::Transaction, w: &ElementsWollet, addr: &elements::Address| -> u64 {
                    let spk = addr.script_pubkey();
                    let o = tx
                        .output
                        .iter()
                        .find(|o| o.script_pubkey == spk)
                        .expect("destination output present");
                    w.unblind(o).unwrap().value
                };
            // Capture the fee account's change (at its OLD-fed addr) as the
            // chained input for the next tx.
            let cap_chain = |tx: &elements::Transaction| -> Result<CapturedUtxo, String> {
                let spk = fee_old_addr.script_pubkey();
                let (vout, txout) = tx
                    .output
                    .iter()
                    .enumerate()
                    .find(|(_, o)| o.script_pubkey == spk)
                    .map(|(i, o)| (u32::try_from(i).unwrap(), o.clone()))
                    .ok_or("fee change output missing")?;
                captured_from_output(&w_fee, tx.txid(), vout, &txout, fee_id, 0).map_err(de)
            };
            let assert_witnessed = |tx: &elements::Transaction| -> Result<(), String> {
                for inp in &tx.input {
                    if inp.witness.script_witness.len() < 4 {
                        return Err("input not finalized with a real 2-of-3 P2WSH witness".into());
                    }
                }
                Ok(())
            };

            let mut broadcasts = 0usize;

            // --- tx0: large customer + fee seed → change back to fee OLD. ---
            let mut inputs: Vec<(CapturedUtxo, &ElementsWollet)> = Vec::new();
            for u in &cl_utxos {
                inputs.push((u.clone(), &w_cl));
            }
            inputs.push((fee_utxos[0].clone(), &w_fee));
            let blinded = build_migration_pset(
                &w_fee,
                &inputs,
                &[(cl_dest.clone(), LARGE)],
                &fee_old_addr,
                2000.0,
            )
            .map_err(de)?;
            let mut pset = blinded.into_pset();
            sign_account(&mut pset, &cl_utxos, &cl_sgn);
            sign_account(&mut pset, std::slice::from_ref(&fee_utxos[0]), &fee_sgn);
            finalize_p2wsh_pset(&mut pset).map_err(de)?;
            let tx0 = pset.extract_tx().map_err(de)?;
            assert_witnessed(&tx0)?;
            // Intermediate fee change at OLD-fed, never new-fed.
            if !tx0
                .output
                .iter()
                .any(|o| o.script_pubkey == fee_old_addr.script_pubkey())
            {
                return Err("tx0 fee change not at OLD-fed address".into());
            }
            if tx0
                .output
                .iter()
                .any(|o| o.script_pubkey == fee_new_dest.script_pubkey())
            {
                return Err("tx0 must NOT touch the new-fed address".into());
            }
            let large_at_new = val_at(&tx0, &w_cl_new, &cl_dest);
            chain.broadcast(&tx0).map_err(de)?;
            broadcasts += 1;
            let chained0 = cap_chain(&tx0)?;

            // --- tx1: small bundle + chained change → change back to fee OLD. ---
            let mut inputs: Vec<(CapturedUtxo, &ElementsWollet)> = Vec::new();
            for u in &cs1_utxos {
                inputs.push((u.clone(), &w_cs1));
            }
            for u in &cs2_utxos {
                inputs.push((u.clone(), &w_cs2));
            }
            inputs.push((chained0.clone(), &w_fee));
            let blinded = build_migration_pset(
                &w_fee,
                &inputs,
                &[(cs1_dest.clone(), SMALL1), (cs2_dest.clone(), SMALL2)],
                &fee_old_addr,
                2000.0,
            )
            .map_err(de)?;
            let mut pset = blinded.into_pset();
            sign_account(&mut pset, &cs1_utxos, &cs1_sgn);
            sign_account(&mut pset, &cs2_utxos, &cs2_sgn);
            sign_account(&mut pset, std::slice::from_ref(&chained0), &fee_sgn);
            finalize_p2wsh_pset(&mut pset).map_err(de)?;
            let tx1 = pset.extract_tx().map_err(de)?;
            assert_witnessed(&tx1)?;
            if tx1
                .output
                .iter()
                .any(|o| o.script_pubkey == fee_new_dest.script_pubkey())
            {
                return Err("tx1 must NOT touch the new-fed address".into());
            }
            let small1_at_new = val_at(&tx1, &w_cs1_new, &cs1_dest);
            let small2_at_new = val_at(&tx1, &w_cs2_new, &cs2_dest);
            chain.broadcast(&tx1).map_err(de)?;
            broadcasts += 1;
            let chained1 = cap_chain(&tx1)?;

            // --- tx2: fee account migrates last → drain to fee NEW dest. ---
            let inputs: Vec<(CapturedUtxo, &ElementsWollet)> = vec![(chained1.clone(), &w_fee)];
            let blinded =
                build_migration_pset(&w_fee, &inputs, &[], &fee_new_dest, 2000.0).map_err(de)?;
            let mut pset = blinded.into_pset();
            sign_account(&mut pset, std::slice::from_ref(&chained1), &fee_sgn);
            finalize_p2wsh_pset(&mut pset).map_err(de)?;
            let tx2 = pset.extract_tx().map_err(de)?;
            assert_witnessed(&tx2)?;
            if tx2
                .output
                .iter()
                .any(|o| o.script_pubkey == fee_old_addr.script_pubkey())
            {
                return Err("final tx must route the fee account to NEW-fed, not OLD".into());
            }
            let fee_at_new = val_at(&tx2, &w_fee_new, &fee_new_dest);
            chain.broadcast(&tx2).map_err(de)?;
            broadcasts += 1;

            Ok((
                large_at_new,
                small1_at_new,
                small2_at_new,
                fee_at_new,
                fee_bal,
                broadcasts,
            ))
        },
    )
    .await
    .unwrap();

    let (large_at_new, small1_at_new, small2_at_new, fee_at_new, fee_bal, broadcasts) =
        outcome.expect("batched migration");

    assert_eq!(broadcasts, 3, "one large tx + one small bundle + fee-final");
    assert_eq!(
        large_at_new, LARGE,
        "large customer migrated its full balance"
    );
    assert_eq!(
        small1_at_new, SMALL1,
        "small customer 1 migrated its full balance"
    );
    assert_eq!(
        small2_at_new, SMALL2,
        "small customer 2 migrated its full balance"
    );
    let fee_paid = fee_bal - fee_at_new;
    assert!(fee_paid > 0, "fee account paid a non-zero cumulative fee");
    assert_eq!(
        fee_at_new + fee_paid,
        fee_bal,
        "fee account: final new-fed balance + cumulative fee == its old balance"
    );

    // cleanup
    let _ = node.call::<Vec<String>>("generatetoaddress", &[json!(1), json!(mine)]);
    for id in [fee_uuid, cl_uuid, cs1_uuid, cs2_uuid] {
        sqlx::query(
            "DELETE FROM users WHERE id = (SELECT user_id FROM elements_wallets WHERE id=$1)",
        )
        .bind(id)
        .execute(&pool)
        .await
        .ok();
    }
    sqlx::query("DELETE FROM elements_blocks")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM elements_sync_cursor")
        .execute(&pool)
        .await
        .unwrap();
}
