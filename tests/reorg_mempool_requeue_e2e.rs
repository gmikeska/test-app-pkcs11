//! Layer-2 e2e — **state (b): mempool-requeue, do-NOT-revert** through the real
//! `UserWallet::sync` (**bitcoind-RPC** backend) path (plan §5.6, D5).
//!
//! RPC-backend sibling of `test-app-electrum`'s `reorg_mempool_requeue_e2e.rs`.
//! Together they prove D5's do-not-revert leg is **cross-backend-safe**: a sweep
//! reorged out of its block but **re-queued into the mempool** is treated as
//! *present* (canonical-unconfirmed) and the completed migration is **NOT**
//! reverted — identically on the Electrum `full_scan` rebuild and this RPC
//! `emitter.mempool()` rebuild. The RPC path's reorg signal is the emitter's
//! `CannotConnect` (Step 1.5), whose rebuild pulls `emitter.mempool()` and applies
//! the re-queued tx via `apply_unconfirmed_txs`, so `D` surfaces as unconfirmed.
//!
//! The recipe difference vs. state (a) (`reorg_reconciliation_e2e.rs`): **no
//! funding double-spend**, and the competing branch is built with coinbase-only
//! **`generateblock`** so the re-queued `D` is never re-mined and stays
//! unconfirmed in the mempool. `D`'s funding input `U` is confirmed *below* the
//! invalidated block, so `D` stays a valid mempool tx throughout.
//!
//! ## Harness (gv-regtest)
//!   * regtest bitcoind — JSON-RPC `host.docker.internal:18543` (`regtest`/`regtest`)
//!   * Postgres — `DATABASE_URL` from `.env` (host.docker.internal:5546)
//!   * dev-HSM — `PKCS11_LIB` + `APP_HSM_{1,2,3}_*` from `.env`, `SOFTHSM2_CONF` set
//!
//! No Electrum/Esplora server needed — the RPC path reads bitcoind directly.
//! Opt-in gate (skips cleanly otherwise): `RPC_LIVE=1`. Run from `test-app-pkcs11/`:
//! ```bash
//! RPC_LIVE=1 cargo test --test reorg_mempool_requeue_e2e -- --nocapture --test-threads=1
//! ```

// Test-local lints: regtest sat/BTC conversions do lossy int/float casts and the
// scenario body is a long linear script (same set the sibling e2es tolerate).
#![allow(
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::needless_pass_by_value
)]

use std::process::Command;
use std::sync::Arc;

use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;

use emvault::core::bdk_wallet::LocalOutput;
use emvault::core::bdk_wallet::chain::ChainPosition;
use emvault::core::bitcoin::{Amount, Txid};

use test_app_pkcs11::config::AppConfig;
use test_app_pkcs11::db;
use test_app_pkcs11::hsm::HsmFleet;
use test_app_pkcs11::wallet::{UserWallet, WalletManager};

const FUND_SATS: u64 = 500_000_000; // 5 BTC deposit

fn rpc_base() -> String {
    "http://host.docker.internal:18543".to_string()
}
fn rpc_auth() -> String {
    "regtest:regtest".to_string()
}
fn miner_path() -> String {
    "/wallet/miner".to_string()
}

/// Minimal bitcoind JSON-RPC over `curl` (mirrors `drive.sh` / `live_reorg.rs`).
fn rpc(method: &str, params: Value, wallet: Option<&str>) -> Value {
    let url = format!("{}{}", rpc_base(), wallet.unwrap_or(""));
    let body =
        json!({"jsonrpc": "1.0", "id": "requeue-rpc-e2e", "method": method, "params": params});
    let out = Command::new("curl")
        .args([
            "-s",
            "--max-time",
            "60",
            "--user",
            &rpc_auth(),
            "--data-binary",
            &body.to_string(),
            "-H",
            "content-type: text/plain;",
            &url,
        ])
        .output()
        .expect("spawn curl");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "rpc {method}: bad JSON: {e}: {}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    assert!(
        v.get("error").is_none_or(Value::is_null),
        "rpc {method} error: {}",
        v["error"]
    );
    v["result"].clone()
}

/// Mine `n` blocks that DO pull the mempool (`generatetoaddress`).
fn mine(n: u32) -> u64 {
    let addr = rpc("getnewaddress", json!([]), Some(&miner_path()));
    let addr = addr.as_str().expect("getnewaddress");
    rpc("generatetoaddress", json!([n, addr]), None);
    block_count()
}

/// Mine ONE coinbase-only block via `generateblock` (empty tx list) — Core does
/// **not** include the general mempool, so a re-queued tx stays unconfirmed.
fn generate_empty_block() -> u64 {
    let addr = rpc("getnewaddress", json!([]), Some(&miner_path()));
    let addr = addr.as_str().expect("getnewaddress");
    rpc("generateblock", json!([addr, []]), None);
    block_count()
}

fn block_count() -> u64 {
    rpc("getblockcount", json!([]), None).as_u64().unwrap()
}
fn block_hash(height: u64) -> String {
    rpc("getblockhash", json!([height]), None)
        .as_str()
        .unwrap()
        .to_string()
}
fn btc(sats: u64) -> f64 {
    sats as f64 / 100_000_000.0
}

/// Set an env var (edition-2024 `set_var` is `unsafe`). Called single-threaded
/// before `AppConfig::from_env`, so no data-race concern.
fn set_env(key: &str, val: &str) {
    unsafe { std::env::set_var(key, val) };
}

/// Point `AppConfig::from_env` at the gv-regtest bitcoind on the **RPC backend**
/// with a fast 2-of-3 federation, overriding the `.env` defaults.
fn configure_regtest_rpc_env() {
    let _ = dotenvy::from_path(concat!(env!("CARGO_MANIFEST_DIR"), "/.env"));
    // The restarted gv-regtest Postgres binds the docker-bridge iface at
    // host.docker.internal:5546 (the app `.env` still names the old
    // 127.0.0.1:5432 endpoint). Override to the live container.
    set_env(
        "DATABASE_URL",
        "postgres://asterism:asterism@host.docker.internal:5546/asterism_pkcs11",
    );
    set_env("BITCOIN_NETWORK", "regtest");
    set_env("APP_CHAIN_BACKEND", "rpc"); // emitter path, esplora disabled
    set_env("BITCOIN_RPC_HOST", "host.docker.internal");
    set_env("BITCOIN_RPC_PORT", "18543");
    set_env("BITCOIN_RPC_USER", "regtest");
    set_env("BITCOIN_RPC_PASSWORD", "regtest");
    set_env("BITCOIN_WALLET_NAME", "miner");
    set_env("APP_FED_SIGNERS", "1,2,3");
    set_env("APP_FED_THRESHOLD", "2");
}

fn skip() -> bool {
    if std::env::var("RPC_LIVE").ok().as_deref() != Some("1") {
        eprintln!("SKIP: set RPC_LIVE=1 (needs gv-regtest bitcoind + Postgres + dev-HSM)");
        return true;
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rpc_reorg_mempool_requeue_does_not_revert() {
    if skip() {
        return;
    }
    configure_regtest_rpc_env();

    let config = AppConfig::from_env().expect("regtest AppConfig::from_env");
    let hsm = Arc::new(HsmFleet::new(&config).expect("dev-HSM fleet"));
    let pool = sqlx::PgPool::connect(&config.database_url)
        .await
        .expect("connect Postgres");
    db::migrate(&pool).await.expect("migrations (incl. 0008)");
    let wm = WalletManager::new(pool.clone(), &config, hsm).expect("wallet manager");

    let email = format!("requeue-rpc-e2e-{}@test.local", Uuid::new_v4());
    db::upsert_user_if_absent(&pool, &email, "x")
        .await
        .expect("create user");
    let user = db::find_user_by_email(&pool, &email)
        .await
        .expect("find user")
        .expect("user row");
    wm.ensure_wallet_for_user(user.id)
        .await
        .expect("provision wallet + v0 federation version");
    let wallet = wm.load_or_init(user.id).await.expect("load UserWallet");
    let wallet_id = wallet.wallet_id();

    let versions = db::list_federation_versions_for_wallet(&pool, wallet_id)
        .await
        .expect("list versions");
    assert_eq!(versions.len(), 1, "bootstrap provisions exactly v0");
    let v0_id = versions[0].id;

    // --- Phase 1: fund a v0 address, confirm, bury below the tip -----------
    let addr = wallet.reveal_addresses(1).await.expect("reveal v0 addr")[0]
        .address
        .clone();
    eprintln!("funding v0 address: {addr}");
    let d_txid_str = rpc(
        "sendtoaddress",
        json!([addr, btc(FUND_SATS)]),
        Some(&miner_path()),
    );
    let d_txid_str = d_txid_str.as_str().expect("sendtoaddress txid").to_string();
    let d_txid: Txid = d_txid_str.parse().expect("parse D txid");
    let d = rpc("getrawtransaction", json!([d_txid_str, true]), None);
    let u_txid = d["vin"][0]["txid"].as_str().unwrap().to_string();
    eprintln!("D={d_txid_str} (funded by U={u_txid})");

    let h0 = mine(1);
    let b0 = block_hash(h0);
    let h_pre = mine(2);
    eprintln!("D confirmed in B0 height={h0}; pre-reorg tip={h_pre}");

    let s1 = wallet.sync().await.expect("sync #1");
    let bal1 = wallet.balance().await;
    eprintln!(
        "sync #1: tip={} confirmed={} total={}",
        s1.tip_height,
        bal1.confirmed,
        bal1.total()
    );
    // Ground truth on D specifically (the 2-of-3 federation descriptor derives a
    // deterministic v0 address shared across test runs, so an aggregate-balance
    // equality would be contaminated by residue from prior runs — assert on D's
    // own UTXO + chain position, which is exactly what the reconcile keys on).
    let funded = find_utxo(&wallet, d_txid).await;
    assert!(
        matches!(funded.chain_position, ChainPosition::Confirmed { .. }),
        "D must be CONFIRMED before the reorg: {:?}",
        funded.chain_position
    );
    assert_eq!(
        funded.txout.value,
        Amount::from_sat(FUND_SATS),
        "D funds the v0 address with the expected amount"
    );

    // --- Enact: optimistically flip v0 -> complete, recording the sweep txid.
    db::set_migration_complete(&pool, v0_id, &d_txid_str)
        .await
        .expect("mark v0 complete + record sweep txid");
    let (st, tx) = read_status(&pool, v0_id).await;
    assert_eq!(st, "complete");
    assert_eq!(tx.as_deref(), Some(d_txid_str.as_str()));

    // --- Phase 2: reorg B0 out, but let D re-queue into the mempool --------
    rpc("invalidateblock", json!([b0]), None);
    let mempool = rpc("getrawmempool", json!([]), None);
    assert!(
        mempool
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t.as_str() == Some(d_txid_str.as_str())),
        "after invalidateblock, D must be back in the mempool (not double-spent): {mempool}"
    );
    let target = h_pre + 3;
    while block_count() < target {
        generate_empty_block();
    }
    let h_post = block_count();
    assert!(h_post > h_pre, "reorg branch must be strictly longer");
    let mempool_post = rpc("getrawmempool", json!([]), None);
    assert!(
        mempool_post
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t.as_str() == Some(d_txid_str.as_str())),
        "D must remain unconfirmed in the mempool after the competing branch: {mempool_post}"
    );
    eprintln!("post-reorg tip={h_post} (was {h_pre}); D still unconfirmed in mempool");

    // --- Phase 3: THE OBSERVATION — sync rebuilds; D is present-in-mempool --
    let s2 = wallet.sync().await.expect("sync #2 (reorg) succeeds");
    let bal2 = wallet.balance().await;
    eprintln!(
        "sync #2: reorg_rebuilt={} migrations_reverted={} tip={} confirmed={} untrusted_pending={} total={}",
        s2.reorg_rebuilt,
        s2.migrations_reverted,
        s2.tip_height,
        bal2.confirmed,
        bal2.untrusted_pending,
        bal2.total()
    );

    let _ = bal2; // aggregate balance is contaminated by the shared-address residue; observe only.

    assert!(s2.reorg_rebuilt, "sync must detect + rebuild the reorg");

    // Ground truth: D is present in the wallet graph as UNCONFIRMED (mempool) —
    // the RPC emitter rebuild pulled `emitter.mempool()` and applied the re-queued tx.
    let requeued = find_utxo(&wallet, d_txid).await;
    assert!(
        matches!(requeued.chain_position, ChainPosition::Unconfirmed { .. }),
        "D must read as UNCONFIRMED-in-mempool, not confirmed and not absent: {:?}",
        requeued.chain_position
    );

    // The migration must NOT be reverted — a present (mempool) sweep is retained.
    assert_eq!(
        s2.migrations_reverted, 0,
        "D5: a mempool-requeued sweep is PRESENT → the migration must NOT revert"
    );
    let (st2, tx2) = read_status(&pool, v0_id).await;
    assert_eq!(
        st2, "complete",
        "v0 stays complete (sweep re-queued, about to re-confirm)"
    );
    assert_eq!(
        tx2.as_deref(),
        Some(d_txid_str.as_str()),
        "v0 sweep txid is RETAINED, not cleared"
    );

    // --- Phase 4: idempotency — a second sync must still not revert ---------
    let s3 = wallet.sync().await.expect("sync #3 (idempotency)");
    eprintln!(
        "sync #3: reorg_rebuilt={} migrations_reverted={}",
        s3.reorg_rebuilt, s3.migrations_reverted
    );
    assert_eq!(
        s3.migrations_reverted, 0,
        "still-complete v0 must not be reverted on a follow-up sync"
    );
    let (st3, tx3) = read_status(&pool, v0_id).await;
    assert_eq!(st3, "complete", "v0 stays complete after re-sync");
    assert_eq!(
        tx3.as_deref(),
        Some(d_txid_str.as_str()),
        "sweep txid still retained"
    );

    // --- Cleanup: drain the mempool leftover (this test deliberately leaves D
    // unconfirmed), then delete the user (CASCADE) ---------------------------
    mine(1); // re-confirm D so no dangling mempool tx surprises a later run
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await;
    eprintln!(
        "PASS: RPC-backend mempool-requeued sweep stayed present; migration NOT reverted; idempotent; cleaned up"
    );
}

/// The single unspent wallet output paying from tx `txid`. The 2-of-3 federation
/// descriptor derives a deterministic v0 address shared across runs, so keying on
/// the txid (not the address/aggregate) isolates *this* run's funding UTXO — and
/// is exactly what the reconcile predicate keys on.
async fn find_utxo(wallet: &UserWallet, txid: Txid) -> LocalOutput {
    let mut matches: Vec<LocalOutput> = wallet
        .list_unspent()
        .await
        .into_iter()
        .filter(|o| o.outpoint.txid == txid)
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one wallet UTXO from tx {txid}, found {}",
        matches.len()
    );
    matches.pop().unwrap()
}

async fn read_status(pool: &sqlx::PgPool, version_id: Uuid) -> (String, Option<String>) {
    let row = sqlx::query(
        "SELECT migration_status, migration_sweep_txid \
         FROM federation_versions WHERE id = $1",
    )
    .bind(version_id)
    .fetch_one(pool)
    .await
    .expect("read version status");
    (row.get("migration_status"), row.get("migration_sweep_txid"))
}
