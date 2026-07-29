//! Layer-2 e2e — **app-side reorg reconciliation** through the real
//! `UserWallet::sync` (**bitcoind-RPC** backend) path (plan §5.3 / Phase 4b).
//!
//! This is the RPC-backend sibling of `test-app-electrum`'s
//! `reorg_reconciliation_e2e.rs`. It proves that the *same* app-domain outcome —
//! an optimistically-`complete` migration reverted to `pending` when its recorded
//! sweep txid is reorged out — is reached through the **RPC emitter** path, whose
//! reorg behaviour is genuinely different from the nodeless backends: the emitter
//! raises `CannotConnect` on a reorg-below-tip, which the backend's
//! rebuild-on-`CannotConnect` recovery (emvault-core `chain_sync::emitter_sync`,
//! Step 1.5) turns into a from-scratch rebuild + `reorg_rebuilt = true`. That the
//! electrum path (test-app-electrum) and this RPC path reach the **identical**
//! domain state (`complete → pending`, `migration_sweep_txid → NULL`) is the
//! cross-backend "switch freely, no rewrite" proof at the app layer.
//!
//! The reconcile predicate is wallet ground-truth (is the recorded sweep txid
//! still present in the rebuilt graph?), federation-size- and backend-agnostic.
//! As in the electrum e2e, the recorded "sweep" is the confirmed funding tx the
//! wallet holds, evicted via the proven §6.2 funding-double-spend recipe (§5.3
//! v1 scope). The federation wallet is genuinely HSM-derived; the reorg path
//! signs nothing.
//!
//! ## Harness (gv-regtest)
//!   * regtest bitcoind — JSON-RPC `host.docker.internal:18543` (`regtest`/`regtest`)
//!   * Postgres — `DATABASE_URL` from `.env` (host.docker.internal:5546)
//!   * dev-HSM — `PKCS11_LIB` + `APP_HSM_{1,2,3}_*` from `.env`, `SOFTHSM2_CONF` set
//!
//! No Electrum/Esplora server needed — the RPC path reads bitcoind directly.
//! Opt-in gate (skips cleanly otherwise): `RPC_LIVE=1`. Run from
//! `test-app-pkcs11/`:
//! ```bash
//! RPC_LIVE=1 cargo test --test reorg_reconciliation_e2e -- --nocapture --test-threads=1
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

use emvault::core::bitcoin::Amount;

use test_app_pkcs11::config::AppConfig;
use test_app_pkcs11::db;
use test_app_pkcs11::hsm::HsmFleet;
use test_app_pkcs11::wallet::WalletManager;

const FUND_SATS: u64 = 500_000_000; // 5 BTC deposit
const EVICT_FEE_SATS: u64 = 1_000_000; // dwarfs the funding fee, RBF-replaces D

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
    let body = json!({"jsonrpc": "1.0", "id": "recon-rpc-e2e", "method": method, "params": params});
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

fn mine(n: u32) -> u64 {
    let addr = rpc("getnewaddress", json!([]), Some(&miner_path()));
    let addr = addr.as_str().expect("getnewaddress");
    rpc("generatetoaddress", json!([n, addr]), None);
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
async fn rpc_reorg_reverts_completed_migration() {
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

    let email = format!("recon-rpc-e2e-{}@test.local", Uuid::new_v4());
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
    let d_txid = rpc(
        "sendtoaddress",
        json!([addr, btc(FUND_SATS)]),
        Some(&miner_path()),
    );
    let d_txid = d_txid.as_str().expect("sendtoaddress txid").to_string();
    let d = rpc("getrawtransaction", json!([d_txid, true]), None);
    let u_txid = d["vin"][0]["txid"].as_str().unwrap().to_string();
    let u_vout = d["vin"][0]["vout"].as_u64().unwrap();
    let u = rpc("getrawtransaction", json!([u_txid, true]), None);
    let u_value_btc = u["vout"][u_vout as usize]["value"].as_f64().unwrap();
    eprintln!("D={d_txid} U={u_txid}:{u_vout} ({u_value_btc} BTC)");

    let h0 = mine(1);
    let b0 = block_hash(h0);
    let h_pre = mine(2);
    eprintln!("D confirmed in B0 height={h0}; pre-reorg tip={h_pre}");

    let s1 = wallet.sync().await.expect("sync #1");
    let bal1 = wallet.balance().await.total();
    eprintln!("sync #1: tip={} balance={}", s1.tip_height, bal1);
    assert_eq!(
        bal1,
        Amount::from_sat(FUND_SATS),
        "v0 must see the funding UTXO before the reorg"
    );

    // --- Enact: optimistically flip v0 -> complete, recording the sweep txid.
    db::set_migration_complete(&pool, v0_id, &d_txid)
        .await
        .expect("mark v0 complete + record sweep txid");
    let (st, tx) = read_status(&pool, v0_id).await;
    assert_eq!(st, "complete");
    assert_eq!(tx.as_deref(), Some(d_txid.as_str()));

    // --- Phase 2: reorg below the persisted tip, evicting D ----------------
    rpc("invalidateblock", json!([b0]), None);
    let dest = rpc("getnewaddress", json!([]), Some(&miner_path()));
    let out_sats = (u_value_btc * 100_000_000.0).round() as u64 - EVICT_FEE_SATS;
    let mut outputs = serde_json::Map::new();
    outputs.insert(dest.as_str().unwrap().to_string(), json!(btc(out_sats)));
    let raw = rpc(
        "createrawtransaction",
        json!([[{"txid": u_txid, "vout": u_vout}], Value::Object(outputs)]),
        None,
    );
    let signed = rpc(
        "signrawtransactionwithwallet",
        json!([raw.as_str().unwrap()]),
        Some(&miner_path()),
    );
    assert!(
        signed["complete"].as_bool().unwrap_or(false),
        "miner must sign the double-spend of U: {signed}"
    );
    let d_prime = rpc(
        "sendrawtransaction",
        json!([signed["hex"].as_str().unwrap()]),
        None,
    );
    eprintln!("broadcast D' (evicts D): {}", d_prime.as_str().unwrap());
    let h_post = mine((h_pre - block_count()) as u32 + 3);
    assert!(h_post > h_pre, "reorg branch must be strictly longer");
    eprintln!("post-reorg tip={h_post} (was {h_pre})");

    // --- Phase 3: THE OBSERVATION — sync drives rebuild + reconcile --------
    let s2 = wallet.sync().await.expect("sync #2 (reorg) succeeds");
    let bal2 = wallet.balance().await.total();
    eprintln!(
        "sync #2: reorg_rebuilt={} migrations_reverted={} tip={} balance={bal2}",
        s2.reorg_rebuilt, s2.migrations_reverted, s2.tip_height
    );
    assert!(s2.reorg_rebuilt, "sync must detect + rebuild the reorg");
    assert_eq!(
        s2.migrations_reverted, 1,
        "the completed migration whose sweep was evicted must be reverted"
    );
    let (st2, tx2) = read_status(&pool, v0_id).await;
    assert_eq!(st2, "pending", "v0 reverted complete -> pending");
    assert_eq!(tx2, None, "v0 sweep txid cleared to NULL");
    assert_eq!(
        bal2,
        Amount::from_sat(0),
        "the §6.2 funding-double-spend also drops the deposit (v0 -> 0)"
    );

    // --- Phase 4: idempotency ----------------------------------------------
    let s3 = wallet.sync().await.expect("sync #3 (idempotency)");
    eprintln!(
        "sync #3: reorg_rebuilt={} migrations_reverted={}",
        s3.reorg_rebuilt, s3.migrations_reverted
    );
    assert_eq!(
        s3.migrations_reverted, 0,
        "already-pending v0 must not be reverted again"
    );
    let (st3, _) = read_status(&pool, v0_id).await;
    assert_eq!(st3, "pending", "v0 stays pending after re-sync");

    // --- Cleanup ------------------------------------------------------------
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await;
    eprintln!("PASS: RPC-backend reorg reverted the completed migration; idempotent; cleaned up");
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
