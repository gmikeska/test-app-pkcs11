//! Post-migration verification — check that all accounts migrated correctly.
//!
//! Syncs all wallets, displays per-account balances, checks migration
//! status on federation versions, and reports pass/fail.
//!
//! ```text
//! cargo run --example migration_verify
//! ```

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::Amount;
use sqlx::postgres::PgPoolOptions;

use test_app_pkcs11::config::AppConfig;
use test_app_pkcs11::db;
use test_app_pkcs11::hsm::HsmFleet;
use test_app_pkcs11::wallet::WalletManager;

// =========================================================================
// Main
// =========================================================================

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() {
    let env_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".env");
    let _ = dotenvy::from_path(&env_path);

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let app_config = AppConfig::from_env().expect("app config");

    let pool = PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(8))
        .connect(&app_config.database_url)
        .await
        .expect("database connection");
    db::migrate(&pool).await.expect("database migration");

    let hsm = Arc::new(HsmFleet::new(&app_config).expect("HSM fleet"));
    let wm = WalletManager::new(pool.clone(), &app_config, hsm.clone()).expect("wallet manager");

    println!("Migration Verification");
    println!("======================");
    println!();

    let wallet_rows = db::list_all_wallets(&pool).await.expect("list wallets");
    if wallet_rows.is_empty() {
        eprintln!("  No wallets found.");
        std::process::exit(1);
    }

    // =====================================================================
    // Balance check
    // =====================================================================

    println!("  Account Balances (post-migration)");
    println!("  ─────────────────────────────────");
    println!();

    let mut total_balance = Amount::ZERO;
    let mut wallet_ids = Vec::new();

    for row in &wallet_rows {
        wallet_ids.push(row.id);
    }

    for row in wallet_rows {
        let acct_idx = row.account_idx;
        let wallet_id = row.id;
        let wallet = wm.load_wallet_from_row(row).await.expect("load wallet");

        if let Err(e) = wallet.sync().await {
            eprintln!("  warning: sync failed for account {acct_idx}: {e}");
        }

        let balance = wallet.balance().await.total();
        total_balance += balance;
        let utxos = wallet.list_unspent().await;

        // Count federation versions.
        let versions = db::list_federation_versions_for_wallet(&pool, wallet_id)
            .await
            .unwrap_or_default();

        println!(
            "  Account {:>3} (idx {acct_idx}):  {}  │  {} UTXOs  │  {} federation version(s)",
            wallet_ids.iter().position(|&id| id == wallet_id).unwrap_or(0),
            balance,
            utxos.len(),
            versions.len(),
        );
    }

    println!();
    println!("  Total balance: {total_balance}");

    // =====================================================================
    // Federation version status
    // =====================================================================

    println!();
    println!("  Federation Version Status");
    println!("  ─────────────────────────");
    println!();

    let mut all_pass = true;

    for &wallet_id in &wallet_ids {
        let versions = db::list_federation_versions_for_wallet(&pool, wallet_id)
            .await
            .unwrap_or_default();

        if versions.is_empty() {
            continue;
        }

        let max_v = versions.iter().map(|v| v.version_index).max().unwrap_or(0);

        for v in &versions {
            let is_current = v.version_index == max_v;
            let icon = if is_current {
                "●"
            } else if v.migration_status == "complete" {
                "✓"
            } else {
                all_pass = false;
                "✗"
            };

            let label = if is_current {
                "current".to_string()
            } else {
                v.migration_status.clone()
            };

            println!(
                "  {icon}  Wallet {:.8}…  v{}  │  {}-of-{}  │  {label}",
                wallet_id,
                v.version_index,
                v.threshold,
                v.signer_count,
            );
        }
    }

    // =====================================================================
    // Summary
    // =====================================================================

    println!();
    if all_pass {
        println!("  ════════════════════════════════════════");
        println!("  ✓ All old federation versions are 'complete'");
        println!("  ✓ Migration verification PASSED");
        println!("  ════════════════════════════════════════");
    } else {
        println!("  ════════════════════════════════════════");
        println!("  ✗ Some old federation versions are NOT 'complete'");
        println!("  ✗ Migration verification FAILED");
        println!("  ════════════════════════════════════════");
        std::process::exit(1);
    }
}
