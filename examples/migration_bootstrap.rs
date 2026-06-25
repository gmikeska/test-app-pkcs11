//! Migration bootstrap — set up test accounts for federation migration.
//!
//! Creates users and wallets in the database, derives receive addresses,
//! and prints funding commands. After funding and mining, re-run with
//! `--sync` to verify balances before running `federation_migration`.
//!
//! ## Workflow
//!
//! ```text
//! # 1. Reset dev state
//! ./reset-dev.sh --yes
//!
//! # 2. Create accounts and get funding addresses
//! cargo run --example migration_bootstrap
//!
//! # 3. Fund accounts using the printed commands (paytoaddress.sh etc.)
//! # 4. Mine a block
//!
//! # 5. Sync and verify balances
//! cargo run --example migration_bootstrap -- --sync
//!
//! # 6. Run the migration
//! cargo run --example federation_migration -- --config examples/federation_change.example.toml
//!
//! # 7. Verify post-migration
//! cargo run --example migration_verify
//! ```

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::too_many_lines
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
// Test accounts
// =========================================================================

struct TestAccount {
    email: &'static str,
    fund_amounts: &'static [u64],
    description: &'static str,
}

const ACCOUNTS: &[TestAccount] = &[
    TestAccount {
        email: "fee-account@test.local",
        fund_amounts: &[50_000_000],
        description: "fee account (internal/house)",
    },
    TestAccount {
        email: "small-1@test.local",
        fund_amounts: &[100_000],
        description: "small account (below threshold)",
    },
    TestAccount {
        email: "small-2@test.local",
        fund_amounts: &[200_000],
        description: "small account (below threshold)",
    },
    TestAccount {
        email: "large-3@test.local",
        fund_amounts: &[40_000_000, 30_000_000, 30_000_000],
        description: "large account (3 UTXOs)",
    },
    TestAccount {
        email: "dust-4@test.local",
        fund_amounts: &[50_000],
        description: "dust-adjacent (below threshold)",
    },
];

// =========================================================================
// Main
// =========================================================================

#[tokio::main]
async fn main() {
    let env_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".env");
    let _ = dotenvy::from_path(&env_path);

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let sync_mode = std::env::args().any(|a| a == "--sync");

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

    if sync_mode {
        run_sync(&pool, &wm).await;
    } else {
        run_bootstrap(&pool, &wm).await;
    }
}

// =========================================================================
// Bootstrap mode: create accounts, print funding commands
// =========================================================================

async fn run_bootstrap(pool: &sqlx::PgPool, wm: &WalletManager) {
    println!("Migration Bootstrap");
    println!("====================");
    println!();

    // Check for existing wallets.
    let existing = db::list_all_wallets(pool).await.expect("list wallets");
    if !existing.is_empty() {
        eprintln!("  Database already has {} wallets.", existing.len());
        eprintln!("  Run ./reset-dev.sh --yes to start fresh, or use --sync to check balances.");
        std::process::exit(1);
    }

    // Create users and wallets.
    for acct in ACCOUNTS {
        db::upsert_user_if_absent(pool, acct.email, "test-hash")
            .await
            .expect("upsert user");
        let user = db::find_user_by_email(pool, acct.email)
            .await
            .expect("find user")
            .expect("user exists");
        let wallet_row = wm.ensure_wallet_for_user(user.id).await.expect("wallet");
        println!(
            "  Created account {} (idx {}) — {}",
            acct.email, wallet_row.account_idx, acct.description
        );
    }

    // Load wallets and derive addresses.
    let wallet_rows = db::list_all_wallets(pool).await.expect("list wallets");
    let mut wallets = Vec::new();
    for row in wallet_rows {
        let w = wm.load_wallet_from_row(row).await.expect("load wallet");
        wallets.push(w);
    }

    println!();
    println!("  ─────────────────────────────────────────────────");
    println!("  Funding Commands");
    println!("  ─────────────────────────────────────────────────");
    println!();

    for (i, wallet) in wallets.iter().enumerate() {
        let acct = &ACCOUNTS[i];
        let num_addrs = acct.fund_amounts.len() as u32;
        let addrs = wallet
            .reveal_addresses(num_addrs)
            .await
            .expect("reveal addresses");

        println!(
            "  # Account {} (idx {}) — {}",
            i,
            wallet.account_idx(),
            acct.description,
        );
        for (j, &amount_sat) in acct.fund_amounts.iter().enumerate() {
            let btc = Amount::from_sat(amount_sat).to_btc();
            println!("  paytoaddress.sh {} {btc}", addrs[j].address);
        }
        println!();
    }

    println!("  ─────────────────────────────────────────────────");
    println!("  Next steps:");
    println!("  1. Run the paytoaddress.sh commands above");
    println!("  2. Mine a block (mine.sh or wait for auto-mine)");
    println!("  3. Verify: cargo run --example migration_bootstrap -- --sync");
    println!("  4. Migrate: cargo run --example federation_migration -- \\");
    println!("       --config examples/federation_change.example.toml");
    println!("  ─────────────────────────────────────────────────");
}

// =========================================================================
// Sync mode: load wallets, sync, display balances
// =========================================================================

async fn run_sync(pool: &sqlx::PgPool, wm: &WalletManager) {
    println!("Migration Bootstrap — Sync & Verify");
    println!("====================================");
    println!();

    let wallet_rows = db::list_all_wallets(pool).await.expect("list wallets");
    if wallet_rows.is_empty() {
        eprintln!("  No wallets found. Run without --sync first to create accounts.");
        std::process::exit(1);
    }

    let mut all_ok = true;
    let mut total_balance = Amount::ZERO;

    for (i, row) in wallet_rows.into_iter().enumerate() {
        let acct_idx = row.account_idx;
        let wallet = wm.load_wallet_from_row(row).await.expect("load wallet");

        if let Err(e) = wallet.sync().await {
            eprintln!("  warning: sync failed for account {acct_idx}: {e}");
        }

        let balance = wallet.balance().await.total();
        total_balance += balance;

        let expected: Amount = if i < ACCOUNTS.len() {
            Amount::from_sat(ACCOUNTS[i].fund_amounts.iter().sum::<u64>())
        } else {
            Amount::ZERO
        };

        let utxos = wallet.list_unspent().await;
        let expected_utxos = if i < ACCOUNTS.len() {
            ACCOUNTS[i].fund_amounts.len()
        } else {
            0
        };

        let status = if balance == expected && utxos.len() == expected_utxos {
            "✓"
        } else if balance == Amount::ZERO {
            all_ok = false;
            "✗ NOT FUNDED"
        } else {
            all_ok = false;
            "⚠ MISMATCH"
        };

        let desc = if i < ACCOUNTS.len() {
            ACCOUNTS[i].description
        } else {
            "unknown"
        };

        println!(
            "  {status}  Account {i} (idx {acct_idx}): {} ({} UTXOs) — {desc}",
            balance,
            utxos.len(),
        );
    }

    println!();
    println!("  Total balance: {total_balance}");
    println!();

    if all_ok {
        println!("  ✓ All accounts funded correctly. Ready for migration.");
    } else {
        println!("  ✗ Some accounts are not correctly funded.");
        println!("    Fund them and mine a block, then re-run with --sync.");
    }
}
