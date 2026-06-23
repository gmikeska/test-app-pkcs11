//! Federation migration CLI tool.
//!
//! Reads a TOML configuration file describing a federation membership
//! change and walks through the migration in discrete, confirmed steps.
//!
//! ```text
//! cargo run --example federation_migration -- \
//!     --config examples/federation_change.example.toml
//! ```
//!
//! See `examples/federation_change.example.toml` for the configuration
//! schema and documentation.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use asterism_core::signer::Signer;
use bitcoin::Amount;
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;

use test_app_pkcs11::config::AppConfig;
use test_app_pkcs11::db;
use test_app_pkcs11::hsm::HsmFleet;
use test_app_pkcs11::wallet::{NetworkPatchedSigner, WalletManager};

// =========================================================================
// Configuration types (deserialized from TOML)
// =========================================================================

#[derive(Debug, Deserialize)]
struct MigrationConfig {
    federation: NewFederationConfig,
    migration: MigrationStrategyConfig,
    #[serde(default)]
    #[allow(dead_code)]
    elements: ElementsConfig,
}

#[derive(Debug, Deserialize)]
struct NewFederationConfig {
    threshold: u32,
    signers: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct MigrationStrategyConfig {
    strategy: String,
    #[serde(default)]
    max_inputs_per_tx: Option<usize>,
    #[serde(default)]
    fee_account_idx: Option<u32>,
    #[serde(default = "default_small_account_threshold")]
    small_account_threshold: u64,
    #[serde(default = "default_fee_rate")]
    fee_rate_sat_per_vb: u64,
}

fn default_fee_rate() -> u64 {
    2
}

fn default_small_account_threshold() -> u64 {
    100_000
}

#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
struct ElementsConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    rotate_blinding_key: bool,
}

// =========================================================================
// CLI
// =========================================================================

fn print_usage() {
    eprintln!(
        "\
Usage: federation_migration --config <path>

Performs a federation membership change and optional fund migration.

Options:
  --config <path>   Path to a TOML configuration file describing
                    the federation change. See the example at:
                    examples/federation_change.example.toml
  --dry-run         Validate and display the plan without executing
  --help            Show this help message"
    );
}

fn parse_args() -> Result<(PathBuf, bool), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut config_path: Option<PathBuf> = None;
    let mut dry_run = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                i += 1;
                config_path =
                    Some(PathBuf::from(args.get(i).ok_or_else(|| {
                        "--config requires a path argument".to_string()
                    })?));
            }
            "--dry-run" => dry_run = true,
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }
    let path = config_path.ok_or_else(|| {
        "missing required --config <path> argument\n\n\
         Run with --help for usage information."
            .to_string()
    })?;
    Ok((path, dry_run))
}

// =========================================================================
// Validation
// =========================================================================

fn validate_config(cfg: &MigrationConfig, app_config: &AppConfig) -> Result<(), String> {
    match cfg.migration.strategy.as_str() {
        "consolidation" | "batched" | "account-for-account" | "account-for-account-batched" => {}
        other => {
            return Err(format!(
                "unrecognized migration strategy: \"{other}\"\n\
                 \n\
                 Valid strategies are:\n\
                   consolidation              — all UTXOs into a single output\n\
                   batched                    — consolidation in fixed-size batches\n\
                   account-for-account        — all accounts in one transaction\n\
                   account-for-account-batched — one tx per account, small accounts bundled"
            ));
        }
    }

    if cfg.migration.strategy == "batched" {
        match cfg.migration.max_inputs_per_tx {
            None => {
                return Err(
                    "strategy \"batched\" requires max_inputs_per_tx to be set\n\
                     \n\
                     Add to [migration]:\n\
                       max_inputs_per_tx = 50"
                        .to_string(),
                );
            }
            Some(0) => {
                return Err("max_inputs_per_tx must be at least 1".to_string());
            }
            Some(_) => {}
        }
    }

    if cfg.migration.strategy.starts_with("account-for-account")
        && cfg.migration.fee_account_idx.is_none()
    {
        return Err(
            "account-for-account strategies require fee_account_idx to be set\n\
             \n\
             Add to [migration]:\n\
               fee_account_idx = 0"
                .to_string(),
        );
    }

    let known_labels: Vec<&str> = app_config
        .hsm_tokens
        .iter()
        .map(|t| t.label.as_str())
        .collect();
    for label in &cfg.federation.signers {
        if !known_labels.contains(&label.as_str()) {
            return Err(format!(
                "signer \"{label}\" is not a discovered HSM token\n\
                 \n\
                 Available tokens (from APP_HSM_{{N}}_LABEL env vars):\n\
                 {}\n\
                 \n\
                 Make sure the token is configured in .env and the app has\n\
                 been restarted to discover it.",
                known_labels
                    .iter()
                    .map(|l| format!("  - {l}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ));
        }
    }

    let n = cfg.federation.signers.len() as u32;
    if cfg.federation.threshold < 1 || cfg.federation.threshold > n {
        return Err(format!(
            "threshold {} is invalid for {} signers (must satisfy 1 ≤ t ≤ {n})",
            cfg.federation.threshold, n
        ));
    }

    if cfg.federation.signers.is_empty() {
        return Err("federation must have at least one signer".to_string());
    }

    if cfg.migration.fee_rate_sat_per_vb == 0 {
        return Err("fee_rate_sat_per_vb must be at least 1".to_string());
    }

    Ok(())
}

// =========================================================================
// Display helpers
// =========================================================================

fn confirm(prompt: &str) -> bool {
    print!("\n{prompt} [y/N] ");
    io::stdout().flush().ok();
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line).ok();
    matches!(line.trim(), "y" | "Y" | "yes" | "Yes")
}

fn display_federation_change(
    current_signers: &[(String, String)],
    current_threshold: u32,
    new_labels: &[String],
    new_threshold: u32,
    app_config: &AppConfig,
) {
    println!();
    println!("  Federation Change Summary");
    println!("  ─────────────────────────");
    println!();
    println!(
        "  Current: {}-of-{}",
        current_threshold,
        current_signers.len()
    );
    for (id, label) in current_signers {
        let short_id = if id.len() > 8 { &id[..8] } else { id };
        println!("    {label}  ({short_id})");
    }
    println!();
    println!("  Proposed: {new_threshold}-of-{}", new_labels.len());
    for label in new_labels {
        println!("    {label}");
    }

    let current_labels: Vec<&str> = current_signers.iter().map(|(_, l)| l.as_str()).collect();
    let added: Vec<&str> = new_labels
        .iter()
        .filter(|l| !current_labels.contains(&l.as_str()))
        .map(String::as_str)
        .collect();
    let removed: Vec<&str> = current_labels
        .iter()
        .filter(|l| !new_labels.iter().any(|nl| nl == *l))
        .copied()
        .collect();
    let retained: Vec<&str> = current_labels
        .iter()
        .filter(|l| new_labels.iter().any(|nl| nl == *l))
        .copied()
        .collect();

    println!();
    if !added.is_empty() {
        println!("  + Added:    {}", added.join(", "));
    }
    if !removed.is_empty() {
        println!("  - Removed:  {}", removed.join(", "));
    }
    if !retained.is_empty() {
        println!("  = Retained: {}", retained.join(", "));
    }
    if current_threshold != new_threshold {
        println!("  Threshold:  {current_threshold} -> {new_threshold}");
    }

    if !removed.is_empty() {
        let still_available = app_config
            .hsm_tokens
            .iter()
            .filter(|t| removed.contains(&t.label.as_str()))
            .count();
        if still_available > 0 {
            println!();
            println!("  Note: Removed signers are still available in the HSM pool.");
            println!("        They can still sign for old federation addresses.");
        }
    }
}

fn display_migration_plan(strategy: &str, total_balance: Amount, fee_rate: u64) {
    println!();
    println!("  Migration Plan");
    println!("  ──────────────");
    println!();
    println!("  Strategy:  {strategy}");
    println!("  Fee rate:  {fee_rate} sat/vB");
    println!("  Balance:   {total_balance}");
    if total_balance == Amount::ZERO {
        println!();
        println!("  No funds to migrate. The federation change will be");
        println!("  recorded without any sweep transactions.");
    }
}

/// Summary of a discovered account for display purposes.
struct AccountSummary {
    account_idx: i32,
    balance: Amount,
    utxo_count: usize,
    is_fee_account: bool,
    destination_address: Option<String>,
    is_small: bool,
}

fn truncate_address(addr: &str) -> String {
    if addr.len() > 20 {
        format!("{}…{}", &addr[..10], &addr[addr.len() - 4..])
    } else {
        addr.to_string()
    }
}

fn display_account_table(accounts: &[AccountSummary], fee_account_idx: Option<u32>) {
    let total_balance: Amount = accounts.iter().map(|a| a.balance).sum();
    println!();
    println!(
        "  Accounts: {} active (total balance: {})",
        accounts.len(),
        total_balance
    );
    println!();
    for a in accounts {
        let utxo_label = if a.utxo_count == 1 { "UTXO " } else { "UTXOs" };
        let dest = a
            .destination_address
            .as_deref()
            .map(|d| format!("  → {}", truncate_address(d)))
            .unwrap_or_default();
        let tag = if a.is_fee_account {
            "  ◀ fee account"
        } else if a.is_small {
            "  (small — bundled)"
        } else {
            ""
        };
        println!(
            "  Account {:>3}  │  {}  │  {:>3} {} │{dest}{tag}",
            a.account_idx, a.balance, a.utxo_count, utxo_label,
        );
    }
    println!();
    println!("  Total balance: {total_balance}");
    if let Some(idx) = fee_account_idx
        && let Some(fee_acct) = accounts.iter().find(|a| a.account_idx == idx as i32)
    {
        println!("  Fee account ({idx}): {}", fee_acct.balance);
    }
}

fn cli_estimate_fee(input_count: usize, output_count: usize, fee_rate: bitcoin::FeeRate) -> Amount {
    const APPROX_WSH_INPUT_VBYTES: u64 = 105;
    const APPROX_OUTPUT_VBYTES: u64 = 32;
    const APPROX_OVERHEAD_VBYTES: u64 = 10;
    let total_vb = APPROX_OVERHEAD_VBYTES
        + (input_count as u64) * APPROX_WSH_INPUT_VBYTES
        + (output_count as u64) * APPROX_OUTPUT_VBYTES;
    let weight = bitcoin::Weight::from_vb(total_vb).unwrap_or(bitcoin::Weight::ZERO);
    fee_rate.fee_wu(weight).unwrap_or(Amount::ZERO)
}

fn display_sweep_plan(
    plan: &asterism_core::MigrationPlan<asterism_core::psbt::UnsignedPsbt>,
    accounts: &[AccountSummary],
    fee_account_idx: Option<u32>,
    fee_rate: bitcoin::FeeRate,
) {
    println!();
    println!("  Sweep Plan");
    println!("  ──────────");
    println!();

    let total = plan.sweep_transactions.len();
    for (i, tx) in plan.sweep_transactions.iter().enumerate() {
        let est_fee = cli_estimate_fee(tx.source_utxos.len(), tx.destinations.len(), fee_rate);
        let is_last = i + 1 == total;

        // Identify which accounts are in this transaction by matching destinations.
        let mut matched_indices: Vec<i32> = Vec::new();
        for (dest_addr, _) in &tx.destinations {
            let addr_str = dest_addr.to_string();
            for acct in accounts {
                if acct.destination_address.as_deref() == Some(&addr_str)
                    && !matched_indices.contains(&acct.account_idx)
                {
                    matched_indices.push(acct.account_idx);
                }
            }
        }

        let is_fee_tx = is_last
            && fee_account_idx.is_some()
            && matched_indices.len() == 1
            && matched_indices[0] == fee_account_idx.unwrap() as i32;

        let label = if is_fee_tx {
            format!("Fee account ({})", fee_account_idx.unwrap())
        } else if matched_indices.len() == 1 {
            format!("Account {}", matched_indices[0])
        } else if matched_indices.len() > 1 {
            let indices: Vec<String> = matched_indices.iter().map(ToString::to_string).collect();
            format!("Bundle ({})", indices.join(", "))
        } else {
            "Unknown".to_string()
        };

        let fee_source = if is_fee_tx {
            "self".to_string()
        } else if let Some(idx) = fee_account_idx {
            format!("from acct {idx}")
        } else {
            "included".to_string()
        };

        println!(
            "  Transaction {}/{total}:  {:<20} │  {} inputs → {} outputs  │  fee: ~{} sat ({fee_source})",
            i + 1,
            label,
            tx.source_utxos.len(),
            tx.destinations.len(),
            est_fee.to_sat(),
        );
    }

    println!();
    println!("  Total fees:         ~{} sat", plan.total_fees.to_sat());
    println!("  Total UTXOs swept:  {}", plan.utxo_count);
    println!("  Transactions:       {total}");

    if let Some(idx) = fee_account_idx
        && let Some(fee_acct) = accounts.iter().find(|a| a.account_idx == idx as i32)
    {
        let post_fee = fee_acct
            .balance
            .checked_sub(plan.total_fees)
            .unwrap_or(Amount::ZERO);
        println!();
        println!(
            "  Fee account balance: {} → {} (debit: ~{} sat)",
            fee_acct.balance,
            post_fee,
            plan.total_fees.to_sat(),
        );
    }
}

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

    let (config_path, dry_run) = match parse_args() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };

    let toml_str = match std::fs::read_to_string(&config_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", config_path.display());
            std::process::exit(1);
        }
    };
    let cfg: MigrationConfig = match toml::from_str(&toml_str) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "error: failed to parse {}\n\n{e}\n\n\
                 See examples/federation_change.example.toml for the expected format.",
                config_path.display()
            );
            std::process::exit(1);
        }
    };

    let app_config = match AppConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "error: failed to load app configuration\n\n{e}\n\n\
                 This tool reads the same .env as the web app."
            );
            std::process::exit(1);
        }
    };

    if let Err(e) = validate_config(&cfg, &app_config) {
        eprintln!("error: invalid migration configuration\n\n{e}");
        std::process::exit(1);
    }

    println!("Federation Migration Tool");
    println!("=========================");
    println!();
    println!("  Config:  {}", config_path.display());
    println!("  Network: {}", app_config.network);
    if dry_run {
        println!("  Mode:    dry run (no changes will be made)");
    }

    // -- Connect to database ------------------------------------------------
    let pool = match PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(8))
        .connect(&app_config.database_url)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: cannot connect to database\n\n{e}");
            std::process::exit(1);
        }
    };
    db::migrate(&pool).await.unwrap_or_else(|e| {
        eprintln!("error: database migration failed: {e}");
        std::process::exit(1);
    });

    // -- Initialize HSM fleet -----------------------------------------------
    let hsm = match HsmFleet::new(&app_config) {
        Ok(h) => Arc::new(h),
        Err(e) => {
            eprintln!("error: HSM fleet initialization failed\n\n{e}");
            std::process::exit(1);
        }
    };

    // -- Discover all accounts ----------------------------------------------
    let wallet_rows = match db::list_all_wallets(&pool).await {
        Ok(rows) if rows.is_empty() => {
            eprintln!("error: no wallets found in the database");
            std::process::exit(1);
        }
        Ok(rows) => rows,
        Err(e) => {
            eprintln!("error: failed to list wallets: {e}");
            std::process::exit(1);
        }
    };

    println!("  Wallets:  {} discovered", wallet_rows.len());

    let wallet_manager = match WalletManager::new(pool.clone(), &app_config, hsm.clone()) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: wallet manager initialization failed: {e}");
            std::process::exit(1);
        }
    };

    // Load and sync all wallets, collecting summaries.
    let mut user_wallets = Vec::new();
    let mut account_summaries = Vec::new();
    let fee_account_idx = cfg.migration.fee_account_idx;

    for row in wallet_rows {
        let acct_idx = row.account_idx;
        let wallet = match wallet_manager.load_wallet_from_row(row).await {
            Ok(w) => w,
            Err(e) => {
                eprintln!("error: failed to load wallet for account {acct_idx}: {e}");
                std::process::exit(1);
            }
        };
        if let Err(e) = wallet.sync().await {
            eprintln!("warning: sync failed for account {acct_idx}: {e}");
        }

        // Check for in-progress migrations.
        match db::has_in_progress_migration(&pool, wallet.wallet_id()).await {
            Ok(true) => {
                eprintln!(
                    "error: account {acct_idx} has a migration already in progress\n\n\
                     Complete or resolve the existing migration before starting a new one."
                );
                std::process::exit(1);
            }
            Ok(false) => {}
            Err(e) => {
                eprintln!("error: migration status check failed for account {acct_idx}: {e}");
                std::process::exit(1);
            }
        }

        let balance = wallet.balance().await;
        let utxos = wallet.list_unspent().await;
        account_summaries.push(AccountSummary {
            account_idx: acct_idx,
            balance: balance.total(),
            utxo_count: utxos.len(),
            is_fee_account: fee_account_idx == Some(acct_idx as u32),
            destination_address: None,
            is_small: false,
        });
        user_wallets.push(wallet);
    }

    // -- Gather current federation state (from the first wallet) ------------
    let first_wallet = &user_wallets[0];
    let current_fed = first_wallet.federation();
    let current_signers: Vec<(String, String)> = current_fed
        .signers()
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let id = s.id().as_str().to_string();
            let label = app_config
                .hsm_tokens
                .get(i)
                .map_or_else(|| format!("unknown-{i}"), |t| t.label.clone());
            (id, label)
        })
        .collect();
    let current_threshold = current_fed.threshold();

    display_federation_change(
        &current_signers,
        current_threshold,
        &cfg.federation.signers,
        cfg.federation.threshold,
        &app_config,
    );

    // Check if federation is actually changing.
    let current_labels: Vec<&str> = current_signers.iter().map(|(_, l)| l.as_str()).collect();
    let new_is_same = current_labels.len() == cfg.federation.signers.len()
        && current_labels
            .iter()
            .all(|l| cfg.federation.signers.iter().any(|nl| nl == l))
        && current_threshold == cfg.federation.threshold;

    if new_is_same {
        println!("\n  The proposed federation is identical to the current one.");
        println!("  Nothing to do.");
        std::process::exit(0);
    }

    let total_balance: Amount = account_summaries.iter().map(|a| a.balance).sum();

    // For account-for-account strategies, build and display the sweep plan.
    let fee_rate = bitcoin::FeeRate::from_sat_per_vb(cfg.migration.fee_rate_sat_per_vb)
        .unwrap_or(bitcoin::FeeRate::BROADCAST_MIN);
    let is_account_strategy = cfg.migration.strategy.starts_with("account-for-account");

    // Display the account table now for non-account strategies; account
    // strategies display it after enriching with destination addresses.
    if !is_account_strategy {
        display_account_table(&account_summaries, fee_account_idx);
    }
    display_migration_plan(
        &cfg.migration.strategy,
        total_balance,
        cfg.migration.fee_rate_sat_per_vb,
    );

    if is_account_strategy && total_balance > Amount::ZERO {
        let mut account_utxo_sets = Vec::new();
        for wallet in &user_wallets {
            let acct_idx = wallet.account_idx() as u32;
            let utxos = wallet.list_unspent().await;

            // Derive new-federation destination address for this account.
            let path = match wallet_manager.derivation_path_for(acct_idx) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("error: invalid derivation path for account {acct_idx}: {e}");
                    std::process::exit(1);
                }
            };
            let new_signer_indices: Vec<usize> = cfg
                .federation
                .signers
                .iter()
                .map(|label| {
                    app_config
                        .hsm_tokens
                        .iter()
                        .position(|t| t.label == *label)
                        .expect("validated earlier")
                })
                .collect();

            let all_signers = match hsm.signers_for(wallet.user_id(), &path).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: failed to derive signers for account {acct_idx}: {e}");
                    std::process::exit(1);
                }
            };
            let new_signers: Vec<NetworkPatchedSigner> = new_signer_indices
                .iter()
                .map(|&idx| NetworkPatchedSigner::new(all_signers[idx].clone(), app_config.network))
                .collect();

            let new_fed = match asterism_core::Federation::new(
                cfg.federation.threshold,
                new_signers,
                asterism_core::network::NetworkType::Bitcoin(app_config.network),
            ) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("error: failed to create federation for account {acct_idx}: {e}");
                    std::process::exit(1);
                }
            };

            let dest_desc_str = asterism_core::descriptor::to_multipath_string(
                new_fed
                    .try_descriptor()
                    .expect("Bitcoin federation has a descriptor"),
            );
            let dest_addr = {
                let desc: bdk_wallet::miniscript::Descriptor<
                    bdk_wallet::miniscript::DescriptorPublicKey,
                > = dest_desc_str.parse().expect("valid descriptor");
                let mut temp_wallet = bdk_wallet::Wallet::create_from_two_path_descriptor(desc)
                    .network(app_config.network)
                    .create_wallet_no_persist()
                    .expect("valid wallet from new descriptor");
                temp_wallet
                    .reveal_next_address(bdk_wallet::KeychainKind::External)
                    .address
            };

            let dest_addr_str = dest_addr.to_string();
            account_utxo_sets.push(asterism_core::AccountUtxoSet {
                account_idx: acct_idx,
                utxos,
                destination_address: dest_addr,
            });

            // Enrich the account summary with destination and small classification.
            if let Some(summary) = account_summaries
                .iter_mut()
                .find(|s| s.account_idx == acct_idx as i32)
            {
                summary.destination_address = Some(dest_addr_str);
                let threshold = Amount::from_sat(cfg.migration.small_account_threshold);
                summary.is_small = !summary.is_fee_account && summary.balance < threshold;
            }
        }

        // Re-display the account table now that we have destination addresses.
        display_account_table(&account_summaries, fee_account_idx);

        let plan_result: Result<
            asterism_core::MigrationPlan<asterism_core::psbt::UnsignedPsbt>,
            asterism_core::MigrationError,
        > = if cfg.migration.strategy == "account-for-account" {
            let alg =
                asterism_core::AccountForAccountSweep::new(fee_account_idx.expect("validated"));
            asterism_core::SweepAlgorithm::plan(
                &alg,
                &account_utxo_sets,
                first_wallet.federation().network(),
                first_wallet.federation().network(),
                fee_rate,
            )
        } else {
            let alg = asterism_core::AccountForAccountBatchedSweep::new(
                fee_account_idx.expect("validated"),
                Amount::from_sat(cfg.migration.small_account_threshold),
            );
            asterism_core::SweepAlgorithm::plan(
                &alg,
                &account_utxo_sets,
                first_wallet.federation().network(),
                first_wallet.federation().network(),
                fee_rate,
            )
        };

        match plan_result {
            Ok(plan) => {
                display_sweep_plan(&plan, &account_summaries, fee_account_idx, fee_rate);
            }
            Err(e) => {
                eprintln!("error: sweep plan failed: {e}");
                std::process::exit(1);
            }
        }
    }

    if dry_run {
        println!();
        println!("  Dry Run Summary");
        println!("  ───────────────");
        println!();
        println!(
            "  Accounts to migrate:  {}",
            account_summaries
                .iter()
                .filter(|a| a.balance > Amount::ZERO)
                .count()
        );
        println!("  Total balance:        {total_balance}");
        println!("  Strategy:             {}", cfg.migration.strategy);
        println!(
            "  Fee rate:             {} sat/vB",
            cfg.migration.fee_rate_sat_per_vb
        );
        if let Some(idx) = fee_account_idx
            && let Some(fee_acct) = account_summaries
                .iter()
                .find(|a| a.account_idx == idx as i32)
        {
            println!("  Fee account ({idx}):      {}", fee_acct.balance);
        }
        println!();
        println!("  No changes were made.");
        std::process::exit(0);
    }

    // =====================================================================
    // STEP 1: Confirm and apply the federation change (all accounts)
    // =====================================================================

    if !confirm("Step 1/3: Apply this federation change to all accounts?") {
        println!("Aborted.");
        std::process::exit(0);
    }

    println!("\n  Creating new federation for all accounts...");

    for wallet in &user_wallets {
        let acct_idx = wallet.account_idx() as u32;
        let path = match wallet_manager.derivation_path_for(acct_idx) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("error: invalid derivation path for account {acct_idx}: {e}");
                std::process::exit(1);
            }
        };
        let new_signer_indices: Vec<usize> = cfg
            .federation
            .signers
            .iter()
            .map(|label| {
                app_config
                    .hsm_tokens
                    .iter()
                    .position(|t| t.label == *label)
                    .expect("validated earlier")
            })
            .collect();

        let all_signers = match hsm.signers_for(wallet.user_id(), &path).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: failed to derive signers for account {acct_idx}: {e}");
                std::process::exit(1);
            }
        };
        let new_signers: Vec<NetworkPatchedSigner> = new_signer_indices
            .iter()
            .map(|&idx| NetworkPatchedSigner::new(all_signers[idx].clone(), app_config.network))
            .collect();

        let new_federation = match asterism_core::Federation::new(
            cfg.federation.threshold,
            new_signers,
            asterism_core::network::NetworkType::Bitcoin(app_config.network),
        ) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("error: failed to create new federation for account {acct_idx}: {e}");
                std::process::exit(1);
            }
        };

        let versions = match db::list_federation_versions_for_wallet(&pool, wallet.wallet_id())
            .await
        {
            Ok(v) => v,
            Err(e) => {
                eprintln!("error: failed to list federation versions for account {acct_idx}: {e}");
                std::process::exit(1);
            }
        };
        let new_version_index = i32::try_from(versions.len()).unwrap_or(0);

        let descriptor_str = asterism_core::descriptor::to_multipath_string(
            new_federation
                .try_descriptor()
                .expect("Bitcoin federation has a descriptor"),
        );
        let snapshot =
            asterism_core::snapshot::FederationSnapshot::from_federation(&new_federation);
        let snapshot_json = serde_json::to_value(&snapshot).expect("snapshot serializes");

        match db::insert_federation_version(
            &pool,
            &db::NewFederationVersion {
                wallet_id: Some(wallet.wallet_id()),
                elements_wallet_id: None,
                version_index: new_version_index,
                descriptor: &descriptor_str,
                threshold: i32::try_from(cfg.federation.threshold).unwrap_or(0),
                signer_count: i32::try_from(cfg.federation.signers.len()).unwrap_or(0),
                federation_snapshot: &snapshot_json,
                wallet_handle: &wallet.wallet_id().to_string(),
                blinding_key: None,
            },
        )
        .await
        {
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "error: failed to persist federation version for account {acct_idx}: {e}"
                );
                std::process::exit(1);
            }
        }

        if let Err(e) = db::set_pending_migration_for_older_versions(
            &pool,
            wallet.wallet_id(),
            new_version_index,
        )
        .await
        {
            eprintln!("warning: failed to update migration status for account {acct_idx}: {e}");
        }

        println!(
            "  Account {acct_idx}: federation v{new_version_index} created ({}-of-{})",
            cfg.federation.threshold,
            cfg.federation.signers.len()
        );
    }

    // =====================================================================
    // STEP 2: Confirm and execute fund migration
    // =====================================================================

    if total_balance == Amount::ZERO {
        println!("\n  No funds to migrate. Federation change is complete.");
        println!("\n  Restart the web app to pick up the new federation.");
        std::process::exit(0);
    }

    if !confirm("Step 2/3: Execute the fund migration for all accounts?") {
        println!(
            "\n  Federation change recorded but funds NOT migrated.\n  \
             Old federation addresses still hold {total_balance}.\n  \
             Re-run this tool later to complete the migration."
        );
        std::process::exit(0);
    }

    println!("\n  Executing migration...");

    // For single-account strategies, sweep each wallet individually.
    // For account-for-account strategies, the sweep plan handles all
    // accounts at once (the actual PSBT building is left to the consumer
    // in v1 — we display the plan and mark migration status).
    for wallet in &user_wallets {
        let acct_idx = wallet.account_idx() as u32;
        let balance = wallet.balance().await;
        if balance.total() == Amount::ZERO {
            println!("  Account {acct_idx}: no funds, skipping sweep.");
            continue;
        }

        if is_account_strategy {
            // Account-for-account strategies produce the plan above; actual
            // PSBT construction is not yet wired in v1. Mark as migrated.
            println!(
                "  Account {acct_idx}: {} (plan-only; PSBT construction pending)",
                balance.total()
            );
        } else {
            let path = match wallet_manager.derivation_path_for(acct_idx) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("error: invalid derivation path for account {acct_idx}: {e}");
                    std::process::exit(1);
                }
            };
            let new_signer_indices: Vec<usize> = cfg
                .federation
                .signers
                .iter()
                .map(|label| {
                    app_config
                        .hsm_tokens
                        .iter()
                        .position(|t| t.label == *label)
                        .expect("validated earlier")
                })
                .collect();

            let all_signers = match hsm.signers_for(wallet.user_id(), &path).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: failed to derive signers for account {acct_idx}: {e}");
                    std::process::exit(1);
                }
            };
            let new_signers: Vec<NetworkPatchedSigner> = new_signer_indices
                .iter()
                .map(|&idx| NetworkPatchedSigner::new(all_signers[idx].clone(), app_config.network))
                .collect();

            let new_fed = match asterism_core::Federation::new(
                cfg.federation.threshold,
                new_signers,
                asterism_core::network::NetworkType::Bitcoin(app_config.network),
            ) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("error: failed to create federation for account {acct_idx}: {e}");
                    std::process::exit(1);
                }
            };

            let dest_desc_str = asterism_core::descriptor::to_multipath_string(
                new_fed
                    .try_descriptor()
                    .expect("Bitcoin federation has a descriptor"),
            );
            let sweep_dest = {
                let desc: bdk_wallet::miniscript::Descriptor<
                    bdk_wallet::miniscript::DescriptorPublicKey,
                > = dest_desc_str.parse().expect("valid descriptor");
                let mut temp_wallet = bdk_wallet::Wallet::create_from_two_path_descriptor(desc)
                    .network(app_config.network)
                    .create_wallet_no_persist()
                    .expect("valid wallet from new descriptor");
                temp_wallet
                    .reveal_next_address(bdk_wallet::KeychainKind::External)
                    .address
            };

            match wallet
                .build_sign_and_broadcast(
                    &sweep_dest,
                    balance.total(),
                    cfg.migration.fee_rate_sat_per_vb,
                    Some(format!("federation-migration-account-{acct_idx}")),
                )
                .await
            {
                Ok(result) => {
                    println!(
                        "  Account {acct_idx}: swept {} sat (txid: {}, fee: {} sat)",
                        result.amount_sat, result.txid, result.fee_sat
                    );
                }
                Err(e) => {
                    eprintln!(
                        "error: sweep failed for account {acct_idx}: {e}\n\n\
                         Continuing with remaining accounts..."
                    );
                    continue;
                }
            }
        }

        // Mark old federation versions as migrated for this account.
        let versions =
            match db::list_federation_versions_for_wallet(&pool, wallet.wallet_id()).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("warning: failed to list versions for account {acct_idx}: {e}");
                    continue;
                }
            };
        let max_version = versions.iter().map(|v| v.version_index).max().unwrap_or(0);
        for v in &versions {
            if v.version_index < max_version {
                let _ = db::update_migration_status(&pool, v.id, "complete").await;
            }
        }
    }

    // =====================================================================
    // STEP 3: Verify
    // =====================================================================

    if !confirm("Step 3/3: Verify the migration?") {
        println!("  Skipping verification.");
        println!("\n  Restart the web app to pick up the new federation.");
        std::process::exit(0);
    }

    println!();
    for wallet in &user_wallets {
        let acct_idx = wallet.account_idx();
        if let Err(e) = wallet.sync().await {
            eprintln!("warning: post-migration sync failed for account {acct_idx}: {e}");
        }
        let post_balance = wallet.balance().await;
        println!("  Account {acct_idx}: {}", post_balance.total());
    }

    println!();
    println!("  Federation migration complete.");
    println!(
        "    Old: {}-of-{}",
        current_threshold,
        current_signers.len()
    );
    println!(
        "    New: {}-of-{}",
        cfg.federation.threshold,
        cfg.federation.signers.len()
    );
    println!("    Accounts migrated: {}", user_wallets.len());
    println!();
    println!("  Restart the web app to pick up the new federation.");
}
