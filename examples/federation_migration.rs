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

// This is a daemon-wallet-based migration demo, slated for rework in the
// (out-of-scope) federation-migration phase; we scope away pedantic style noise
// here rather than churn soon-to-be-replaced code.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::items_after_statements,
    clippy::map_unwrap_or,
    clippy::single_match_else,
    clippy::manual_let_else,
    clippy::let_unit_value,
    clippy::needless_continue,
    clippy::collapsible_if,
    clippy::ignored_unit_patterns
)]

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use asterism_core::descriptor::KeyMode;
use asterism_core::signer::Signer;
use bitcoin::Amount;
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;

use test_app_pkcs11::config::AppConfig;
use test_app_pkcs11::db;
use test_app_pkcs11::elements_wallet::ElementsWalletManager;
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
Usage: federation_migration --config <path> [--elements]

Performs a federation membership change and optional fund migration.

Options:
  --config <path>   Path to a TOML configuration file describing
                    the federation change. See the example at:
                    examples/federation_change.example.toml
  --elements        Run the Elements/Liquid migration instead of Bitcoin
  --dry-run         Validate and display the plan without executing
  --sweep-only      Skip Step 1 (federation already recorded); sweep funds only
  --help            Show this help message"
    );
}

struct CliArgs {
    config_path: PathBuf,
    dry_run: bool,
    sweep_only: bool,
    elements: bool,
}

fn parse_args() -> Result<CliArgs, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut config_path: Option<PathBuf> = None;
    let mut dry_run = false;
    let mut sweep_only = false;
    let mut elements = false;
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
            "--sweep-only" => sweep_only = true,
            "--elements" => elements = true,
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
    Ok(CliArgs {
        config_path: path,
        dry_run,
        sweep_only,
        elements,
    })
}

// =========================================================================
// Validation
// =========================================================================

fn validate_config(cfg: &MigrationConfig, app_config: &AppConfig) -> Result<(), String> {
    match cfg.migration.strategy.as_str() {
        "account-for-account" | "account-for-account-batched" => {}
        other => {
            return Err(format!(
                "unrecognized migration strategy: \"{other}\"\n\
                 \n\
                 Valid strategies are:\n\
                   account-for-account        — all accounts in one transaction\n\
                   account-for-account-batched — one tx per account, small accounts bundled"
            ));
        }
    }

    if cfg.migration.fee_account_idx.is_none() {
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

/// Summary of a discovered account for display purposes (Bitcoin).
struct AccountSummary {
    account_idx: i32,
    balance: Amount,
    utxo_count: usize,
    is_fee_account: bool,
    destination_address: Option<String>,
    is_small: bool,
}

/// Summary of a discovered Elements account for display purposes.
struct ElementsAccountSummary {
    account_idx: i32,
    balance_btc: f64,
    utxo_count: usize,
    destination_address: Option<String>,
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
// Elements display helpers
// =========================================================================

fn display_elements_migration_plan(strategy: &str, total_balance_btc: f64, fee_rate: u64) {
    println!();
    println!("  Migration Plan");
    println!("  ──────────────");
    println!();
    println!("  Strategy:  {strategy}");
    println!("  Fee rate:  {fee_rate} sat/vB");
    println!("  Balance:   {total_balance_btc:.8} L-BTC");
    if total_balance_btc <= 0.0 {
        println!();
        println!("  No funds to migrate. The federation change will be");
        println!("  recorded without any sweep transactions.");
    }
}

fn display_elements_account_table(accounts: &[ElementsAccountSummary]) {
    let total_balance: f64 = accounts.iter().map(|a| a.balance_btc).sum();
    println!();
    println!(
        "  Accounts: {} active (total balance: {total_balance:.8} L-BTC)",
        accounts.len(),
    );
    println!();
    for a in accounts {
        let utxo_label = if a.utxo_count == 1 { "UTXO " } else { "UTXOs" };
        let dest = a
            .destination_address
            .as_deref()
            .map(|d| format!("  → {}", truncate_address(d)))
            .unwrap_or_default();
        println!(
            "  Account {:>3}  │  {:.8} L-BTC  │  {:>3} {} │{dest}",
            a.account_idx, a.balance_btc, a.utxo_count, utxo_label,
        );
    }
    println!();
    println!("  Total balance: {total_balance:.8} L-BTC");
}

// =========================================================================
// Elements migration
// =========================================================================

#[allow(clippy::too_many_lines)]
async fn run_elements_migration(
    cfg: &MigrationConfig,
    app_config: &AppConfig,
    pool: &sqlx::PgPool,
    hsm: &Arc<HsmFleet>,
    dry_run: bool,
    sweep_only: bool,
) {
    use std::str::FromStr;

    use asterism_elements::descriptor::{CtDescriptorBuilder, CtKeyMode, to_multipath_string};

    println!();
    println!("  Chain:   Elements/Liquid");
    println!("  Elements network: {}", app_config.elements_network);

    let elements_manager = ElementsWalletManager::new(pool.clone(), app_config, hsm.clone());

    let wallet_rows = match db::list_all_elements_wallets(pool).await {
        Ok(rows) if rows.is_empty() => {
            eprintln!("error: no Elements wallets found in the database");
            std::process::exit(1);
        }
        Ok(rows) => rows,
        Err(e) => {
            eprintln!("error: failed to list Elements wallets: {e}");
            std::process::exit(1);
        }
    };

    println!("  Wallets: {} discovered", wallet_rows.len());

    let mut user_wallets = Vec::new();

    for row in wallet_rows {
        let acct_idx = row.account_idx;

        match db::has_in_progress_elements_migration(pool, row.id).await {
            Ok(true) => {
                eprintln!(
                    "error: Elements account {acct_idx} has a migration already in progress\n\n\
                     Complete or resolve the existing migration before starting a new one."
                );
                std::process::exit(1);
            }
            Ok(false) => {}
            Err(e) => {
                eprintln!(
                    "error: migration status check failed for Elements account {acct_idx}: {e}"
                );
                std::process::exit(1);
            }
        }

        let wallet = match elements_manager.load_wallet_from_row(row).await {
            Ok(w) => w,
            Err(e) => {
                eprintln!("error: failed to load Elements wallet for account {acct_idx}: {e}");
                std::process::exit(1);
            }
        };
        user_wallets.push(wallet);
    }

    // -- Gather current federation state from the first wallet's latest version --
    let first_wallet = &user_wallets[0];
    let current_versions = match db::list_federation_versions_for_elements_wallet(
        pool,
        first_wallet.wallet_id(),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: failed to list federation versions: {e}");
            std::process::exit(1);
        }
    };

    let (current_threshold, current_signer_count) = current_versions
        .last()
        .map(|v| (v.threshold as u32, v.signer_count as usize))
        .unwrap_or((
            app_config.fed_threshold,
            app_config.fed_signer_indices.len(),
        ));

    let current_signers: Vec<(String, String)> = app_config
        .fed_signer_indices
        .iter()
        .take(current_signer_count)
        .filter_map(|&idx| app_config.hsm_tokens.get(idx))
        .map(|t| (t.label.clone(), t.label.clone()))
        .collect();

    display_federation_change(
        &current_signers,
        current_threshold,
        &cfg.federation.signers,
        cfg.federation.threshold,
        app_config,
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

    // -- Collect account summaries (balance + UTXO count) ----------------------
    let rpc = elements_manager.rpc().clone();
    let mut account_summaries: Vec<ElementsAccountSummary> = Vec::new();
    let mut total_balance_btc = 0.0_f64;

    for wallet in &user_wallets {
        let acct_idx = wallet.account_idx();
        let daemon_name = wallet.daemon_wallet_name().to_string();
        let balance = match wallet.balance().await {
            Ok(b) => b,
            Err(e) => {
                eprintln!("warning: failed to get balance for Elements account {acct_idx}: {e}");
                continue;
            }
        };
        let btc = balance.trusted + balance.untrusted_pending;
        total_balance_btc += btc;

        let utxo_count = {
            let rpc = rpc.clone();
            let wn = daemon_name;
            tokio::task::spawn_blocking(move || rpc.list_unspent(&wn))
                .await
                .expect("spawn_blocking join")
                .map(|u| u.len())
                .unwrap_or(0)
        };

        account_summaries.push(ElementsAccountSummary {
            account_idx: acct_idx,
            balance_btc: btc,
            utxo_count,
            destination_address: None,
        });
    }

    display_elements_migration_plan(
        &cfg.migration.strategy,
        total_balance_btc,
        cfg.migration.fee_rate_sat_per_vb,
    );

    display_elements_account_table(&account_summaries);

    if dry_run {
        println!();
        println!("  Dry Run Summary");
        println!("  ───────────────");
        println!();
        println!(
            "  Accounts to migrate:  {}",
            account_summaries
                .iter()
                .filter(|a| a.balance_btc > 0.0)
                .count()
        );
        println!("  Total balance:        {total_balance_btc:.8} L-BTC");
        println!("  Strategy:             {}", cfg.migration.strategy);
        println!(
            "  Fee rate:             {} sat/vB",
            cfg.migration.fee_rate_sat_per_vb
        );
        println!();
        println!("  No changes were made.");
        std::process::exit(0);
    }

    // =====================================================================
    // STEP 1: Record new federation for each Elements wallet
    // =====================================================================

    if sweep_only {
        println!("\n  --sweep-only: skipping Step 1 (federation change already recorded).");
    } else {
        if !confirm("Step 1/3: Apply federation change to all Elements accounts?") {
            println!("Aborted.");
            std::process::exit(0);
        }

        println!("\n  Creating new federation for all Elements accounts...");

        let rotate_blinding_key = cfg.elements.rotate_blinding_key;

        for wallet in &user_wallets {
            let acct_idx = wallet.account_idx() as u32;
            let path = match elements_manager.derivation_path_for(acct_idx) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!(
                        "error: invalid derivation path for Elements account {acct_idx}: {e}"
                    );
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
                    eprintln!(
                        "error: failed to derive signers for Elements account {acct_idx}: {e}"
                    );
                    std::process::exit(1);
                }
            };
            let patched: Vec<NetworkPatchedSigner> = new_signer_indices
                .iter()
                .map(|&idx| NetworkPatchedSigner::new(all_signers[idx].clone(), app_config.network))
                .collect();

            // Get existing MBK or derive a new one.
            let versions = match db::list_federation_versions_for_elements_wallet(
                pool,
                wallet.wallet_id(),
            )
            .await
            {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(
                        "error: failed to list federation versions for Elements account {acct_idx}: {e}"
                    );
                    std::process::exit(1);
                }
            };

            let mbk_hex = if rotate_blinding_key {
                let new_version = i32::try_from(versions.len()).unwrap_or(0);
                let key =
                    crate::derive_elements_mbk(wallet.user_id(), wallet.account_idx(), new_version);
                hex_encode_bytes(&key)
            } else {
                versions
                    .last()
                    .and_then(|v| v.blinding_key.clone())
                    .unwrap_or_else(|| {
                        hex_encode_bytes(&crate::derive_elements_mbk(
                            wallet.user_id(),
                            wallet.account_idx(),
                            0,
                        ))
                    })
            };

            let mbk_bytes = hex_decode_bytes(&mbk_hex);
            let mut builder = match CtDescriptorBuilder::new(cfg.federation.threshold, &mbk_bytes) {
                Ok(b) => b.key_mode(CtKeyMode::Ranged),
                Err(e) => {
                    eprintln!("error: CT descriptor builder failed for account {acct_idx}: {e}");
                    std::process::exit(1);
                }
            };
            for signer in &patched {
                if let Err(e) = builder.add_signer(signer) {
                    eprintln!("error: failed to add signer for account {acct_idx}: {e}");
                    std::process::exit(1);
                }
            }
            let ct_desc = match builder.build() {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: failed to build CT descriptor for account {acct_idx}: {e}");
                    std::process::exit(1);
                }
            };
            let multipath = to_multipath_string(&ct_desc);

            // Set up the new daemon wallet.
            let new_version_index = i32::try_from(versions.len()).unwrap_or(0);
            let daemon_wallet_name = format!(
                "asterism-elements-user-{}-v{new_version_index}",
                wallet.account_idx()
            );

            let rpc = elements_manager.rpc().clone();
            let wallet_name = daemon_wallet_name.clone();
            let inner_multipath = extract_inner_wsh(&multipath).unwrap_or_else(|| {
                eprintln!("error: could not extract inner wsh for account {acct_idx}");
                std::process::exit(1);
            });
            let inner_receive = inner_multipath.replace("/<0;1>/*", "/0/*");
            let inner_change = inner_multipath.replace("/<0;1>/*", "/1/*");
            let mbk_for_import = mbk_bytes;
            let ct_desc_for_import = ct_desc.clone();
            let network = elements_manager.network();

            if let Err(e) = tokio::task::spawn_blocking(move || -> Result<(), String> {
                use asterism_elements::elements_miniscript::slip77::MasterBlindingKey;
                use std::str::FromStr;

                type CtDesc = asterism_elements::elements_miniscript::confidential::Descriptor<
                    asterism_elements::elements_miniscript::descriptor::DescriptorPublicKey,
                >;

                rpc.ensure_wallet_loaded(&wallet_name)
                    .map_err(|e| e.to_string())?;

                for (desc, is_internal) in [(&inner_receive, false), (&inner_change, true)] {
                    let info = rpc.get_descriptor_info(desc).map_err(|e| e.to_string())?;
                    let desc_with_checksum = format!("{desc}#{}", info.checksum);
                    let results = rpc
                        .import_descriptors(
                            &wallet_name,
                            &[test_app_pkcs11::elements_rpc::ImportDescriptorRequest {
                                descriptor: desc_with_checksum,
                                active: true,
                                internal: is_internal,
                            }],
                        )
                        .map_err(|e| e.to_string())?;
                    for r in &results {
                        if let (false, Some(err)) = (r.success, &r.error) {
                            tracing::warn!(
                                code = err.code,
                                msg = %err.message,
                                internal = is_internal,
                                "import_descriptors warning"
                            );
                        }
                    }
                }

                let slip77_mbk = MasterBlindingKey::from(mbk_for_import);
                let secp =
                    asterism_elements::elements_miniscript::elements::secp256k1_zkp::Secp256k1::new(
                    );
                let multipath_str = ct_desc_for_import.to_string();
                let receive_str = multipath_str.replace("/<0;1>/*", "/0/*");
                let change_str = multipath_str.replace("/<0;1>/*", "/1/*");

                let descs: Vec<CtDesc> = [&receive_str, &change_str]
                    .iter()
                    .filter_map(|s| CtDesc::from_str(s).ok())
                    .collect();

                for desc in &descs {
                    for idx in 0..20u32 {
                        if let Ok(definite) = desc.at_derivation_index(idx) {
                            let Ok(addr) = definite.address(&secp, network.address_params()) else {
                                continue;
                            };
                            let spk = definite.descriptor.script_pubkey();
                            let bk = slip77_mbk.blinding_private_key(&spk);
                            let bk_hex = {
                                let bytes = bk.secret_bytes();
                                let mut s = String::with_capacity(64);
                                for b in &bytes {
                                    use std::fmt::Write;
                                    let _ = write!(s, "{b:02x}");
                                }
                                s
                            };
                            let _ =
                                rpc.import_blinding_key(&wallet_name, &addr.to_string(), &bk_hex);
                        }
                    }
                }

                Ok(())
            })
            .await
            .expect("spawn_blocking join")
            {
                eprintln!(
                    "error: failed to set up Elements daemon wallet for account {acct_idx}: {e}"
                );
                std::process::exit(1);
            }

            let snapshot = serde_json::json!({
                "descriptor": multipath,
                "daemon_wallet_name": daemon_wallet_name,
            });

            match db::insert_federation_version(
                pool,
                &db::NewFederationVersion {
                    wallet_id: None,
                    elements_wallet_id: Some(wallet.wallet_id()),
                    version_index: new_version_index,
                    descriptor: &multipath,
                    threshold: i32::try_from(cfg.federation.threshold).unwrap_or(0),
                    signer_count: i32::try_from(cfg.federation.signers.len()).unwrap_or(0),
                    federation_snapshot: &snapshot,
                    wallet_handle: &daemon_wallet_name,
                    blinding_key: Some(&mbk_hex),
                },
            )
            .await
            {
                Ok(_) => {}
                Err(e) => {
                    eprintln!(
                        "error: failed to persist federation version for Elements account {acct_idx}: {e}"
                    );
                    std::process::exit(1);
                }
            }

            if let Err(e) = db::set_pending_migration_for_older_elements_versions(
                pool,
                wallet.wallet_id(),
                new_version_index,
            )
            .await
            {
                eprintln!(
                    "warning: failed to update migration status for Elements account {acct_idx}: {e}"
                );
            }

            println!(
                "  Account {}: federation v{new_version_index} created ({}-of-{}, daemon: {daemon_wallet_name})",
                wallet.account_idx(),
                cfg.federation.threshold,
                cfg.federation.signers.len()
            );
        }
    } // end if !sweep_only

    // =====================================================================
    // STEP 2: Sweep funds from old daemon wallet to new
    // =====================================================================

    if total_balance_btc <= 0.0 {
        println!("\n  No funds to migrate. Federation change is complete.");
        println!("\n  Restart the web app to pick up the new federation.");
        std::process::exit(0);
    }

    if !confirm("Step 2/3: Execute the fund migration for all Elements accounts?") {
        println!(
            "\n  Federation change recorded but funds NOT migrated.\n  \
             Old federation addresses still hold {total_balance_btc:.8} L-BTC.\n  \
             Re-run this tool later to complete the migration."
        );
        std::process::exit(0);
    }

    println!("\n  Executing Elements migration...");

    // Collect all UTXOs and destination addresses per account.
    let fee_acct_idx_el = cfg.migration.fee_account_idx;
    struct ElementsMigrationData {
        wallet_idx: usize,
        acct_idx: i32,
        daemon_wallet: String,
        balance_btc: f64,
        utxos: Vec<test_app_pkcs11::elements_rpc::ElementsUtxo>,
        dest_address: String,
    }
    let mut migration_data: Vec<ElementsMigrationData> = Vec::new();

    for (wi, wallet) in user_wallets.iter().enumerate() {
        let acct_idx = wallet.account_idx();
        let balance = match wallet.balance().await {
            Ok(b) => b,
            Err(e) => {
                eprintln!("warning: failed to get balance for Elements account {acct_idx}: {e}");
                continue;
            }
        };
        let btc = balance.trusted + balance.untrusted_pending;
        if btc <= 0.0 {
            println!("  Account {acct_idx}: no funds, skipping sweep.");
            continue;
        }

        let daemon_name = wallet.daemon_wallet_name().to_string();
        let utxos = {
            let rpc = rpc.clone();
            let wn = daemon_name.clone();
            match tokio::task::spawn_blocking(move || rpc.list_unspent(&wn))
                .await
                .expect("spawn_blocking join")
            {
                Ok(u) => u,
                Err(e) => {
                    eprintln!("error: failed to list UTXOs for Elements account {acct_idx}: {e}");
                    std::process::exit(1);
                }
            }
        };

        // Get the new federation's receive address from the new daemon wallet.
        let versions = match db::list_federation_versions_for_elements_wallet(
            pool,
            wallet.wallet_id(),
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                eprintln!("warning: failed to list versions for Elements account {acct_idx}: {e}");
                continue;
            }
        };
        let latest = match versions.last() {
            Some(v) => v,
            None => {
                eprintln!("warning: no federation versions for Elements account {acct_idx}");
                continue;
            }
        };

        let dest_address = {
            type CtDesc = asterism_elements::elements_miniscript::confidential::Descriptor<
                asterism_elements::elements_miniscript::descriptor::DescriptorPublicKey,
            >;
            let receive_str = latest.descriptor.replace("/<0;1>/*", "/0/*");
            let ct_desc = match CtDesc::from_str(&receive_str) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: failed to parse descriptor for account {acct_idx}: {e}");
                    continue;
                }
            };
            let secp =
                asterism_elements::elements_miniscript::elements::secp256k1_zkp::Secp256k1::new();
            match ct_desc.at_derivation_index(0) {
                Ok(definite) => {
                    match definite.address(&secp, elements_manager.network().address_params()) {
                        Ok(addr) => addr.to_string(),
                        Err(e) => {
                            eprintln!(
                                "error: failed to derive address for account {acct_idx}: {e}"
                            );
                            continue;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error: failed to derive address for account {acct_idx}: {e}");
                    continue;
                }
            }
        };

        if let Some(summary) = account_summaries
            .iter_mut()
            .find(|s| s.account_idx == acct_idx)
        {
            summary.destination_address = Some(truncate_address(&dest_address));
        }

        migration_data.push(ElementsMigrationData {
            wallet_idx: wi,
            acct_idx,
            daemon_wallet: daemon_name,
            balance_btc: btc,
            utxos,
            dest_address,
        });
    }

    if migration_data.is_empty() {
        println!("  No funded accounts to migrate.");
    } else if fee_acct_idx_el.is_some() && migration_data.len() > 1 {
        // Fee-account-pays: build a single PSET with all inputs and outputs.
        let fee_idx = fee_acct_idx_el.unwrap() as i32;

        // Build PSET inputs and outputs.
        let mut pset_inputs = Vec::new();
        let mut daemon_wallets_involved = Vec::new();
        for data in &migration_data {
            for utxo in &data.utxos {
                pset_inputs.push(serde_json::json!({
                    "txid": utxo.txid,
                    "vout": utxo.vout
                }));
            }
            if !daemon_wallets_involved.contains(&data.daemon_wallet) {
                daemon_wallets_involved.push(data.daemon_wallet.clone());
            }
        }

        // Build outputs: customer accounts get exact balance, fee account
        // gets its balance (fee will be subtracted from it below).
        let mut pset_outputs = Vec::new();
        let mut fee_output_idx: Option<usize> = None;
        for data in &migration_data {
            if data.acct_idx == fee_idx {
                fee_output_idx = Some(pset_outputs.len());
            }
            pset_outputs.push(serde_json::json!({
                data.dest_address.clone(): data.balance_btc
            }));
        }

        let fee_out_idx = fee_output_idx.unwrap_or(0);

        // Create raw PSET with explicit inputs/outputs.
        let base_pset_b64 = {
            let rpc = rpc.clone();
            let inputs = pset_inputs.clone();
            let outputs = pset_outputs.clone();
            match tokio::task::spawn_blocking(move || rpc.create_psbt(&inputs, &outputs))
                .await
                .expect("spawn_blocking join")
            {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("error: createpsbt failed: {e}");
                    std::process::exit(1);
                }
            }
        };

        // Chain walletprocesspsbt (sign=false) through each daemon wallet
        // to populate witness_utxo, witness_script, bip32_derivation.
        let mut updated_pset_b64 = base_pset_b64;
        for wn in &daemon_wallets_involved {
            let rpc = rpc.clone();
            let wn = wn.clone();
            let wn_display = wn.clone();
            let pset = updated_pset_b64.clone();
            updated_pset_b64 =
                match tokio::task::spawn_blocking(move || rpc.wallet_update_psbt(&wn, &pset))
                    .await
                    .expect("spawn_blocking join")
                {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("error: walletprocesspsbt failed for {wn_display}: {e}");
                        std::process::exit(1);
                    }
                };
        }

        // Now we need to subtract the fee from the fee account's output.
        // Re-create with fee subtraction using the fee wallet.
        // Actually, `createpsbt` doesn't compute fees. Let's use
        // `walletcreatefundedpsbt` on the fee wallet instead, with explicit
        // inputs and subtractFeeFromOutputs targeting the fee output.
        let funded = {
            let rpc = rpc.clone();
            let inputs = pset_inputs;
            let outputs = pset_outputs;
            let fee_wallet = migration_data
                .iter()
                .find(|d| d.acct_idx == fee_idx)
                .map(|d| d.daemon_wallet.clone())
                .unwrap_or_default();
            #[allow(clippy::cast_precision_loss)]
            let fee_rate_btc_kb =
                (cfg.migration.fee_rate_sat_per_vb as f64) * 1000.0 / 100_000_000.0;
            let foi = fee_out_idx;
            match tokio::task::spawn_blocking(move || {
                rpc.wallet_create_funded_psbt_with_inputs(
                    &fee_wallet,
                    &inputs,
                    &outputs,
                    foi,
                    fee_rate_btc_kb,
                )
            })
            .await
            .expect("spawn_blocking join")
            {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("error: walletcreatefundedpsbt failed: {e}");
                    std::process::exit(1);
                }
            }
        };

        // Chain walletprocesspsbt (sign=false) through NON-fee daemon
        // wallets to add their witness data to the funded PSET.
        let mut final_pset_b64 = funded.psbt;
        for wn in &daemon_wallets_involved {
            let fee_wn = migration_data
                .iter()
                .find(|d| d.acct_idx == fee_idx)
                .map(|d| d.daemon_wallet.as_str())
                .unwrap_or("");
            if wn == fee_wn {
                continue; // Fee wallet already populated by walletcreatefundedpsbt.
            }
            let rpc = rpc.clone();
            let wn = wn.clone();
            let wn_display = wn.clone();
            let pset = final_pset_b64.clone();
            final_pset_b64 =
                match tokio::task::spawn_blocking(move || rpc.wallet_update_psbt(&wn, &pset))
                    .await
                    .expect("spawn_blocking join")
                {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("error: walletprocesspsbt failed for {wn_display}: {e}");
                        std::process::exit(1);
                    }
                };
        }

        // Parse, blind, sign, finalize, broadcast.
        let result = {
            let pset_b64 = final_pset_b64;
            let rpc = rpc.clone();
            let migration_data_ref = &migration_data;
            let user_wallets_ref = &user_wallets;

            use asterism_elements::elements_miniscript::slip77::MasterBlindingKey;
            use base64::Engine;
            use base64::engine::general_purpose::STANDARD as BASE64;
            use elements::encode::deserialize as consensus_deserialize;
            use elements::encode::serialize as consensus_serialize;
            use elements::pset::PartiallySignedTransaction as Pset;

            let pset_bytes = BASE64
                .decode(pset_b64.as_bytes())
                .expect("valid base64 from RPC");
            let pset: Pset = consensus_deserialize(&pset_bytes).expect("valid PSET from RPC");
            let unsigned =
                asterism_elements::UnsignedPset::new(pset).expect("PSET has no signatures yet");

            // Derive input secrets for blinding. Each input's blinding
            // key comes from the owning account.
            let mut inp_secrets = std::collections::HashMap::new();
            let mut input_offset = 0;
            for data in migration_data_ref {
                let wallet = &user_wallets_ref[data.wallet_idx];
                let mbk_bytes = derive_elements_mbk(wallet.user_id(), wallet.account_idx(), 0);
                let mbk = MasterBlindingKey::from(mbk_bytes);
                for (u_idx, _utxo) in data.utxos.iter().enumerate() {
                    let global_idx = input_offset + u_idx;
                    let input = &unsigned.as_pset().inputs()[global_idx];
                    let utxo_out = input.witness_utxo.as_ref();
                    if let Some(utxo_out) = utxo_out {
                        use elements::confidential;
                        if let (
                            confidential::Value::Explicit(value),
                            confidential::Asset::Explicit(asset),
                        ) = (utxo_out.value, utxo_out.asset)
                        {
                            inp_secrets.insert(
                                global_idx,
                                asterism_elements::explicit_txout_secrets(asset, value),
                            );
                        } else {
                            let slip77_key = asterism_elements::slip77_blinding_key(
                                &mbk,
                                &utxo_out.script_pubkey,
                            );
                            match asterism_elements::unblind_input(utxo_out, slip77_key) {
                                Ok(s) => {
                                    inp_secrets.insert(global_idx, s);
                                }
                                Err(e) => {
                                    eprintln!(
                                        "error: failed to unblind input {global_idx} for account {}: {e}",
                                        data.acct_idx
                                    );
                                    std::process::exit(1);
                                }
                            }
                        }
                    }
                }
                input_offset += data.utxos.len();
            }

            let blinded =
                asterism_elements::blind_pset(unsigned, &inp_secrets).expect("blinding succeeds");
            let mut pset = blinded.into_pset();

            // Sign with each account's signers.
            for data in migration_data_ref {
                let wallet = &user_wallets_ref[data.wallet_idx];
                // The wallet's signers are accessible through the UserElementsWallet.
                // We need to sign only this account's inputs — but Elements
                // signers (like Bitcoin) match by fingerprint in bip32_derivation.
                // Use the same masking approach: clear bip32_derivation from
                // non-owned inputs before signing, then restore.
                let start = {
                    let mut off = 0;
                    for d in migration_data_ref {
                        if d.acct_idx == data.acct_idx {
                            break;
                        }
                        off += d.utxos.len();
                    }
                    off
                };
                let end = start + data.utxos.len();

                // Save and clear non-owned bip32_derivation.
                let mut saved = Vec::new();
                for (i, inp) in pset.inputs_mut().iter_mut().enumerate() {
                    if i < start || i >= end {
                        saved.push((i, std::mem::take(&mut inp.bip32_derivation)));
                    }
                }

                wallet.sign_pset_with_signers(&mut pset);

                // Restore.
                for (i, derivation) in saved {
                    pset.inputs_mut()[i].bip32_derivation = derivation;
                }
            }

            // Finalize.
            asterism_elements::finalize_p2wsh_pset(&mut pset).expect("finalization succeeds");
            let tx = pset.extract_tx().expect("extraction succeeds");
            let raw_hex = {
                let bytes = consensus_serialize(&tx);
                let mut hex = String::with_capacity(bytes.len() * 2);
                for b in &bytes {
                    use std::fmt::Write;
                    let _ = write!(hex, "{b:02x}");
                }
                hex
            };

            let rpc_clone = rpc.clone();
            let hex_clone = raw_hex.clone();
            let txid =
                tokio::task::spawn_blocking(move || rpc_clone.send_raw_transaction(&hex_clone))
                    .await
                    .expect("spawn_blocking join")
                    .expect("broadcast succeeds");

            println!(
                "  Broadcast: txid {txid} ({} inputs, {} outputs)",
                migration_data_ref
                    .iter()
                    .map(|d| d.utxos.len())
                    .sum::<usize>(),
                migration_data_ref.len()
            );

            for data in migration_data_ref {
                #[allow(clippy::cast_possible_truncation)]
                let amount_sat = (data.balance_btc * 100_000_000.0).round() as i64;
                println!(
                    "    Account {}: {amount_sat} sat → {}",
                    data.acct_idx,
                    truncate_address(&data.dest_address)
                );
            }

            #[allow(clippy::cast_possible_truncation)]
            let fee_sat = (funded.fee * 100_000_000.0).round() as i64;
            if let Some(fee_data) = migration_data_ref.iter().find(|d| d.acct_idx == fee_idx) {
                println!(
                    "    Fee: {fee_sat} sat (paid by account {})",
                    fee_data.acct_idx
                );
            }
        };

        let _ = result;
    } else {
        // No fee account or single account — fall back to per-account sweep.
        for data in &migration_data {
            let wallet = &user_wallets[data.wallet_idx];
            match wallet
                .sweep_to(
                    &data.dest_address,
                    cfg.migration.fee_rate_sat_per_vb,
                    Some(format!(
                        "federation-migration-elements-account-{}",
                        data.acct_idx
                    )),
                )
                .await
            {
                Ok(result) => {
                    println!(
                        "  Account {}: swept {} sat (txid: {}, fee: {} sat)",
                        data.acct_idx, result.amount_sat, result.txid, result.fee_sat
                    );
                }
                Err(e) => {
                    eprintln!(
                        "error: sweep failed for Elements account {}: {e}\n\
                         Continuing with remaining accounts...",
                        data.acct_idx
                    );
                    continue;
                }
            }
        }
    }

    // Mark old federation versions as migrated for all accounts.
    for data in &migration_data {
        let wallet = &user_wallets[data.wallet_idx];
        let versions = match db::list_federation_versions_for_elements_wallet(
            pool,
            wallet.wallet_id(),
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "warning: failed to list versions for Elements account {}: {e}",
                    data.acct_idx
                );
                continue;
            }
        };
        let max_version = versions.iter().map(|v| v.version_index).max().unwrap_or(0);
        for v in &versions {
            if v.version_index < max_version {
                let _ = db::update_migration_status(pool, v.id, "complete").await;
            }
        }
    }

    // =====================================================================
    // STEP 3: Verify
    // =====================================================================

    if !confirm("Step 3/3: Verify the Elements migration?") {
        println!("  Skipping verification.");
        println!("\n  Restart the web app to pick up the new federation.");
        std::process::exit(0);
    }

    println!();
    println!("  Post-Migration Balances (old daemon wallets)");
    println!("  ────────────────────────────────────────────");
    for wallet in &user_wallets {
        let acct_idx = wallet.account_idx();
        match wallet.balance().await {
            Ok(bal) => {
                let btc = bal.trusted + bal.untrusted_pending;
                let status = if btc <= 0.000_000_01 {
                    "✓ drained"
                } else {
                    "⚠ residual"
                };
                println!("  Account {acct_idx}: {btc:.8} L-BTC  {status}");
            }
            Err(e) => {
                eprintln!(
                    "warning: post-migration balance check failed for account {acct_idx}: {e}"
                );
            }
        }
    }

    // Query balances on the NEW daemon wallets.
    println!();
    println!("  New Federation Balances");
    println!("  ───────────────────────");
    for wallet in &user_wallets {
        let acct_idx = wallet.account_idx();
        let versions = match db::list_federation_versions_for_elements_wallet(
            pool,
            wallet.wallet_id(),
        )
        .await
        {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Some(latest) = versions.last() {
            let rpc = elements_manager.rpc().clone();
            let wn = latest.wallet_handle.clone();
            match tokio::task::spawn_blocking(move || rpc.get_balances(&wn))
                .await
                .expect("spawn_blocking join")
            {
                Ok(bal) => {
                    let btc = bal.trusted + bal.untrusted_pending;
                    println!(
                        "  Account {acct_idx}: {btc:.8} L-BTC  (daemon: {})",
                        latest.wallet_handle
                    );
                }
                Err(e) => {
                    eprintln!(
                        "warning: new wallet balance check failed for account {acct_idx}: {e}"
                    );
                }
            }
        }
    }

    println!();
    println!("  Elements federation migration complete.");
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

fn hex_encode_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn hex_decode_bytes(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let offset = i * 2;
        if offset + 2 <= s.len() {
            *byte = u8::from_str_radix(&s[offset..offset + 2], 16).unwrap_or(0);
        }
    }
    out
}

fn extract_inner_wsh(ct_desc: &str) -> Option<String> {
    let body = ct_desc.split_once('#').map_or(ct_desc, |(b, _)| b);
    let inner_start = body.find("elwsh(").or_else(|| body.find("wsh("))?;
    let inner = &body[inner_start..body.len() - 1];
    Some(inner.replace("elwsh(", "wsh("))
}

/// Derive a deterministic MBK. For version 0, matches the original derivation.
/// For version > 0, includes version salt for rotation.
fn derive_elements_mbk(user_id: uuid::Uuid, account_idx: i32, version: i32) -> [u8; 32] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    user_id.hash(&mut hasher);
    account_idx.hash(&mut hasher);
    if version > 0 {
        version.hash(&mut hasher);
        "asterism-elements-mbk-rotated".hash(&mut hasher);
    }
    let h1 = hasher.finish();
    let mut hasher2 = DefaultHasher::new();
    h1.hash(&mut hasher2);
    "asterism-elements-mbk-v1".hash(&mut hasher2);
    let h2 = hasher2.finish();

    let mut key = [0u8; 32];
    key[..8].copy_from_slice(&h1.to_le_bytes());
    key[8..16].copy_from_slice(&h2.to_le_bytes());
    key[16..24].copy_from_slice(&h1.to_be_bytes());
    key[24..32].copy_from_slice(&h2.to_be_bytes());
    key
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

    let cli = match parse_args() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };
    let dry_run = cli.dry_run;
    let sweep_only = cli.sweep_only;

    let toml_str = match std::fs::read_to_string(&cli.config_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", cli.config_path.display());
            std::process::exit(1);
        }
    };
    let cfg: MigrationConfig = match toml::from_str(&toml_str) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "error: failed to parse {}\n\n{e}\n\n\
                 See examples/federation_change.example.toml for the expected format.",
                cli.config_path.display()
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
    println!("  Config:  {}", cli.config_path.display());
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

    // -- Branch: Elements or Bitcoin -----------------------------------------
    if cli.elements {
        run_elements_migration(&cfg, &app_config, &pool, &hsm, dry_run, sweep_only).await;
        return;
    }

    // -- Discover all accounts (Bitcoin) -------------------------------------
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

    let fee_rate = bitcoin::FeeRate::from_sat_per_vb(cfg.migration.fee_rate_sat_per_vb)
        .unwrap_or(bitcoin::FeeRate::BROADCAST_MIN);

    display_migration_plan(
        &cfg.migration.strategy,
        total_balance,
        cfg.migration.fee_rate_sat_per_vb,
    );

    let mut migration_plan: Option<
        asterism_core::MigrationPlan<asterism_core::psbt::UnsignedPsbt>,
    > = None;
    let mut account_utxo_sets: Vec<asterism_core::AccountUtxoSet> = Vec::new();

    if total_balance > Amount::ZERO {
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

            let new_fed = match asterism_core::Federation::with_key_mode(
                cfg.federation.threshold,
                new_signers,
                asterism_core::network::NetworkType::Bitcoin(app_config.network),
                KeyMode::Ranged,
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
                migration_plan = Some(plan);
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

    // New federation descriptor strings per account — needed to build temp
    // wallets that can produce PSBT inputs for chained outputs.
    let mut new_fed_descriptors: std::collections::HashMap<u32, String> =
        std::collections::HashMap::new();

    if sweep_only {
        println!("\n  --sweep-only: skipping Step 1 (federation change already recorded).");
        for wallet in &user_wallets {
            let acct_idx = wallet.account_idx() as u32;
            if let Ok(versions) =
                db::list_federation_versions_for_wallet(&pool, wallet.wallet_id()).await
            {
                if let Some(latest) = versions.last() {
                    new_fed_descriptors.insert(acct_idx, latest.descriptor.clone());
                }
            }
        }
    } else {
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

            let new_federation = match asterism_core::Federation::with_key_mode(
                cfg.federation.threshold,
                new_signers,
                asterism_core::network::NetworkType::Bitcoin(app_config.network),
                KeyMode::Ranged,
            ) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("error: failed to create new federation for account {acct_idx}: {e}");
                    std::process::exit(1);
                }
            };

            let versions =
                match db::list_federation_versions_for_wallet(&pool, wallet.wallet_id()).await {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!(
                            "error: failed to list federation versions for account {acct_idx}: {e}"
                        );
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

            new_fed_descriptors.insert(acct_idx, descriptor_str.clone());

            println!(
                "  Account {acct_idx}: federation v{new_version_index} created ({}-of-{})",
                cfg.federation.threshold,
                cfg.federation.signers.len()
            );
        }
    } // end if !sweep_only

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

    // Build a map from account_idx → wallet index for quick lookup.
    let wallet_by_acct: std::collections::HashMap<u32, usize> = user_wallets
        .iter()
        .enumerate()
        .map(|(i, w)| (w.account_idx() as u32, i))
        .collect();

    // Build a map from OutPoint → (wallet_index, account_idx) for UTXO ownership.
    let mut utxo_owner: std::collections::HashMap<bitcoin::OutPoint, (usize, u32)> =
        std::collections::HashMap::new();
    for acct_set in &account_utxo_sets {
        if let Some(&wi) = wallet_by_acct.get(&acct_set.account_idx) {
            for utxo in &acct_set.utxos {
                utxo_owner.insert(utxo.outpoint, (wi, acct_set.account_idx));
            }
        }
    }

    let plan = migration_plan.expect("plan computed when total_balance > 0");
    let fee_acct_idx = fee_account_idx.expect("validated earlier");
    let fee_wallet_idx = *wallet_by_acct
        .get(&fee_acct_idx)
        .expect("fee account exists");

    // Chained fee-change data from the previous broadcast: outpoint +
    // pre-built PSBT input (because the UserWallet's version_wallets were
    // loaded before Step 1 and don't include the new federation).
    let mut fee_change_data: Option<(bitcoin::OutPoint, bitcoin::psbt::Input, bitcoin::Weight)> =
        None;

    for (tx_num, sweep_tx) in plan.sweep_transactions.iter().enumerate() {
        println!(
            "\n  Transaction {}/{}:",
            tx_num + 1,
            plan.sweep_transactions.len()
        );

        // Separate real outpoints from synthetic change placeholders (zeroed
        // txid). Synthetic entries represent the chained fee-account change
        // from the preceding broadcast.
        let has_synthetic_fee_input = {
            use bitcoin::hashes::Hash;
            sweep_tx
                .source_utxos
                .iter()
                .any(|op| op.txid == bitcoin::Txid::from_byte_array([0u8; 32]))
        };

        let real_utxos: Vec<&bitcoin::OutPoint> = sweep_tx
            .source_utxos
            .iter()
            .filter(|op| {
                use bitcoin::hashes::Hash;
                op.txid != bitcoin::Txid::from_byte_array([0u8; 32])
            })
            .collect();

        // Build the PSBT using the fee account's BDK wallet.
        let fee_wallet = &user_wallets[fee_wallet_idx];

        // Collect PSBT input data for ALL UTXOs via psbt_input_for_utxo(),
        // which searches across all federation version wallets. This is
        // necessary because the inner wallet may use the latest federation's
        // descriptor and won't find UTXOs locked to an older federation.
        let mut all_utxo_data: Vec<(
            bitcoin::OutPoint,
            bitcoin::psbt::Input,
            bitcoin::Weight,
            usize, // owning wallet index
        )> = Vec::new();

        // If a synthetic fee-change placeholder exists, resolve it with the
        // pre-built PSBT input from the previous broadcast.
        if has_synthetic_fee_input {
            if let Some((change_op, change_psbt_input, change_weight)) = fee_change_data.take() {
                all_utxo_data.push((change_op, change_psbt_input, change_weight, fee_wallet_idx));
            } else {
                eprintln!(
                    "error: transaction {} expects chained fee change but none available",
                    tx_num + 1
                );
                std::process::exit(1);
            }
        }

        for &outpoint in &real_utxos {
            if let Some(&(wi, _acct_idx)) = utxo_owner.get(outpoint) {
                let wallet = &user_wallets[wi];
                match wallet.psbt_input_for_utxo(*outpoint).await {
                    Ok((psbt_input, weight)) => {
                        all_utxo_data.push((*outpoint, psbt_input, weight, wi));
                    }
                    Err(e) => {
                        eprintln!(
                            "error: failed to build PSBT input for {outpoint}: {e}\n\
                             Aborting migration."
                        );
                        std::process::exit(1);
                    }
                }
            }
        }

        // Build the PSBT on the fee wallet.
        let psbt = {
            let mut inner = fee_wallet.inner_wallet().await;
            let fee_rate_obj = bitcoin::FeeRate::from_sat_per_vb(cfg.migration.fee_rate_sat_per_vb)
                .unwrap_or(bitcoin::FeeRate::BROADCAST_MIN);

            let mut builder = inner.build_tx();

            // Add all UTXOs as foreign inputs (they belong to the old
            // federation's descriptor, not the builder wallet's).
            for (outpoint, psbt_input, weight, _wi) in &all_utxo_data {
                if let Err(e) = builder.add_foreign_utxo(*outpoint, psbt_input.clone(), *weight) {
                    eprintln!("error: failed to add UTXO {outpoint}: {e}");
                    std::process::exit(1);
                }
            }

            // Only use manually selected UTXOs — don't let BDK pick extras.
            builder.manually_selected_only();

            // Add explicit outputs for each destination.
            // The fee account's destination gets drain_to (absorbs the fee).
            let fee_dest_idx = sweep_tx.destinations.iter().position(|(addr, _)| {
                account_utxo_sets
                    .iter()
                    .find(|a| a.account_idx == fee_acct_idx)
                    .is_some_and(|a| a.destination_address == *addr)
            });

            for (i, (addr, amount)) in sweep_tx.destinations.iter().enumerate() {
                if Some(i) == fee_dest_idx {
                    // Fee account output: use drain_to so it absorbs the mining fee.
                    builder.drain_to(addr.script_pubkey());
                } else {
                    // Customer output: exact amount, no fee deduction.
                    builder.add_recipient(addr.script_pubkey(), *amount);
                }
            }

            builder.fee_rate(fee_rate_obj);

            match builder.finish() {
                Ok(psbt) => psbt,
                Err(e) => {
                    eprintln!("error: PSBT construction failed for tx {}: {e}", tx_num + 1);
                    std::process::exit(1);
                }
            }
        };

        let mut psbt = psbt;

        // Determine input indices per wallet by matching each PSBT input's
        // previous_output against known outpoints. BDK applies BIP-69
        // ordering in finish(), so we cannot assume insertion order.
        let outpoint_to_wallet: std::collections::HashMap<bitcoin::OutPoint, usize> = all_utxo_data
            .iter()
            .map(|(op, _, _, wi)| (*op, *wi))
            .collect();

        let mut input_indices_by_wallet: std::collections::HashMap<usize, Vec<usize>> =
            std::collections::HashMap::new();

        for (i, input) in psbt.unsigned_tx.input.iter().enumerate() {
            if let Some(&wi) = outpoint_to_wallet.get(&input.previous_output) {
                input_indices_by_wallet.entry(wi).or_default().push(i);
            }
        }

        // Sign each account's inputs using its wallet (which has the
        // correct PKCS#11 signers registered for the old federation).
        for (wi, indices) in &input_indices_by_wallet {
            let wallet = &user_wallets[*wi];
            if let Err(e) = wallet.sign_migration_inputs(&mut psbt, indices).await {
                eprintln!(
                    "error: signing failed for account {}: {e}",
                    wallet.account_idx()
                );
                std::process::exit(1);
            }
        }

        // Finalize using miniscript's standalone finalizer (works across
        // descriptors without needing a single wallet).
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        if let Err(errors) = miniscript::psbt::PsbtExt::finalize_mut(&mut psbt, &secp) {
            eprintln!("error: PSBT finalization failed for tx {}:", tx_num + 1);
            for e in &errors {
                eprintln!("  input error: {e}");
            }
            std::process::exit(1);
        }

        // Extract and broadcast.
        let tx = match psbt.extract_tx() {
            Ok(tx) => tx,
            Err(e) => {
                eprintln!("error: failed to extract tx {}: {e}", tx_num + 1);
                std::process::exit(1);
            }
        };
        let txid = tx.compute_txid();
        let mut raw = Vec::new();
        bitcoin::consensus::Encodable::consensus_encode(&tx, &mut raw)
            .expect("consensus encode succeeds");

        let raw_clone = raw.clone();
        let rpc = fee_wallet.rpc().clone();
        match tokio::task::spawn_blocking(move || {
            bitcoincore_rpc::RpcApi::send_raw_transaction(&*rpc, &raw_clone[..])
        })
        .await
        {
            Ok(Ok(broadcast_txid)) => {
                // Report per-output amounts.
                let mut output_summary = Vec::new();
                for (addr, amount) in &sweep_tx.destinations {
                    let acct = account_utxo_sets
                        .iter()
                        .find(|a| a.destination_address == *addr);
                    if let Some(a) = acct {
                        output_summary.push(format!(
                            "account {}: {} sat",
                            a.account_idx,
                            amount.to_sat()
                        ));
                    }
                }
                println!(
                    "    Broadcast: txid {broadcast_txid}\n    Outputs: {}",
                    output_summary.join(", ")
                );
            }
            Ok(Err(e)) => {
                eprintln!("error: broadcast rejected for tx {}: {e}", tx_num + 1);
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("error: broadcast task failed for tx {}: {e}", tx_num + 1);
                std::process::exit(1);
            }
        }

        // Build PSBT input data for the fee account's change output so
        // the next transaction can spend it without a full wallet sync.
        // The UserWallet's version_wallets were loaded before Step 1 and
        // don't include the new federation, so we use a temp wallet built
        // from the stored descriptor instead.
        let fee_dest_script = account_utxo_sets
            .iter()
            .find(|a| a.account_idx == fee_acct_idx)
            .map(|a| a.destination_address.script_pubkey());
        if let Some(ref fee_script) = fee_dest_script {
            for (vout, output) in tx.output.iter().enumerate() {
                if output.script_pubkey == *fee_script {
                    let change_op = bitcoin::OutPoint {
                        txid,
                        vout: vout as u32,
                    };
                    // Build the PSBT input via a temp wallet with the new
                    // federation's descriptor.
                    if let Some(desc_str) = new_fed_descriptors.get(&fee_acct_idx) {
                        let desc: bdk_wallet::miniscript::Descriptor<
                            bdk_wallet::miniscript::DescriptorPublicKey,
                        > = desc_str.parse().expect("valid descriptor");
                        let mut temp_wallet =
                            bdk_wallet::Wallet::create_from_two_path_descriptor(desc)
                                .network(app_config.network)
                                .create_wallet_no_persist()
                                .expect("valid temp wallet");
                        // Reveal at least one address so the script index
                        // recognises index 0.
                        let _ = temp_wallet.reveal_next_address(bdk_wallet::KeychainKind::External);
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        temp_wallet.apply_unconfirmed_txs(vec![(tx.clone(), now)]);
                        if let Some(local) = temp_wallet.get_utxo(change_op) {
                            let satisfaction_weight = bitcoin::Weight::from_witness_data_size(260);
                            match temp_wallet.get_psbt_input(local, None, false) {
                                Ok(psbt_input) => {
                                    fee_change_data =
                                        Some((change_op, psbt_input, satisfaction_weight));
                                }
                                Err(e) => {
                                    eprintln!(
                                        "warning: could not build PSBT input for \
                                         fee change {change_op}: {e}"
                                    );
                                }
                            }
                        } else {
                            eprintln!(
                                "warning: fee change {change_op} not found in \
                                 temp wallet after insert"
                            );
                        }
                    }
                    break;
                }
            }
        }

        // Record the transaction for each involved account.
        let raw_hex = bitcoin::hex::DisplayHex::to_lower_hex_string(raw.as_slice());
        for (addr, amount) in &sweep_tx.destinations {
            let acct = account_utxo_sets
                .iter()
                .find(|a| a.destination_address == *addr);
            if let Some(a) = acct {
                if let Some(&wi) = wallet_by_acct.get(&a.account_idx) {
                    let wallet = &user_wallets[wi];
                    let _ = db::insert_transaction(
                        wallet.pool(),
                        &db::NewTransaction {
                            wallet_id: wallet.wallet_id(),
                            txid: &txid.to_string(),
                            recipient: &addr.to_string(),
                            amount_sat: i64::try_from(amount.to_sat()).unwrap_or(i64::MAX),
                            fee_sat: 0, // fee attributed to fee account only
                            raw_tx_hex: &raw_hex,
                            label: Some(&format!("federation-migration-account-{}", a.account_idx)),
                        },
                    )
                    .await;
                }
            }
        }
    }

    // Mark old federation versions as migrated for all accounts.
    for wallet in &user_wallets {
        let acct_idx = wallet.account_idx();
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
