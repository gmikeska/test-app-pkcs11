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
    clippy::ignored_unit_patterns,
    clippy::similar_names,
    clippy::too_many_lines
)]

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::Amount;
use emvault::core::descriptor::KeyMode;
use emvault::core::signer::Signer;
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
    is_fee_account: bool,
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
    plan: &emvault::core::MigrationPlan<emvault::core::psbt::UnsignedPsbt>,
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
        let est_fee = cli_estimate_fee(tx.source_utxos.len(), tx.outputs.len(), fee_rate);

        // Identify which accounts are in this transaction from the output markers.
        let mut matched_indices: Vec<i32> = Vec::new();
        for o in &tx.outputs {
            let idx = o.account_idx() as i32;
            if !matched_indices.contains(&idx) {
                matched_indices.push(idx);
            }
        }

        let is_fee_tx = tx.is_fee_final
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
            tx.outputs.len(),
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

fn display_elements_account_table(
    accounts: &[ElementsAccountSummary],
    fee_account_idx: Option<u32>,
) {
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
        let tag = if a.is_fee_account {
            "  ◀ fee account"
        } else {
            ""
        };
        println!(
            "  Account {:>3}  │  {:.8} L-BTC  │  {:>3} {} │{dest}{tag}",
            a.account_idx, a.balance_btc, a.utxo_count, utxo_label,
        );
    }
    println!();
    println!("  Total balance: {total_balance:.8} L-BTC");
    if let Some(idx) = fee_account_idx
        && let Some(fee_acct) = accounts.iter().find(|a| a.account_idx == idx as i32)
    {
        println!("  Fee account ({idx}): {:.8} L-BTC", fee_acct.balance_btc);
    }
}

/// Elements parallel of [`display_sweep_plan`]: one account-for-account
/// transaction, fee paid by the fee account.
fn display_elements_sweep_plan(
    accounts: &[ElementsAccountSummary],
    fee_account_idx: Option<u32>,
    fee_rate_sat_per_vb: u64,
) {
    println!();
    println!("  Sweep Plan");
    println!("  ──────────");
    println!();

    let customers: Vec<&ElementsAccountSummary> = accounts
        .iter()
        .filter(|a| !a.is_fee_account && a.balance_btc > 0.0)
        .collect();
    let input_count: usize = accounts
        .iter()
        .filter(|a| a.balance_btc > 0.0)
        .map(|a| a.utxo_count)
        .sum();
    let output_count = customers.len() + usize::from(fee_account_idx.is_some());
    let est_fee_sat =
        (input_count as u64 * 1100 + output_count as u64 * 1500 + 200) * fee_rate_sat_per_vb / 10;

    let label = match fee_account_idx {
        Some(idx) => format!("All accounts (fee from acct {idx})"),
        None => "All accounts".to_string(),
    };
    println!(
        "  Transaction 1/1:  {label:<28} │  {input_count} inputs → {output_count} outputs  │  fee: ~{est_fee_sat} sat",
    );
    println!();
    println!("  Total UTXOs swept:  {input_count}");
    println!("  Transactions:       1");

    if let Some(idx) = fee_account_idx
        && let Some(fee_acct) = accounts.iter().find(|a| a.account_idx == idx as i32)
    {
        #[allow(clippy::cast_precision_loss)]
        let post_fee = fee_acct.balance_btc - (est_fee_sat as f64 / 100_000_000.0);
        println!();
        println!(
            "  Fee account balance: {:.8} → {:.8} L-BTC (debit: ~{est_fee_sat} sat)",
            fee_acct.balance_btc, post_fee,
        );
    }
}

// =========================================================================
// Elements migration
// =========================================================================

/// Build the new-federation CT descriptor + blinding key for one account.
/// Returns `(multipath_descriptor, mbk_bytes, new_version_index)`.
async fn build_new_elements_federation(
    wallet: &test_app_pkcs11::elements_wallet::UserElementsWallet,
    cfg: &MigrationConfig,
    app_config: &AppConfig,
    hsm: &Arc<HsmFleet>,
    manager: &ElementsWalletManager,
    pool: &sqlx::PgPool,
) -> Result<(String, [u8; 32], i32), String> {
    use emvault::elements::descriptor::{CtDescriptorBuilder, CtKeyMode, to_multipath_string};

    let acct_idx = wallet.account_idx() as u32;
    let path = manager
        .derivation_path_for(acct_idx)
        .map_err(|e| e.to_string())?;
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
    let all_signers = hsm
        .signers_for(wallet.user_id(), &path)
        .await
        .map_err(|e| e.to_string())?;
    let patched: Vec<NetworkPatchedSigner> = new_signer_indices
        .iter()
        .map(|&idx| NetworkPatchedSigner::new(all_signers[idx].clone(), app_config.network))
        .collect();

    let versions = db::list_federation_versions_for_elements_wallet(pool, wallet.wallet_id())
        .await
        .map_err(|e| e.to_string())?;
    let new_version = i32::try_from(versions.len()).unwrap_or(0);
    let mbk = if cfg.elements.rotate_blinding_key {
        derive_elements_mbk(wallet.user_id(), wallet.account_idx(), new_version)
    } else {
        versions
            .last()
            .and_then(|v| v.blinding_key.clone())
            .map_or_else(
                || derive_elements_mbk(wallet.user_id(), wallet.account_idx(), 0),
                |h| hex_decode_bytes(&h),
            )
    };

    let mut builder = CtDescriptorBuilder::new(cfg.federation.threshold, &mbk)
        .map_err(|e| e.to_string())?
        .key_mode(CtKeyMode::Ranged);
    for s in &patched {
        builder.add_signer(s).map_err(|e| e.to_string())?;
    }
    let ct_desc = builder.build().map_err(|e| e.to_string())?;
    Ok((to_multipath_string(&ct_desc), mbk, new_version))
}

/// Per-account data assembled for the (blocking) migration execution.
struct ElementsExecAccount {
    account_idx: i32,
    is_fee: bool,
    old_descriptor: String,
    old_mbk: [u8; 32],
    utxos: Vec<emvault::elements::CapturedUtxo>,
    signers: test_app_pkcs11::hsm::SignerSet,
    dest: elements::Address,
    balance_sat: u64,
}

// =========================================================================
// Batched migration planner (Elements)
//
// `emvault::core::migration::AccountForAccountBatchedSweep` is bitcoin-typed,
// so — as with the account-for-account split — we reimplement the simple amount
// math inline for Elements. Produces the ordered transaction shape; the
// executor maps each tx's customer accounts to their UTXOs / wollets / dests
// and threads the fee-account change (decision (b): change stays at the fee
// account's old-fed address until the final tx).
// =========================================================================

/// A funded account, reduced to the fields the planner needs.
#[derive(Debug, Clone)]
struct BatchAcct {
    account_idx: i32,
    balance_sat: u64,
    utxo_count: usize,
}

/// One planned batched-migration transaction.
#[derive(Debug, PartialEq, Eq)]
struct BatchTxPlan {
    /// Customers paid in this tx (each receives its full balance): `(idx, sat)`.
    customers: Vec<(i32, u64)>,
    /// Estimated mining fee for this tx (paid by the fee account via drain).
    fee_sat: u64,
    /// The final fee-account migration tx (drains to the new federation; no
    /// customer recipients).
    is_fee_final: bool,
}

/// The full ordered batched plan plus the cumulative fee estimate.
#[derive(Debug)]
struct BatchPlan {
    txs: Vec<BatchTxPlan>,
    total_fee_sat: u64,
}

/// Planning fee estimate for an Elements P2WSH multisig tx, matching the
/// heuristic used by `display_elements_sweep_plan`.
fn estimate_elements_fee_sat(inputs: usize, outputs: usize, fee_rate_sat_per_vb: u64) -> u64 {
    (inputs as u64 * 1100 + outputs as u64 * 1500 + 200) * fee_rate_sat_per_vb / 10
}

/// Build the ordered batched plan: one tx per large account, all small accounts
/// bundled into one tx, and the fee account migrating last. Fees are estimated
/// and pre-checked against the fee account's balance.
///
/// Mirrors `AccountForAccountBatchedSweep::plan`'s ordering and fee accounting.
fn plan_elements_batched(
    accounts: &[BatchAcct],
    fee_account_idx: u32,
    small_threshold_sat: u64,
    fee_rate_sat_per_vb: u64,
) -> Result<BatchPlan, String> {
    let funded: Vec<&BatchAcct> = accounts.iter().filter(|a| a.utxo_count > 0).collect();
    if funded.is_empty() {
        return Err("no funded accounts to migrate".to_string());
    }

    let fee = funded
        .iter()
        .find(|a| a.account_idx == fee_account_idx as i32)
        .ok_or_else(|| {
            format!("fee account index {fee_account_idx} not found among funded accounts")
        })?;
    let fee_balance = fee.balance_sat;
    let fee_utxo_count = fee.utxo_count;

    let (large, small): (Vec<&BatchAcct>, Vec<&BatchAcct>) = funded
        .iter()
        .filter(|a| a.account_idx != fee_account_idx as i32)
        .partition(|a| a.balance_sat >= small_threshold_sat);

    // Pre-flight: estimate the cumulative fee across every planned tx.
    let mut total_fee = 0u64;
    for a in &large {
        total_fee += estimate_elements_fee_sat(a.utxo_count + 1, 2, fee_rate_sat_per_vb);
    }
    if !small.is_empty() {
        let small_inputs: usize = small.iter().map(|a| a.utxo_count).sum::<usize>() + 1;
        total_fee += estimate_elements_fee_sat(small_inputs, small.len() + 1, fee_rate_sat_per_vb);
    }
    let fee_final_fee = estimate_elements_fee_sat(fee_utxo_count, 1, fee_rate_sat_per_vb);
    total_fee += fee_final_fee;

    if fee_balance < total_fee {
        return Err(format!(
            "fee account {fee_account_idx} has insufficient balance to pay migration fees: \
             available {fee_balance} sat, required ~{total_fee} sat"
        ));
    }

    let mut txs = Vec::new();
    for a in &large {
        txs.push(BatchTxPlan {
            customers: vec![(a.account_idx, a.balance_sat)],
            fee_sat: estimate_elements_fee_sat(a.utxo_count + 1, 2, fee_rate_sat_per_vb),
            is_fee_final: false,
        });
    }
    if !small.is_empty() {
        let small_inputs: usize = small.iter().map(|a| a.utxo_count).sum::<usize>() + 1;
        txs.push(BatchTxPlan {
            customers: small
                .iter()
                .map(|a| (a.account_idx, a.balance_sat))
                .collect(),
            fee_sat: estimate_elements_fee_sat(small_inputs, small.len() + 1, fee_rate_sat_per_vb),
            is_fee_final: false,
        });
    }
    // Fee account migrates last (drains its remaining balance to the new fed).
    txs.push(BatchTxPlan {
        customers: Vec::new(),
        fee_sat: fee_final_fee,
        is_fee_final: true,
    });

    Ok(BatchPlan {
        txs,
        total_fee_sat: total_fee,
    })
}

/// Elements parallel of [`display_elements_sweep_plan`] for the **batched**
/// strategy: one line per planned transaction (large accounts individually,
/// small accounts bundled, fee account last), plus the cumulative fee estimate.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn display_elements_batched_plan(
    accounts: &[ElementsAccountSummary],
    fee_account_idx: Option<u32>,
    small_threshold_sat: u64,
    fee_rate_sat_per_vb: u64,
) {
    println!();
    println!("  Sweep Plan (batched)");
    println!("  ────────────────────");
    println!();

    let Some(fee_idx) = fee_account_idx else {
        println!("  (the batched strategy requires a fee account)");
        return;
    };

    let baccts: Vec<BatchAcct> = accounts
        .iter()
        .filter(|a| a.balance_btc > 0.0)
        .map(|a| BatchAcct {
            account_idx: a.account_idx,
            balance_sat: (a.balance_btc * 100_000_000.0).round() as u64,
            utxo_count: a.utxo_count,
        })
        .collect();

    match plan_elements_batched(&baccts, fee_idx, small_threshold_sat, fee_rate_sat_per_vb) {
        Ok(plan) => {
            let total = plan.txs.len();
            for (i, tx) in plan.txs.iter().enumerate() {
                let label = if tx.is_fee_final {
                    format!("Fee account {fee_idx} → new federation")
                } else if tx.customers.len() == 1 {
                    format!("Account {}", tx.customers[0].0)
                } else {
                    format!("{} small accounts (bundled)", tx.customers.len())
                };
                println!(
                    "  Transaction {}/{}:  {label:<34} │  fee: ~{} sat",
                    i + 1,
                    total,
                    tx.fee_sat
                );
            }
            println!();
            println!("  Transactions:        {total}");
            println!(
                "  Estimated total fee: ~{} sat (paid by account {fee_idx})",
                plan.total_fee_sat
            );
        }
        Err(e) => {
            println!("  Cannot plan batched migration: {e}");
        }
    }
}

async fn run_elements_migration(
    cfg: &MigrationConfig,
    app_config: &AppConfig,
    pool: &sqlx::PgPool,
    hsm: &Arc<HsmFleet>,
    dry_run: bool,
    sweep_only: bool,
) {
    use emvault::elements::sync::KeychainKind;
    use emvault::elements::{
        ElementsWollet, build_migration_pset, captured_from_output, finalize_p2wsh_pset,
    };

    println!("  Elements network: {}", app_config.elements_network);
    let manager = ElementsWalletManager::new(pool.clone(), app_config, hsm.clone());

    // -- Discover all Elements accounts ------------------------------------
    let wallet_rows = match db::list_all_elements_wallets(pool).await {
        Ok(r) if r.is_empty() => {
            eprintln!("error: no Elements wallets found in the database");
            std::process::exit(1);
        }
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: failed to list Elements wallets: {e}");
            std::process::exit(1);
        }
    };
    println!("  Wallets:  {} discovered", wallet_rows.len());

    let fee_account_idx = cfg.migration.fee_account_idx;
    let mut user_wallets = Vec::new();
    let mut summaries = Vec::new();
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
                eprintln!("error: migration status check failed for account {acct_idx}: {e}");
                std::process::exit(1);
            }
        }
        let wallet = match manager.load_wallet_from_row(row).await {
            Ok(w) => w,
            Err(e) => {
                eprintln!("error: failed to load Elements wallet for account {acct_idx}: {e}");
                std::process::exit(1);
            }
        };
        let utxos = match wallet.captured_utxos().await {
            Ok(u) => u,
            Err(e) => {
                eprintln!("error: failed to read UTXOs for account {acct_idx}: {e}");
                std::process::exit(1);
            }
        };
        let balance_sat: u64 = utxos
            .iter()
            .map(emvault::elements::CapturedUtxo::value)
            .sum();
        #[allow(clippy::cast_precision_loss)]
        let balance_btc = balance_sat as f64 / 100_000_000.0;
        summaries.push(ElementsAccountSummary {
            account_idx: acct_idx,
            balance_btc,
            utxo_count: utxos.len(),
            destination_address: None,
            is_fee_account: fee_account_idx == Some(acct_idx as u32),
        });
        user_wallets.push(wallet);
    }

    // -- Federation-change display (current = app-config federation) -------
    let current_signers: Vec<(String, String)> = app_config
        .fed_signer_indices
        .iter()
        .filter_map(|&i| app_config.hsm_tokens.get(i))
        .map(|t| (t.label.clone(), t.label.clone()))
        .collect();
    let current_threshold = app_config.fed_threshold;
    display_federation_change(
        &current_signers,
        current_threshold,
        &cfg.federation.signers,
        cfg.federation.threshold,
        app_config,
    );

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

    let total_balance_btc: f64 = summaries.iter().map(|a| a.balance_btc).sum();
    display_elements_migration_plan(
        &cfg.migration.strategy,
        total_balance_btc,
        cfg.migration.fee_rate_sat_per_vb,
    );

    let batched = cfg.migration.strategy == "account-for-account-batched";

    // -- Resolve each account's destination federation ---------------------
    // (account_idx → (new_descriptor, new_mbk, new_version_index))
    let net = manager.network();
    let lwk_net = match manager.lwk_network().await {
        Ok(n) => n,
        Err(e) => {
            eprintln!("error: failed to resolve Elements network params: {e}");
            std::process::exit(1);
        }
    };
    let mut new_feds: std::collections::HashMap<i32, (String, [u8; 32], i32)> =
        std::collections::HashMap::new();
    for wallet in &user_wallets {
        let acct_idx = wallet.account_idx();
        let resolved = if sweep_only {
            match db::list_federation_versions_for_elements_wallet(pool, wallet.wallet_id()).await {
                Ok(versions) => versions.last().map(|v| {
                    let mbk = v.blinding_key.as_deref().map_or_else(
                        || derive_elements_mbk(wallet.user_id(), acct_idx, v.version_index),
                        hex_decode_bytes,
                    );
                    (v.descriptor.clone(), mbk, v.version_index)
                }),
                Err(e) => {
                    eprintln!("error: failed to list versions for account {acct_idx}: {e}");
                    std::process::exit(1);
                }
            }
        } else {
            match build_new_elements_federation(wallet, cfg, app_config, hsm, &manager, pool).await
            {
                Ok(v) => Some(v),
                Err(e) => {
                    eprintln!("error: failed to build new federation for account {acct_idx}: {e}");
                    std::process::exit(1);
                }
            }
        };
        let Some((desc, mbk, version)) = resolved else {
            eprintln!("error: no destination federation for account {acct_idx}");
            std::process::exit(1);
        };
        let dest = match ElementsWollet::from_descriptor_str(&desc, mbk, net, lwk_net)
            .and_then(|w| w.address(KeychainKind::External, 0))
        {
            Ok(a) => a,
            Err(e) => {
                eprintln!(
                    "error: failed to derive destination address for account {acct_idx}: {e}"
                );
                std::process::exit(1);
            }
        };
        if let Some(s) = summaries.iter_mut().find(|s| s.account_idx == acct_idx) {
            s.destination_address = Some(dest.to_string());
        }
        new_feds.insert(acct_idx, (desc, mbk, version));
    }

    display_elements_account_table(&summaries, fee_account_idx);
    if total_balance_btc > 0.0 {
        if batched {
            display_elements_batched_plan(
                &summaries,
                fee_account_idx,
                cfg.migration.small_account_threshold,
                cfg.migration.fee_rate_sat_per_vb,
            );
        } else {
            display_elements_sweep_plan(
                &summaries,
                fee_account_idx,
                cfg.migration.fee_rate_sat_per_vb,
            );
        }
    }

    // -- Dry run -----------------------------------------------------------
    if dry_run {
        println!();
        println!("  Dry Run Summary");
        println!("  ───────────────");
        println!();
        println!(
            "  Accounts to migrate:  {}",
            summaries.iter().filter(|a| a.balance_btc > 0.0).count()
        );
        println!("  Total balance:        {total_balance_btc:.8} L-BTC");
        println!("  Strategy:             {}", cfg.migration.strategy);
        println!(
            "  Fee rate:             {} sat/vB",
            cfg.migration.fee_rate_sat_per_vb
        );
        if let Some(idx) = fee_account_idx
            && let Some(fa) = summaries.iter().find(|a| a.account_idx == idx as i32)
        {
            println!("  Fee account ({idx}):      {:.8} L-BTC", fa.balance_btc);
        }
        println!();
        println!("  No changes were made.");
        std::process::exit(0);
    }

    // === STEP 1: apply the federation change ==============================
    if sweep_only {
        println!("\n  --sweep-only: skipping Step 1 (federation change already recorded).");
    } else {
        if !confirm("Step 1/3: Apply this federation change to all Elements accounts?") {
            println!("Aborted.");
            std::process::exit(0);
        }
        println!("\n  Creating new federation for all accounts...");
        for wallet in &user_wallets {
            let acct_idx = wallet.account_idx();
            let (desc, mbk, version) = new_feds.get(&acct_idx).cloned().expect("resolved above");
            let snapshot = serde_json::json!({ "descriptor": desc });
            let mbk_hex = hex_encode_bytes(&mbk);
            match db::insert_federation_version(
                pool,
                &db::NewFederationVersion {
                    wallet_id: None,
                    elements_wallet_id: Some(wallet.wallet_id()),
                    version_index: version,
                    descriptor: &desc,
                    threshold: i32::try_from(cfg.federation.threshold).unwrap_or(0),
                    signer_count: i32::try_from(cfg.federation.signers.len()).unwrap_or(0),
                    federation_snapshot: &snapshot,
                    wallet_handle: &format!("elements-{acct_idx}-v{version}"),
                    blinding_key: Some(&mbk_hex),
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
            if let Err(e) = db::set_pending_migration_for_older_elements_versions(
                pool,
                wallet.wallet_id(),
                version,
            )
            .await
            {
                eprintln!("warning: failed to update migration status for account {acct_idx}: {e}");
            }
            println!(
                "  Account {acct_idx}: federation v{version} created ({}-of-{})",
                cfg.federation.threshold,
                cfg.federation.signers.len()
            );
        }
    }

    // === STEP 2/3: execute the fund migration =============================
    if total_balance_btc <= 0.0 {
        println!("\n  No funds to migrate. Federation change is complete.");
        println!("\n  Restart the web app to pick up the new federation.");
        std::process::exit(0);
    }
    if !confirm("Step 2/3: Execute the fund migration for all Elements accounts?") {
        println!(
            "\n  Federation change recorded but funds NOT migrated.\n  \
             Re-run with --sweep-only later to complete the migration."
        );
        std::process::exit(0);
    }
    println!("\n  Executing migration...");

    let fee_idx = match fee_account_idx {
        Some(i) => i as i32,
        None => {
            eprintln!("error: Elements migration requires fee_account_idx (fee-account-pays)");
            std::process::exit(1);
        }
    };

    // Assemble per-account execution data (async side).
    let mut exec_accounts: Vec<ElementsExecAccount> = Vec::new();
    for wallet in &user_wallets {
        let acct_idx = wallet.account_idx();
        let utxos = match wallet.captured_utxos().await {
            Ok(u) => u,
            Err(e) => {
                eprintln!("error: failed to read UTXOs for account {acct_idx}: {e}");
                std::process::exit(1);
            }
        };
        if utxos.is_empty() {
            continue;
        }
        let balance_sat: u64 = utxos
            .iter()
            .map(emvault::elements::CapturedUtxo::value)
            .sum();
        let (desc, mbk, _) = new_feds.get(&acct_idx).cloned().expect("resolved above");
        let dest = match ElementsWollet::from_descriptor_str(&desc, mbk, net, lwk_net)
            .and_then(|w| w.address(KeychainKind::External, 0))
        {
            Ok(a) => a,
            Err(e) => {
                eprintln!("error: destination address for account {acct_idx}: {e}");
                std::process::exit(1);
            }
        };
        exec_accounts.push(ElementsExecAccount {
            account_idx: acct_idx,
            is_fee: acct_idx == fee_idx,
            old_descriptor: wallet.descriptor().to_string(),
            old_mbk: wallet.master_blinding_key(),
            utxos,
            signers: wallet.signer_set(),
            dest,
            balance_sat,
        });
    }

    // Plan the batched transaction sequence up-front (pure amount math; no
    // node). `None` for the single-tx account-for-account strategy.
    let batch_plan = if batched {
        let baccts: Vec<BatchAcct> = exec_accounts
            .iter()
            .map(|a| BatchAcct {
                account_idx: a.account_idx,
                balance_sat: a.balance_sat,
                utxo_count: a.utxos.len(),
            })
            .collect();
        match plan_elements_batched(
            &baccts,
            fee_idx as u32,
            cfg.migration.small_account_threshold,
            cfg.migration.fee_rate_sat_per_vb,
        ) {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("error: batched migration planning failed: {e}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    let rpc = (
        app_config.elements_rpc_url.clone(),
        app_config.elements_rpc_user.clone(),
        app_config.elements_rpc_password.clone(),
    );
    #[allow(clippy::cast_precision_loss)]
    let fee_rate_kvb = (cfg.migration.fee_rate_sat_per_vb as f64 * 1000.0) as f32;

    type TxResult = (String, Vec<(i32, u64)>, bool);
    let result = tokio::task::spawn_blocking(move || -> Result<Vec<TxResult>, String> {
        use emvault::elements::signer::ElementsSigner;
        use emvault::elements::sync::{ElementsChainSource, KeychainKind};
        use test_app_pkcs11::elements_sync::RpcChainSource;

        // Build each account's old (input-owning) wollet.
        let mut wollets: Vec<(i32, ElementsWollet)> = Vec::new();
        for a in &exec_accounts {
            let w = ElementsWollet::from_descriptor_str(&a.old_descriptor, a.old_mbk, net, lwk_net)
                .map_err(|e| e.to_string())?;
            wollets.push((a.account_idx, w));
        }
        let wollet_of = |idx: i32| -> &ElementsWollet {
            &wollets
                .iter()
                .find(|(i, _)| *i == idx)
                .expect("wollet present")
                .1
        };

        let chain = RpcChainSource::new(&rpc.0, &rpc.1, &rpc.2).map_err(|e| e.to_string())?;

        // Sign a PSET so that each involved account signs only its own inputs.
        // The old federation shares signer fingerprints across accounts (they
        // differ only by BIP-48 account path), so we index-scope by clearing
        // the `bip32_derivation` on inputs an account does not own before
        // running its signers, then restore.
        let sign_scoped =
            |pset: &mut elements::pset::PartiallySignedTransaction,
             owner: &std::collections::HashMap<elements::OutPoint, i32>| {
                let involved: std::collections::HashSet<i32> = owner.values().copied().collect();
                for acct in involved {
                    let Some(exec) = exec_accounts.iter().find(|a| a.account_idx == acct) else {
                        continue;
                    };
                    let owned: std::collections::HashSet<elements::OutPoint> = owner
                        .iter()
                        .filter(|(_, v)| **v == acct)
                        .map(|(k, _)| *k)
                        .collect();
                    let indices: Vec<usize> = pset
                        .inputs()
                        .iter()
                        .enumerate()
                        .filter(|(_, inp)| {
                            owned.contains(&elements::OutPoint::new(
                                inp.previous_txid,
                                inp.previous_output_index,
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
                    for signer in exec.signers.iter() {
                        let _ = signer.sign_pset(pset);
                    }
                    for (i, d) in saved {
                        pset.inputs_mut()[i].bip32_derivation = d;
                    }
                }
            };

        let mut results: Vec<TxResult> = Vec::new();

        if let Some(plan) = batch_plan {
            // --- batched: chained confidential fee-change (decision (b)) ----
            // Intermediate fee change stays at the fee account's OLD-fed
            // address (old-fed-signed); the fee account crosses to the new
            // federation only in the final tx.
            let fee_exec_idx = exec_accounts
                .iter()
                .position(|a| a.account_idx == fee_idx)
                .ok_or("fee account is not funded")?;
            let fee_wollet = wollet_of(fee_idx);
            let fee_old_addr = fee_wollet
                .address(KeychainKind::External, 0)
                .map_err(|e| e.to_string())?;
            let fee_new_dest = exec_accounts[fee_exec_idx].dest.clone();
            let fee_utxos = exec_accounts[fee_exec_idx].utxos.clone();
            let fee_wallet_id = fee_utxos
                .first()
                .ok_or("fee account has no UTXOs")?
                .wallet_id;

            let mut chained: Option<emvault::elements::CapturedUtxo> = None;
            let mut fee_seed_used = false;

            for txp in &plan.txs {
                let mut inputs: Vec<(emvault::elements::CapturedUtxo, &ElementsWollet)> =
                    Vec::new();
                let mut recipients: Vec<(elements::Address, u64)> = Vec::new();
                let mut report: Vec<(i32, u64)> = Vec::new();
                let mut owner: std::collections::HashMap<elements::OutPoint, i32> =
                    std::collections::HashMap::new();

                for (cidx, amt) in &txp.customers {
                    let a = exec_accounts
                        .iter()
                        .find(|a| a.account_idx == *cidx)
                        .ok_or("planned customer account missing from exec set")?;
                    let w = wollet_of(*cidx);
                    for u in &a.utxos {
                        owner.insert(u.outpoint, *cidx);
                        inputs.push((u.clone(), w));
                    }
                    recipients.push((a.dest.clone(), *amt));
                    report.push((*cidx, *amt));
                }

                let fee_dest = if txp.is_fee_final {
                    &fee_new_dest
                } else {
                    &fee_old_addr
                };

                if txp.is_fee_final {
                    // Remaining real fee UTXOs (skip the chain seed if used)
                    // plus the final chained change.
                    let start = usize::from(fee_seed_used);
                    for u in fee_utxos.iter().skip(start) {
                        owner.insert(u.outpoint, fee_idx);
                        inputs.push((u.clone(), fee_wollet));
                    }
                    if let Some(c) = chained.take() {
                        owner.insert(c.outpoint, fee_idx);
                        inputs.push((c, fee_wollet));
                    }
                } else if let Some(c) = chained.take() {
                    owner.insert(c.outpoint, fee_idx);
                    inputs.push((c, fee_wollet));
                } else {
                    let seed = fee_utxos.first().ok_or("fee account has no UTXOs")?.clone();
                    owner.insert(seed.outpoint, fee_idx);
                    inputs.push((seed, fee_wollet));
                    fee_seed_used = true;
                }

                if inputs.is_empty() {
                    continue;
                }

                let blinded =
                    build_migration_pset(fee_wollet, &inputs, &recipients, fee_dest, fee_rate_kvb)
                        .map_err(|e| e.to_string())?;
                let mut pset = blinded.into_pset();
                sign_scoped(&mut pset, &owner);
                finalize_p2wsh_pset(&mut pset).map_err(|e| e.to_string())?;
                let tx = pset.extract_tx().map_err(|e| e.to_string())?;
                let txid = chain.broadcast(&tx).map_err(|e| e.to_string())?;

                // Capture the fee account's change (at its old-fed address) to
                // feed the next transaction.
                if !txp.is_fee_final {
                    let spk = fee_old_addr.script_pubkey();
                    let (vout, txout) = tx
                        .output
                        .iter()
                        .enumerate()
                        .find(|(_, o)| o.script_pubkey == spk)
                        .map(|(i, o)| (u32::try_from(i).unwrap_or(0), o.clone()))
                        .ok_or("fee-account change output not found in broadcast tx")?;
                    chained = Some(
                        captured_from_output(fee_wollet, tx.txid(), vout, &txout, fee_wallet_id, 0)
                            .map_err(|e| e.to_string())?,
                    );
                }

                results.push((txid.to_string(), report, txp.is_fee_final));
            }
        } else {
            // --- account-for-account: single fee-account-pays transaction ---
            let mut inputs: Vec<(emvault::elements::CapturedUtxo, &ElementsWollet)> = Vec::new();
            let mut customers: Vec<(elements::Address, u64)> = Vec::new();
            let mut report: Vec<(i32, u64)> = Vec::new();
            let mut owner: std::collections::HashMap<elements::OutPoint, i32> =
                std::collections::HashMap::new();
            let mut fee_dest: Option<elements::Address> = None;
            let mut fee_acct: Option<i32> = None;
            for a in &exec_accounts {
                let w = wollet_of(a.account_idx);
                for u in &a.utxos {
                    owner.insert(u.outpoint, a.account_idx);
                    inputs.push((u.clone(), w));
                }
                if a.is_fee {
                    fee_dest = Some(a.dest.clone());
                    fee_acct = Some(a.account_idx);
                } else {
                    customers.push((a.dest.clone(), a.balance_sat));
                    report.push((a.account_idx, a.balance_sat));
                }
            }
            let fee_dest = fee_dest.ok_or("fee account has no UTXOs to pay the migration fee")?;
            let fee_wollet = wollet_of(fee_acct.expect("fee account present"));

            let blinded =
                build_migration_pset(fee_wollet, &inputs, &customers, &fee_dest, fee_rate_kvb)
                    .map_err(|e| e.to_string())?;
            let mut pset = blinded.into_pset();
            sign_scoped(&mut pset, &owner);
            finalize_p2wsh_pset(&mut pset).map_err(|e| e.to_string())?;
            let tx = pset.extract_tx().map_err(|e| e.to_string())?;
            let txid = chain.broadcast(&tx).map_err(|e| e.to_string())?;
            results.push((txid.to_string(), report, false));
        }

        Ok(results)
    })
    .await
    .expect("spawn_blocking join");

    match result {
        Ok(txs) => {
            let total = txs.len();
            for (i, (txid, outputs, is_fee_final)) in txs.iter().enumerate() {
                println!("\n  Transaction {}/{}:", i + 1, total);
                println!("    Broadcast: txid {txid}");
                if *is_fee_final {
                    println!("    Outputs: fee account {fee_idx} → new federation");
                } else {
                    let summary: Vec<String> = outputs
                        .iter()
                        .map(|(acct, sat)| format!("account {acct}: {sat} sat"))
                        .collect();
                    println!("    Outputs: {}", summary.join(", "));
                }
            }
        }
        Err(e) => {
            eprintln!("error: Elements migration failed: {e}");
            std::process::exit(1);
        }
    }

    println!();
    println!("  Migration complete.");
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
        "emvault-elements-mbk-rotated".hash(&mut hasher);
    }
    let h1 = hasher.finish();
    let mut hasher2 = DefaultHasher::new();
    h1.hash(&mut hasher2);
    "emvault-elements-mbk-v1".hash(&mut hasher2);
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
        emvault::core::MigrationPlan<emvault::core::psbt::UnsignedPsbt>,
    > = None;
    let mut account_utxo_sets: Vec<emvault::core::AccountUtxoSet> = Vec::new();

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

            let new_fed = match emvault::core::Federation::with_key_mode(
                cfg.federation.threshold,
                new_signers,
                emvault::core::network::NetworkType::Bitcoin(app_config.network),
                KeyMode::Ranged,
            ) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("error: failed to create federation for account {acct_idx}: {e}");
                    std::process::exit(1);
                }
            };

            let dest_desc_str = emvault::core::descriptor::to_multipath_string(
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
            account_utxo_sets.push(emvault::core::AccountUtxoSet {
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
            emvault::core::MigrationPlan<emvault::core::psbt::UnsignedPsbt>,
            emvault::core::MigrationError,
        > = if cfg.migration.strategy == "account-for-account" {
            let alg =
                emvault::core::AccountForAccountSweep::new(fee_account_idx.expect("validated"));
            emvault::core::SweepAlgorithm::plan(
                &alg,
                &account_utxo_sets,
                first_wallet.federation().network(),
                first_wallet.federation().network(),
                fee_rate,
            )
        } else {
            let alg = emvault::core::AccountForAccountBatchedSweep::new(
                fee_account_idx.expect("validated"),
                Amount::from_sat(cfg.migration.small_account_threshold),
            );
            emvault::core::SweepAlgorithm::plan(
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
    if sweep_only {
        println!("\n  --sweep-only: skipping Step 1 (federation change already recorded).");
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

            let new_federation = match emvault::core::Federation::with_key_mode(
                cfg.federation.threshold,
                new_signers,
                emvault::core::network::NetworkType::Bitcoin(app_config.network),
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

            let descriptor_str = emvault::core::descriptor::to_multipath_string(
                new_federation
                    .try_descriptor()
                    .expect("Bitcoin federation has a descriptor"),
            );
            let snapshot =
                emvault::core::snapshot::FederationSnapshot::from_federation(&new_federation);
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

    // Fee-change routing (decision (b), matching Elements): intermediate fee
    // change stays at the fee account's OLD-federation address — old-fed-signed,
    // identical to the original fee UTXO — and only the final fee-account tx
    // crosses to the new federation. Resolve both addresses up front, plus the
    // old descriptor used to rebuild the chained PSBT input.
    //
    // The OLD federation is the version *before* the newest: `load_wallet_from_row`
    // always seeds a v0 row, and Step 1 appends the new version, so the
    // second-to-last version is the fund-holding old federation.
    let fee_old_descriptor: String = {
        let versions = db::list_federation_versions_for_wallet(
            &pool,
            user_wallets[fee_wallet_idx].wallet_id(),
        )
        .await
        .unwrap_or_default();
        if versions.len() < 2 {
            eprintln!(
                "error: fee account {fee_acct_idx} has no prior (old) federation version to \
                 source intermediate fee-change from"
            );
            std::process::exit(1);
        }
        versions[versions.len() - 2].descriptor.clone()
    };
    let fee_old_addr: bitcoin::Address = {
        let desc: bdk_wallet::miniscript::Descriptor<bdk_wallet::miniscript::DescriptorPublicKey> =
            fee_old_descriptor
                .parse()
                .expect("valid old fee descriptor");
        let mut tw = bdk_wallet::Wallet::create_from_two_path_descriptor(desc)
            .network(app_config.network)
            .create_wallet_no_persist()
            .expect("valid temp wallet from old fee descriptor");
        tw.reveal_next_address(bdk_wallet::KeychainKind::External)
            .address
    };
    let fee_new_dest: bitcoin::Address = account_utxo_sets
        .iter()
        .find(|a| a.account_idx == fee_acct_idx)
        .map(|a| a.destination_address.clone())
        .expect("fee account present in account set");

    // Chained fee-change data from the previous broadcast: outpoint +
    // pre-built PSBT input (because the UserWallet's version_wallets were
    // loaded before Step 1 and don't include the chained, unconfirmed change).
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

            // Add outputs from the plan markers. Customers get an exact
            // recipient; the fee-change output uses drain_to (absorbs the fee)
            // routed to the fee account's OLD-fed address on intermediate hops
            // and its NEW-fed address only on the final fee-account tx.
            for output in &sweep_tx.outputs {
                match output {
                    emvault::core::SweepOutput::Customer {
                        address, amount, ..
                    } => {
                        builder.add_recipient(address.script_pubkey(), *amount);
                    }
                    emvault::core::SweepOutput::FeeChange { .. } => {
                        let dest = if sweep_tx.is_fee_final {
                            &fee_new_dest
                        } else {
                            &fee_old_addr
                        };
                        builder.drain_to(dest.script_pubkey());
                    }
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
                // Report per-output amounts from the plan markers.
                let output_summary: Vec<String> = sweep_tx
                    .outputs
                    .iter()
                    .map(|o| format!("account {}: {} sat", o.account_idx(), o.amount().to_sat()))
                    .collect();
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

        // Build PSBT input data for the fee account's change output so the next
        // transaction can spend it without a full wallet sync. Intermediate fee
        // change lands at the fee account's OLD-fed address and must be rebuilt
        // from the OLD descriptor (decision (b)) — so it stays old-fed-signed.
        // The final fee-account tx has no successor, so skip capture there.
        if !sweep_tx.is_fee_final {
            let fee_script = fee_old_addr.script_pubkey();
            for (vout, output) in tx.output.iter().enumerate() {
                if output.script_pubkey == fee_script {
                    let change_op = bitcoin::OutPoint {
                        txid,
                        vout: vout as u32,
                    };
                    // Build the PSBT input via a temp wallet on the fee
                    // account's OLD descriptor; the chained change is an
                    // unconfirmed output the fee wallet never synced, so apply
                    // the just-broadcast tx to a throwaway wallet to spend it.
                    let desc: bdk_wallet::miniscript::Descriptor<
                        bdk_wallet::miniscript::DescriptorPublicKey,
                    > = fee_old_descriptor
                        .parse()
                        .expect("valid old fee descriptor");
                    let mut temp_wallet = bdk_wallet::Wallet::create_from_two_path_descriptor(desc)
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
                    break;
                }
            }
        }

        // Record the transaction for each involved account, attributing by the
        // output's account index (the fee account's address now varies per tx:
        // old-fed for intermediate hops, new-fed for the final tx).
        let raw_hex = bitcoin::hex::DisplayHex::to_lower_hex_string(raw.as_slice());
        for output in &sweep_tx.outputs {
            let out_acct = output.account_idx();
            let recipient = match output {
                emvault::core::SweepOutput::Customer { address, .. } => address.to_string(),
                emvault::core::SweepOutput::FeeChange { .. } => {
                    if sweep_tx.is_fee_final {
                        fee_new_dest.to_string()
                    } else {
                        fee_old_addr.to_string()
                    }
                }
            };
            if let Some(&wi) = wallet_by_acct.get(&out_acct) {
                let wallet = &user_wallets[wi];
                let _ = db::insert_transaction(
                    wallet.pool(),
                    &db::NewTransaction {
                        wallet_id: wallet.wallet_id(),
                        txid: &txid.to_string(),
                        recipient: &recipient,
                        amount_sat: i64::try_from(output.amount().to_sat()).unwrap_or(i64::MAX),
                        fee_sat: 0, // fee attributed to fee account only
                        raw_tx_hex: &raw_hex,
                        label: Some(&format!("federation-migration-account-{out_acct}")),
                    },
                )
                .await;
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

#[cfg(test)]
mod batch_planner_tests {
    use super::{BatchAcct, plan_elements_batched};

    fn acct(account_idx: i32, balance_sat: u64, utxo_count: usize) -> BatchAcct {
        BatchAcct {
            account_idx,
            balance_sat,
            utxo_count,
        }
    }

    const RATE: u64 = 1; // sat/vB

    #[test]
    fn splits_by_threshold() {
        // fee(0) large, 1 & 2 large, 3 & 4 small.
        let accounts = vec![
            acct(0, 1_000_000, 1),
            acct(1, 200_000, 1),
            acct(2, 150_000, 1),
            acct(3, 50_000, 1),
            acct(4, 30_000, 1),
        ];
        let plan = plan_elements_batched(&accounts, 0, 100_000, RATE).unwrap();
        // 2 large individual + 1 small bundle + 1 fee-final = 4
        assert_eq!(plan.txs.len(), 4);
        assert!(plan.txs.last().unwrap().is_fee_final);
        assert!(plan.txs.last().unwrap().customers.is_empty());
        // small bundle carries both small customers
        let bundle = &plan.txs[2];
        assert_eq!(bundle.customers.len(), 2);
    }

    #[test]
    fn all_large() {
        let accounts = vec![
            acct(0, 1_000_000, 1),
            acct(1, 200_000, 1),
            acct(2, 150_000, 1),
        ];
        let plan = plan_elements_batched(&accounts, 0, 10_000, RATE).unwrap();
        // 2 large + 0 bundle + 1 fee = 3
        assert_eq!(plan.txs.len(), 3);
    }

    #[test]
    fn all_small() {
        let accounts = vec![
            acct(0, 5_000_000, 1),
            acct(1, 50_000, 1),
            acct(2, 30_000, 1),
            acct(3, 20_000, 1),
        ];
        let plan = plan_elements_batched(&accounts, 0, 1_000_000, RATE).unwrap();
        // 0 large + 1 bundle + 1 fee = 2
        assert_eq!(plan.txs.len(), 2);
        assert_eq!(plan.txs[0].customers.len(), 3);
    }

    #[test]
    fn only_fee_account_funded() {
        let accounts = vec![acct(0, 1_000_000, 2)];
        let plan = plan_elements_batched(&accounts, 0, 100_000, RATE).unwrap();
        // Just the fee-final tx.
        assert_eq!(plan.txs.len(), 1);
        assert!(plan.txs[0].is_fee_final);
    }

    #[test]
    fn customers_get_full_balance() {
        let accounts = vec![acct(0, 1_000_000, 1), acct(1, 200_000, 1)];
        let plan = plan_elements_batched(&accounts, 0, 10_000, RATE).unwrap();
        assert_eq!(plan.txs[0].customers, vec![(1, 200_000)]);
    }

    #[test]
    fn total_fee_is_sum_of_tx_fees() {
        let accounts = vec![
            acct(0, 1_000_000, 1),
            acct(1, 200_000, 1),
            acct(2, 50_000, 1),
        ];
        let plan = plan_elements_batched(&accounts, 0, 100_000, RATE).unwrap();
        let summed: u64 = plan.txs.iter().map(|t| t.fee_sat).sum();
        assert_eq!(summed, plan.total_fee_sat);
    }

    #[test]
    fn rejects_insufficient_fee_balance() {
        let accounts = vec![
            acct(0, 100, 1), // fee account far too small
            acct(1, 200_000, 1),
            acct(2, 300_000, 1),
        ];
        let err = plan_elements_batched(&accounts, 0, 100_000, RATE).unwrap_err();
        assert!(err.contains("insufficient"), "got: {err}");
    }

    #[test]
    fn rejects_no_funded_accounts() {
        let accounts = vec![acct(0, 0, 0), acct(1, 0, 0)];
        let err = plan_elements_batched(&accounts, 0, 100_000, RATE).unwrap_err();
        assert!(err.contains("no funded"), "got: {err}");
    }

    #[test]
    fn rejects_missing_fee_account() {
        let accounts = vec![acct(1, 200_000, 1), acct(2, 300_000, 1)];
        let err = plan_elements_batched(&accounts, 99, 100_000, RATE).unwrap_err();
        assert!(err.contains("not found"), "got: {err}");
    }
}
