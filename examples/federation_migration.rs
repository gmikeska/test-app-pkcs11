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

    // Show balances.
    let mut total_balance_btc = 0.0_f64;
    for wallet in &user_wallets {
        let acct_idx = wallet.account_idx();
        match wallet.balance().await {
            Ok(bal) => {
                let btc = bal.trusted + bal.untrusted_pending;
                total_balance_btc += btc;
                println!("  Account {acct_idx}: {btc:.8} L-BTC");
            }
            Err(e) => {
                eprintln!("warning: failed to get balance for Elements account {acct_idx}: {e}");
            }
        }
    }
    println!("  Total:   {total_balance_btc:.8} L-BTC");

    if dry_run {
        println!();
        println!("  Dry Run — no changes were made.");
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
            let versions =
                match db::list_federation_versions_for_elements_wallet(pool, wallet.wallet_id())
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
                // Derive fresh MBK using a version-salted derivation.
                let new_version = i32::try_from(versions.len()).unwrap_or(0);
                let key = crate::derive_elements_mbk(
                    wallet.user_id(),
                    wallet.account_idx(),
                    new_version,
                );
                hex_encode_bytes(&key)
            } else {
                // Reuse existing MBK from the latest federation version.
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
                    eprintln!(
                        "error: CT descriptor builder failed for account {acct_idx}: {e}"
                    );
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
                    eprintln!(
                        "error: failed to build CT descriptor for account {acct_idx}: {e}"
                    );
                    std::process::exit(1);
                }
            };
            let multipath = to_multipath_string(&ct_desc);

            // Set up the new daemon wallet.
            let new_version_index = i32::try_from(versions.len()).unwrap_or(0);
            let daemon_wallet_name =
                format!("asterism-elements-user-{}-v{new_version_index}", wallet.account_idx());

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
                    let info = rpc
                        .get_descriptor_info(desc)
                        .map_err(|e| e.to_string())?;
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
                    asterism_elements::elements_miniscript::elements::secp256k1_zkp::Secp256k1::new();
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
                            let _ = rpc.import_blinding_key(
                                &wallet_name,
                                &addr.to_string(),
                                &bk_hex,
                            );
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
             Re-run this tool later to complete the migration."
        );
        std::process::exit(0);
    }

    println!("\n  Executing Elements migration...");

    for wallet in &user_wallets {
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

        // Get the new federation's receive address from the new daemon wallet.
        let versions =
            match db::list_federation_versions_for_elements_wallet(pool, wallet.wallet_id()).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(
                        "warning: failed to list versions for Elements account {acct_idx}: {e}"
                    );
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

        // Derive the new federation's first receive address.
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
                    eprintln!(
                        "error: failed to derive address for account {acct_idx}: {e}"
                    );
                    continue;
                }
            }
        };

        match wallet
            .sweep_to(
                &dest_address,
                cfg.migration.fee_rate_sat_per_vb,
                Some(format!("federation-migration-elements-account-{acct_idx}")),
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
                    "error: sweep failed for Elements account {acct_idx}: {e}\n\
                     Continuing with remaining accounts..."
                );
                continue;
            }
        }

        // Mark old federation versions as migrated.
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
    for wallet in &user_wallets {
        let acct_idx = wallet.account_idx();
        match wallet.balance().await {
            Ok(bal) => {
                let btc = bal.trusted + bal.untrusted_pending;
                println!("  Account {acct_idx}: {btc:.8} L-BTC");
            }
            Err(e) => {
                eprintln!("warning: post-migration balance check failed for account {acct_idx}: {e}");
            }
        }
    }

    println!();
    println!("  Elements federation migration complete.");
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

    if total_balance > Amount::ZERO {
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
            .sweep_to(
                &sweep_dest,
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
