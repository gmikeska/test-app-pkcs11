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
    user_email: String,
    federation: NewFederationConfig,
    migration: MigrationStrategyConfig,
    #[serde(default)]
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
    #[serde(default = "default_fee_rate")]
    fee_rate_sat_per_vb: u64,
}

fn default_fee_rate() -> u64 {
    2
}

#[derive(Debug, Default, Deserialize)]
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
                config_path = Some(PathBuf::from(
                    args.get(i)
                        .ok_or_else(|| "--config requires a path argument".to_string())?,
                ));
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

fn validate_config(
    cfg: &MigrationConfig,
    app_config: &AppConfig,
) -> Result<(), String> {
    match cfg.migration.strategy.as_str() {
        "consolidation" | "address-for-address" | "batched" => {}
        other => {
            return Err(format!(
                "unrecognized migration strategy: \"{other}\"\n\
                 \n\
                 Valid strategies are:\n\
                   consolidation       — all UTXOs into a single output\n\
                   address-for-address  — preserves per-address segregation\n\
                   batched             — consolidation in fixed-size batches"
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
        .map(|l| l.as_str())
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
        println!("  Threshold:  {} -> {}", current_threshold, new_threshold);
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
    println!("  User:    {}", cfg.user_email);
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

    // -- Look up the user ---------------------------------------------------
    let user = match db::find_user_by_email(&pool, &cfg.user_email).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            eprintln!(
                "error: user \"{}\" not found in the database\n\n\
                 Available test users: test1@test.com, test2@test.com, test3@test.com",
                cfg.user_email
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("error: database lookup failed: {e}");
            std::process::exit(1);
        }
    };
    println!("  User ID: {}", user.id);

    // -- Load existing wallet -----------------------------------------------
    let wallet_manager = match WalletManager::new(pool.clone(), &app_config, hsm.clone()) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: wallet manager initialization failed: {e}");
            std::process::exit(1);
        }
    };
    let user_wallet = match wallet_manager.load_or_init(user.id).await {
        Ok(w) => w,
        Err(e) => {
            eprintln!("error: failed to load wallet for {}: {e}", cfg.user_email);
            std::process::exit(1);
        }
    };

    if let Err(e) = user_wallet.sync().await {
        eprintln!("warning: wallet sync failed (balances may be stale): {e}");
    }

    // -- Check for in-progress migrations -----------------------------------
    match db::has_in_progress_migration(&pool, user_wallet.wallet_id()).await {
        Ok(true) => {
            eprintln!(
                "error: this wallet has a migration already in progress\n\n\
                 Complete or resolve the existing migration before starting a new one."
            );
            std::process::exit(1);
        }
        Ok(false) => {}
        Err(e) => {
            eprintln!("error: migration status check failed: {e}");
            std::process::exit(1);
        }
    }

    // -- Gather current state -----------------------------------------------
    let current_fed = user_wallet.federation();
    let current_signers: Vec<(String, String)> = current_fed
        .signers()
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let id = s.id().as_str().to_string();
            let label = app_config
                .hsm_tokens
                .get(i)
                .map(|t| t.label.clone())
                .unwrap_or_else(|| format!("unknown-{i}"));
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

    let balance = user_wallet.balance().await;
    let total_balance = balance.total();

    display_migration_plan(
        &cfg.migration.strategy,
        total_balance,
        cfg.migration.fee_rate_sat_per_vb,
    );

    if dry_run {
        println!("\n  Dry run complete. No changes were made.");
        std::process::exit(0);
    }

    // =====================================================================
    // STEP 1: Confirm and apply the federation change
    // =====================================================================

    if !confirm("Step 1/3: Apply this federation change?") {
        println!("Aborted.");
        std::process::exit(0);
    }

    println!("\n  Creating new federation...");

    let account_idx = u32::try_from(user_wallet.account_idx()).unwrap_or(0);
    let path = match wallet_manager.derivation_path_for(account_idx) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: invalid derivation path: {e}");
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

    let all_signers = match hsm.signers_for(user.id, &path).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to derive signers: {e}");
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
            eprintln!("error: failed to create new federation: {e}");
            std::process::exit(1);
        }
    };

    let versions =
        match db::list_federation_versions_for_wallet(&pool, user_wallet.wallet_id()).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("error: failed to list federation versions: {e}");
                std::process::exit(1);
            }
        };
    let new_version_index = i32::try_from(versions.len()).unwrap_or(0);

    let descriptor_str = asterism_core::descriptor::to_multipath_string(
        new_federation
            .try_descriptor()
            .expect("Bitcoin federation has a descriptor"),
    );
    let snapshot = asterism_core::snapshot::FederationSnapshot::from_federation(&new_federation);
    let snapshot_json = serde_json::to_value(&snapshot).expect("snapshot serializes");

    match db::insert_federation_version(
        &pool,
        &db::NewFederationVersion {
            wallet_id: Some(user_wallet.wallet_id()),
            elements_wallet_id: None,
            version_index: new_version_index,
            descriptor: &descriptor_str,
            threshold: i32::try_from(cfg.federation.threshold).unwrap_or(0),
            signer_count: i32::try_from(cfg.federation.signers.len()).unwrap_or(0),
            federation_snapshot: &snapshot_json,
            wallet_handle: &user_wallet.wallet_id().to_string(),
            blinding_key: None,
        },
    )
    .await
    {
        Ok(_) => {}
        Err(e) => {
            eprintln!("error: failed to persist new federation version: {e}");
            std::process::exit(1);
        }
    }

    if let Err(e) = db::set_pending_migration_for_older_versions(
        &pool,
        user_wallet.wallet_id(),
        new_version_index,
    )
    .await
    {
        eprintln!("warning: failed to update migration status on old versions: {e}");
    }

    println!(
        "  Federation v{new_version_index} created ({}-of-{})",
        cfg.federation.threshold,
        cfg.federation.signers.len()
    );
    let desc_short = if descriptor_str.len() > 40 {
        format!(
            "{}...{}",
            &descriptor_str[..20],
            &descriptor_str[descriptor_str.len().saturating_sub(10)..]
        )
    } else {
        descriptor_str.clone()
    };
    println!("  Descriptor: {desc_short}");

    // =====================================================================
    // STEP 2: Confirm and execute fund migration
    // =====================================================================

    if total_balance == Amount::ZERO {
        println!("\n  No funds to migrate. Federation change is complete.");
        println!("\n  Restart the web app to pick up the new federation.");
        std::process::exit(0);
    }

    // Derive the sweep destination from the new federation's descriptor.
    let sweep_dest = {
        let desc: bdk_wallet::miniscript::Descriptor<bdk_wallet::miniscript::DescriptorPublicKey> =
            descriptor_str.parse().expect("valid descriptor");
        let mut temp_wallet = bdk_wallet::Wallet::create_from_two_path_descriptor(desc)
            .network(app_config.network)
            .create_wallet_no_persist()
            .expect("valid wallet from new descriptor");
        temp_wallet
            .reveal_next_address(bdk_wallet::KeychainKind::External)
            .address
    };

    println!();
    println!("  Balance to migrate: {total_balance}");
    println!("  Sweep destination:  {sweep_dest}");

    if !confirm("Step 2/3: Execute the fund migration?") {
        println!(
            "\n  Federation change recorded but funds NOT migrated.\n  \
             Old federation addresses still hold {total_balance}.\n  \
             Re-run this tool later to complete the migration."
        );
        std::process::exit(0);
    }

    println!("\n  Executing migration...");

    match user_wallet
        .build_sign_and_broadcast(
            &sweep_dest,
            total_balance,
            cfg.migration.fee_rate_sat_per_vb,
            Some(format!(
                "federation-migration-v{}->v{}",
                new_version_index - 1,
                new_version_index
            )),
        )
        .await
    {
        Ok(result) => {
            println!("  Sweep transaction broadcast:");
            println!("    txid:   {}", result.txid);
            println!("    amount: {} sat", result.amount_sat);
            println!("    fee:    {} sat", result.fee_sat);
        }
        Err(e) => {
            eprintln!(
                "error: sweep transaction failed: {e}\n\n\
                 The federation change has been recorded but the sweep failed.\n\
                 Old addresses still hold funds. Check connectivity and re-run."
            );
            std::process::exit(1);
        }
    }

    for v in &versions {
        if v.version_index < new_version_index {
            let _ = db::update_migration_status(&pool, v.id, "complete").await;
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

    if let Err(e) = user_wallet.sync().await {
        eprintln!("warning: post-migration sync failed: {e}");
    }

    let post_balance = user_wallet.balance().await;
    println!();
    println!("  Post-migration balance: {}", post_balance.total());
    println!();
    println!("  Federation migration complete.");
    println!("    Old: {}-of-{}", current_threshold, current_signers.len());
    println!(
        "    New: {}-of-{}",
        cfg.federation.threshold,
        cfg.federation.signers.len()
    );
    println!("    History: {} versions", new_version_index + 1);
    println!();
    println!("  Restart the web app to pick up the new federation.");
}
