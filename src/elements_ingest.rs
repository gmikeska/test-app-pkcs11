//! Background block-ingestion service for Elements.
//!
//! A single task drives the shared [`BlockScanEngine`] over **all** Elements
//! wallets on an interval: fetch each new block once, match it against the
//! union of every wallet's watched scripts, persist captured UTXOs. This is the
//! scalable replacement for per-user daemon-wallet scanning.

use std::time::Duration;

use asterism_elements::ElementsNetwork;
use asterism_elements::ElementsWollet;
use asterism_elements::sync::{BlockScanEngine, WalletId};
use sqlx::PgPool;
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::config::AppConfig;
use crate::db;
use crate::elements_sync::{PgBlockStore, PgWalletUtxoStore, RpcChainSource, node_lwk_network};
use crate::elements_wallet::SCAN_GAP;

/// How often to poll the node for new blocks.
const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Spawn the background ingestion loop. Returns the task handle.
#[must_use]
pub fn spawn(pool: PgPool, config: &AppConfig) -> JoinHandle<()> {
    let url = config.elements_rpc_url.clone();
    let user = config.elements_rpc_user.clone();
    let pass = config.elements_rpc_password.clone();
    let network = config.elements_network;

    tokio::spawn(async move {
        loop {
            if let Err(e) = run_once(&pool, &url, &user, &pass, network).await {
                tracing::warn!(error = %e, "Elements block ingestion pass failed");
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
}

/// One ingestion pass: load all wallets, scan new blocks, persist UTXOs.
async fn run_once(
    pool: &PgPool,
    url: &str,
    user: &str,
    pass: &str,
    network: ElementsNetwork,
) -> Result<(), String> {
    let rows = db::list_all_elements_wallets(pool)
        .await
        .map_err(|e| e.to_string())?;
    if rows.is_empty() {
        return Ok(());
    }

    // (wallet_id, descriptor, master_blinding_key_bytes) — one entry per
    // federation *version* of each wallet, so funds at any version's addresses
    // (e.g. the new federation after a migration) are captured under the same
    // wallet id.
    let mut wallets: Vec<(WalletId, String, [u8; 32])> = Vec::with_capacity(rows.len());
    for row in &rows {
        let wid = wallet_key(row.id);
        let versions = db::list_federation_versions_for_elements_wallet(pool, row.id)
            .await
            .map_err(|e| e.to_string())?;
        if versions.is_empty() {
            // No recorded versions — watch the wallet's stored descriptor.
            if let Some(mbk) = parse_mbk(&row.master_blinding_key) {
                wallets.push((wid, row.descriptor.clone(), mbk));
            } else {
                tracing::warn!(wallet = %row.id, "skipping wallet with malformed blinding key");
            }
            continue;
        }
        for v in &versions {
            // Each version's blinding key (rotation-aware); fall back to the
            // wallet's stored key if a version row lacks one.
            let mbk = v
                .blinding_key
                .as_deref()
                .and_then(parse_mbk)
                .or_else(|| parse_mbk(&row.master_blinding_key));
            if let Some(mbk) = mbk {
                wallets.push((wid, v.descriptor.clone(), mbk));
            } else {
                tracing::warn!(
                    wallet = %row.id, version = v.version_index,
                    "skipping federation version with malformed blinding key"
                );
            }
        }
    }

    // Stores capture the runtime Handle here (async context); the engine runs
    // on a blocking thread.
    let blocks = PgBlockStore::new(pool.clone());
    let utxos = PgWalletUtxoStore::new(pool.clone());
    let url = url.to_string();
    let user = user.to_string();
    let pass = pass.to_string();

    let summary = tokio::task::spawn_blocking(move || -> Result<(u32, String), String> {
        let chain = RpcChainSource::new(&url, &user, &pass).map_err(|e| e.to_string())?;
        let lwk = node_lwk_network(&chain, network).map_err(|e| e.to_string())?;

        // Build wollets (not Send → constructed on this thread) and keep them
        // alive for the engine's borrow.
        let mut built: Vec<(WalletId, ElementsWollet)> = Vec::with_capacity(wallets.len());
        for (wid, desc, mbk) in &wallets {
            match ElementsWollet::from_descriptor_str(desc, *mbk, network, lwk) {
                Ok(w) => built.push((*wid, w)),
                Err(e) => tracing::warn!(error = %e, "skipping wallet: descriptor build failed"),
            }
        }

        let mut engine = BlockScanEngine::new();
        for (wid, w) in &built {
            engine
                .register_wallet(*wid, w, SCAN_GAP)
                .map_err(|e| e.to_string())?;
        }
        let s = engine
            .sync(&chain, &blocks, &utxos)
            .map_err(|e| e.to_string())?;
        Ok((
            s.blocks_scanned,
            format!(
                "scanned={} captured={} spent={} skipped_unblindable={} reorg_to={:?}",
                s.blocks_scanned,
                s.utxos_captured,
                s.utxos_spent,
                s.skipped_unblindable,
                s.reorg_to
            ),
        ))
    })
    .await
    .map_err(|e| e.to_string())??;

    let (blocks_scanned, summary) = summary;
    if blocks_scanned > 0 {
        tracing::info!(%summary, wallets = rows.len(), "Elements ingestion pass");
    }
    Ok(())
}

fn wallet_key(id: Uuid) -> WalletId {
    WalletId::from_bytes(*id.as_bytes())
}

fn parse_mbk(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}
