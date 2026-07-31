//! Background block-ingestion service for Elements.
//!
//! A single task drives the shared [`BlockScanEngine`] over **all** Elements
//! wallets on an interval: fetch each new block once, match it against the
//! union of every wallet's watched scripts, persist captured UTXOs. This is the
//! scalable replacement for per-user daemon-wallet scanning.

use std::collections::HashMap;
use std::time::Duration;

use emvault::elements::ElementsNetwork;
use emvault::elements::ElementsWollet;
use emvault::elements::nodeless::NodelessSync;
use emvault::elements::sync::{BlockScanEngine, WalletId};
use lwk_wollet_backend::BlockchainBackend;
use sqlx::PgPool;
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::config::{AppConfig, ElementsChainBackend};
use crate::db;
use crate::elements_sync::{
    PgBlockStore, PgCheckpointStore, PgWalletUtxoStore, RpcChainSource, node_lwk_network,
};
use crate::elements_wallet::SCAN_GAP;

// LWK's `BlockchainBackend` trait is needed as a bound on the generic nodeless
// driver; alias it through the facade re-export.
mod lwk_wollet_backend {
    pub use emvault::elements::lwk_wollet::blocking::BlockchainBackend;
}

/// How often to poll the node for new blocks.
const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Spawn the background ingestion loop. Returns the task handle.
///
/// Dispatches on [`AppConfig::elements_chain_backend`]: `Rpc` drives the shared
/// [`BlockScanEngine`]; `Electrum` / `Esplora` / `Waterfalls` drive the
/// descriptor-private nodeless [`NodelessSync`] over the matching LWK client.
#[must_use]
pub fn spawn(pool: PgPool, config: &AppConfig) -> JoinHandle<()> {
    let url = config.elements_rpc_url.clone();
    let user = config.elements_rpc_user.clone();
    let pass = config.elements_rpc_password.clone();
    let network = config.elements_network;
    let backend = config.elements_chain_backend;
    let electrum_url = config.elements_electrum_url.clone();
    let esplora_url = config.elements_esplora_url.clone();

    tokio::spawn(async move {
        loop {
            let result = match backend {
                ElementsChainBackend::Rpc => run_once(&pool, &url, &user, &pass, network).await,
                _ => {
                    run_once_nodeless(
                        &pool,
                        backend,
                        electrum_url.clone(),
                        esplora_url.clone(),
                        network,
                    )
                    .await
                }
            };
            if let Err(e) = result {
                tracing::warn!(error = %e, ?backend, "Elements ingestion pass failed");
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
}

/// Load every Elements wallet's federation versions as
/// `(wallet_id, descriptor, master_blinding_key)` — one per version, so funds at
/// any version's addresses are captured under the same wallet id.
async fn load_wallet_versions(pool: &PgPool) -> Result<Vec<(WalletId, String, [u8; 32])>, String> {
    let rows = db::list_all_elements_wallets(pool)
        .await
        .map_err(|e| e.to_string())?;
    let mut wallets: Vec<(WalletId, String, [u8; 32])> = Vec::with_capacity(rows.len());
    for row in &rows {
        let wid = wallet_key(row.id);
        let versions = db::list_federation_versions_for_elements_wallet(pool, row.id)
            .await
            .map_err(|e| e.to_string())?;
        if versions.is_empty() {
            if let Some(mbk) = parse_mbk(&row.master_blinding_key) {
                wallets.push((wid, row.descriptor.clone(), mbk));
            } else {
                tracing::warn!(wallet = %row.id, "skipping wallet with malformed blinding key");
            }
            continue;
        }
        for v in &versions {
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
    Ok(wallets)
}

/// One nodeless ingestion pass (Electrum / Esplora / Waterfalls). Groups every
/// wallet's federation versions by wallet id, constructs the matching LWK client
/// once, and runs one [`NodelessSync`] scan per wallet (all versions unioned).
async fn run_once_nodeless(
    pool: &PgPool,
    backend: ElementsChainBackend,
    electrum_url: Option<String>,
    esplora_url: Option<String>,
    network: ElementsNetwork,
) -> Result<(), String> {
    let entries = load_wallet_versions(pool).await?;
    if entries.is_empty() {
        return Ok(());
    }

    let utxos = PgWalletUtxoStore::new(pool.clone());
    let checkpoints = PgCheckpointStore::new(pool.clone());

    let summary = tokio::task::spawn_blocking(move || -> Result<String, String> {
        let lwk = network.to_lwk();

        // Group descriptors by wallet id (all federation versions together).
        let mut by_wallet: HashMap<WalletId, Vec<ElementsWollet>> = HashMap::new();
        for (wid, desc, mbk) in &entries {
            match ElementsWollet::from_descriptor_str(desc, *mbk, network, lwk) {
                Ok(w) => by_wallet.entry(*wid).or_default().push(w),
                Err(e) => tracing::warn!(error = %e, "skipping wallet: descriptor build failed"),
            }
        }

        match backend {
            ElementsChainBackend::Electrum => {
                let url = electrum_url.unwrap_or_default();
                let client = NodelessSync::new_electrum(&url).map_err(|e| e.to_string())?;
                Ok(drive_nodeless(client, by_wallet, &utxos, &checkpoints))
            }
            ElementsChainBackend::Esplora => {
                let url = esplora_url.unwrap_or_default();
                let client = NodelessSync::new_esplora(&url, lwk).map_err(|e| e.to_string())?;
                Ok(drive_nodeless(client, by_wallet, &utxos, &checkpoints))
            }
            ElementsChainBackend::Waterfalls => {
                let url = esplora_url.unwrap_or_default();
                let client = NodelessSync::new_waterfalls(&url, lwk).map_err(|e| e.to_string())?;
                Ok(drive_nodeless(client, by_wallet, &utxos, &checkpoints))
            }
            ElementsChainBackend::Rpc => Ok("rpc backend not handled here".to_string()),
        }
    })
    .await
    .map_err(|e| e.to_string())??;

    tracing::info!(%summary, ?backend, "Elements nodeless ingestion pass");
    Ok(())
}

/// Sync every wallet (all versions unioned) through the given nodeless client.
/// Generic over the LWK backend so Electrum / Esplora / Waterfalls share one
/// loop.
fn drive_nodeless<B: BlockchainBackend>(
    mut client: NodelessSync<B>,
    by_wallet: HashMap<WalletId, Vec<ElementsWollet>>,
    utxos: &PgWalletUtxoStore,
    checkpoints: &PgCheckpointStore,
) -> String {
    let (mut total_upserted, mut total_spent, mut reorgs) = (0usize, 0usize, 0usize);
    for (wid, mut wollets) in by_wallet {
        match client.sync(wid, &mut wollets, utxos, checkpoints) {
            Ok(o) => {
                total_upserted += o.upserted;
                total_spent += o.spent;
                if o.reorg_to.is_some() {
                    reorgs += 1;
                }
            }
            Err(e) => tracing::warn!(error = %e, "nodeless sync failed for a wallet"),
        }
    }
    format!("unspent_upserted={total_upserted} newly_spent={total_spent} reorgs={reorgs}")
}

/// One RPC block-scan ingestion pass: load all wallets, scan new blocks, persist.
async fn run_once(
    pool: &PgPool,
    url: &str,
    user: &str,
    pass: &str,
    network: ElementsNetwork,
) -> Result<(), String> {
    let wallets = load_wallet_versions(pool).await?;
    if wallets.is_empty() {
        return Ok(());
    }
    let wallet_count = wallets.len();

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
        tracing::info!(%summary, wallets = wallet_count, "Elements ingestion pass");
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
