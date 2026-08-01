//! Per-user Elements/Liquid wallet manager.
//!
//! Client-side model: each user wallet is an [`ElementsWollet`] (descriptor +
//! SLIP-77 key) whose UTXOs are captured by the shared block-scan pipeline
//! ([`crate::elements_sync`] + [`crate::elements_ingest`]) into Postgres, *not*
//! by per-user daemon wallets (which do not scale). Balance/addresses read from
//! [`PgWalletUtxoStore`]; sends build a PSET via
//! [`emvault::elements::build_spend_pset`], sign with the HSM federation, and
//! broadcast through [`RpcChainSource`].
//!
//! The `daemon_wallet_name` column is retained as a vestigial label (federation
//! history + the migration example still reference it); no daemon wallet is
//! created or queried.

use emvault::core::bitcoin;
use emvault::elements::elements;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use emvault::config::hex_encode;
use emvault::elements::descriptor::{CtDescriptorBuilder, CtKeyMode, to_multipath_string};
use emvault::elements::nodeless::{NodelessSync, TokenProvider};
use emvault::elements::signer::ElementsSigner;
use emvault::elements::sync::{ElementsChainSource, KeychainKind, WalletId, WalletUtxoStore};
use emvault::elements::{
    ElementsNetwork, ElementsWollet, LwkNetwork, build_spend_pset, finalize_p2wsh_pset,
};
use sqlx::PgPool;
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

use crate::config::{AppConfig, ElementsChainBackend};
use crate::db;
use crate::elements_sync::{PgWalletUtxoStore, RpcChainSource, node_lwk_network};
use crate::hsm::{HsmError, HsmFleet, SignerSet};
use crate::models::ElementsWalletRow;
use crate::wallet::NetworkPatchedSigner;
use emvault::elements::rpc::{ElementsBalances, ElementsRpc, ElementsRpcError};

#[allow(dead_code)]
pub const REVEAL_COUNT: u32 = 20;

/// Gap limit for the capture pipeline — derive this many external + internal
/// scripts per wallet to watch.
pub const SCAN_GAP: u32 = 100;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub enum ElementsWalletError {
    #[error("Elements wallet for user `{0}` not found")]
    NotFound(Uuid),
    #[error("address `{addr}` is not valid: {reason}")]
    BadAddress { addr: String, reason: String },
    #[error("invalid fee rate `{sat_per_vb}` sat/vB")]
    BadFeeRate { sat_per_vb: u64 },
    #[error("invalid amount `{amount}`: {reason}")]
    BadAmount { amount: String, reason: String },
    #[error("PSET construction failed: {0}")]
    BuildPset(String),
    #[error("PSET signing error: {0}")]
    Sign(String),
    #[error("PSET finalization failed: {0}")]
    Finalize(String),
    #[error("Elements daemon rejected broadcast: {0}")]
    BroadcastRejected(String),
    #[error("Elements RPC error: {0}")]
    Rpc(#[from] ElementsRpcError),
    #[error("descriptor builder error: {0}")]
    Descriptor(String),
    #[error("block-scan pipeline error: {0}")]
    Pipeline(String),
    #[error("HSM error: {0}")]
    Hsm(#[from] HsmError),
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("config error: {0}")]
    Config(#[from] crate::config::ConfigError),
}

/// Broadcast a finalized Elements transaction through the wallet's configured
/// backend: a descriptor-private nodeless client (Electrum / Esplora /
/// Waterfalls) or the elementsd JSON-RPC. Called from a blocking context.
///
/// Public so the federation-migration tool broadcasts sweeps through the same
/// backend as normal sends, instead of hardcoding elementsd JSON-RPC (which
/// breaks nodeless Electrum/Esplora/Waterfalls deployments).
///
/// # Errors
/// Backend/broadcast errors propagate as [`ElementsWalletError`].
pub fn broadcast_via_backend(
    backend: ElementsChainBackend,
    electrum_url: Option<&str>,
    esplora_url: Option<&str>,
    esplora_auth: Option<&TokenProvider>,
    lwk: LwkNetwork,
    rpc: (&str, &str, &str),
    tx: &elements::Transaction,
) -> Result<elements::Txid, ElementsWalletError> {
    let brx = |e: String| ElementsWalletError::BroadcastRejected(e);
    match backend {
        ElementsChainBackend::Electrum => {
            let url = electrum_url.ok_or_else(|| brx("ELEMENTS_ELECTRUM_URL not set".into()))?;
            NodelessSync::new_electrum(url)
                .map_err(|e| brx(e.to_string()))?
                .broadcast(tx)
                .map_err(|e| brx(e.to_string()))
        }
        ElementsChainBackend::Esplora => {
            let url = esplora_url.ok_or_else(|| brx("ELEMENTS_ESPLORA_URL not set".into()))?;
            match esplora_auth {
                Some(token) => NodelessSync::new_esplora_authenticated(url, lwk, token.clone()),
                None => NodelessSync::new_esplora(url, lwk),
            }
            .map_err(|e| brx(e.to_string()))?
            .broadcast(tx)
            .map_err(|e| brx(e.to_string()))
        }
        ElementsChainBackend::Waterfalls => {
            let url = esplora_url.ok_or_else(|| brx("ELEMENTS_ESPLORA_URL not set".into()))?;
            match esplora_auth {
                Some(token) => NodelessSync::new_waterfalls_authenticated(url, lwk, token.clone()),
                None => NodelessSync::new_waterfalls(url, lwk),
            }
            .map_err(|e| brx(e.to_string()))?
            .broadcast(tx)
            .map_err(|e| brx(e.to_string()))
        }
        ElementsChainBackend::Rpc => {
            let chain = RpcChainSource::new(rpc.0, rpc.1, rpc.2).map_err(pipeline_err)?;
            chain.broadcast(tx).map_err(|e| brx(e.to_string()))
        }
    }
}

fn pipeline_err<E: std::fmt::Display>(e: E) -> ElementsWalletError {
    ElementsWalletError::Pipeline(e.to_string())
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

pub struct ElementsWalletManager {
    pool: PgPool,
    rpc: Arc<ElementsRpc>,
    rpc_url: String,
    rpc_user: String,
    rpc_pass: String,
    network: ElementsNetwork,
    /// Which backend the Elements wallet syncs/broadcasts through.
    elements_backend: ElementsChainBackend,
    /// Electrum URL when `elements_backend` is `Electrum`.
    electrum_url: Option<String>,
    /// Esplora URL when `elements_backend` is `Esplora` / `Waterfalls`.
    esplora_url: Option<String>,
    /// Optional bearer auth for the Esplora/Waterfalls backend (enterprise).
    esplora_auth: Option<TokenProvider>,
    /// Cached concrete LWK network (node policy asset + genesis for regtest).
    lwk_net: AsyncMutex<Option<LwkNetwork>>,
    bip48_coin_index: u32,
    fed_threshold: u32,
    fed_signer_indices: Vec<usize>,
    hsm: Arc<HsmFleet>,
    cache: AsyncMutex<HashMap<Uuid, Arc<UserElementsWallet>>>,
}

#[allow(dead_code)]
impl ElementsWalletManager {
    pub fn new(pool: PgPool, config: &AppConfig, hsm: Arc<HsmFleet>) -> Self {
        let rpc = Arc::new(ElementsRpc::new(
            &config.elements_rpc_url,
            &config.elements_rpc_user,
            &config.elements_rpc_password,
        ));
        Self {
            pool,
            rpc,
            rpc_url: config.elements_rpc_url.clone(),
            rpc_user: config.elements_rpc_user.clone(),
            rpc_pass: config.elements_rpc_password.clone(),
            network: config.elements_network,
            elements_backend: config.elements_chain_backend,
            electrum_url: config.elements_electrum_url.clone(),
            esplora_url: config.elements_esplora_url.clone(),
            esplora_auth: config.elements_esplora_auth.clone(),
            lwk_net: AsyncMutex::new(None),
            bip48_coin_index: config.bip48_coin_index,
            fed_threshold: config.fed_threshold,
            fed_signer_indices: config.fed_signer_indices.clone(),
            hsm,
            cache: AsyncMutex::new(HashMap::new()),
        }
    }

    pub fn network(&self) -> ElementsNetwork {
        self.network
    }

    pub fn rpc(&self) -> &Arc<ElementsRpc> {
        &self.rpc
    }

    /// Resolve (and cache) the concrete LWK network from the node.
    pub async fn lwk_network(&self) -> Result<LwkNetwork, ElementsWalletError> {
        if let Some(n) = *self.lwk_net.lock().await {
            return Ok(n);
        }
        let (url, user, pass, net) = (
            self.rpc_url.clone(),
            self.rpc_user.clone(),
            self.rpc_pass.clone(),
            self.network,
        );
        let n = tokio::task::spawn_blocking(move || -> Result<LwkNetwork, ElementsWalletError> {
            let chain = RpcChainSource::new(&url, &user, &pass).map_err(pipeline_err)?;
            node_lwk_network(&chain, net).map_err(pipeline_err)
        })
        .await
        .expect("spawn_blocking join")?;
        *self.lwk_net.lock().await = Some(n);
        Ok(n)
    }

    pub fn derivation_path_for(
        &self,
        account_idx: u32,
    ) -> Result<bitcoin::bip32::DerivationPath, ElementsWalletError> {
        let parts = [
            bitcoin::bip32::ChildNumber::from_hardened_idx(48)
                .map_err(|e| ElementsWalletError::Sign(format!("48': {e}")))?,
            bitcoin::bip32::ChildNumber::from_hardened_idx(self.bip48_coin_index)
                .map_err(|e| ElementsWalletError::Sign(format!("coin: {e}")))?,
            bitcoin::bip32::ChildNumber::from_hardened_idx(account_idx)
                .map_err(|e| ElementsWalletError::Sign(format!("account: {e}")))?,
            bitcoin::bip32::ChildNumber::from_hardened_idx(2)
                .map_err(|e| ElementsWalletError::Sign(format!("script-type: {e}")))?,
        ];
        Ok(bitcoin::bip32::DerivationPath::from(parts.to_vec()))
    }

    pub async fn load_or_init(
        &self,
        user_id: Uuid,
    ) -> Result<Arc<UserElementsWallet>, ElementsWalletError> {
        if let Some(uw) = self.cache.lock().await.get(&user_id).cloned() {
            return Ok(uw);
        }
        let row = match db::find_elements_wallet_for_user(&self.pool, user_id).await? {
            Some(r) => r,
            None => self.create_wallet_for_user(user_id).await?,
        };
        let uw = Arc::new(self.build_user_wallet(user_id, row).await?);
        let mut cache = self.cache.lock().await;
        Ok(cache.entry(user_id).or_insert(uw).clone())
    }

    pub async fn ensure_wallet_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<ElementsWalletRow, ElementsWalletError> {
        if let Some(row) = db::find_elements_wallet_for_user(&self.pool, user_id).await? {
            return Ok(row);
        }
        self.create_wallet_for_user(user_id).await
    }

    pub async fn ensure_wallet_for_user_at(
        &self,
        user_id: Uuid,
        account_idx: i32,
    ) -> Result<ElementsWalletRow, ElementsWalletError> {
        if let Some(row) = db::find_elements_wallet_for_user(&self.pool, user_id).await? {
            return Ok(row);
        }
        self.create_wallet_for_user_at(user_id, account_idx).await
    }

    async fn create_wallet_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<ElementsWalletRow, ElementsWalletError> {
        let account_idx = db::next_elements_account_idx(&self.pool).await?;
        self.create_wallet_for_user_at(user_id, account_idx).await
    }

    /// Build the descriptor + blinding key and persist the wallet row. No
    /// daemon wallet is created — capture is handled by the shared pipeline.
    async fn create_wallet_for_user_at(
        &self,
        user_id: Uuid,
        account_idx: i32,
    ) -> Result<ElementsWalletRow, ElementsWalletError> {
        let account_idx_u32 = u32::try_from(account_idx).unwrap_or(0);
        let path = self.derivation_path_for(account_idx_u32)?;

        let all_signers = self.hsm.signers_for(user_id, &path).await?;
        let patched: Vec<NetworkPatchedSigner> = self
            .fed_signer_indices
            .iter()
            .map(|&idx| NetworkPatchedSigner::new(all_signers[idx].clone(), self.hsm.network()))
            .collect();

        let mbk = derive_master_blinding_key(user_id, account_idx);
        let mbk_hex = hex_encode(&mbk);

        let mut builder = CtDescriptorBuilder::new(self.fed_threshold, &mbk)
            .map_err(|e| ElementsWalletError::Descriptor(e.to_string()))?
            .key_mode(CtKeyMode::Ranged);
        for signer in &patched {
            builder
                .add_signer(signer)
                .map_err(|e| ElementsWalletError::Descriptor(e.to_string()))?;
        }
        let ct_desc = builder
            .build()
            .map_err(|e| ElementsWalletError::Descriptor(e.to_string()))?;
        let multipath = to_multipath_string(&ct_desc);

        // Vestigial label; no daemon wallet is created.
        let daemon_wallet_name = format!("elements-user-{account_idx}");

        let row = db::insert_elements_wallet(
            &self.pool,
            &db::NewElementsWallet {
                user_id,
                account_idx,
                descriptor: &multipath,
                master_blinding_key: &mbk_hex,
                daemon_wallet_name: &daemon_wallet_name,
            },
        )
        .await?;

        tracing::info!(
            %user_id,
            account_idx = row.account_idx,
            "created client-side Elements wallet"
        );
        Ok(row)
    }

    pub async fn load_wallet_from_row(
        &self,
        row: ElementsWalletRow,
    ) -> Result<UserElementsWallet, ElementsWalletError> {
        self.build_user_wallet(row.user_id, row).await
    }

    async fn build_user_wallet(
        &self,
        user_id: Uuid,
        row: ElementsWalletRow,
    ) -> Result<UserElementsWallet, ElementsWalletError> {
        let account_idx_u32 = u32::try_from(row.account_idx).unwrap_or(0);
        let path = self.derivation_path_for(account_idx_u32)?;
        let signers_arc = self.hsm.signers_for(user_id, &path).await?;
        let lwk_net = self.lwk_network().await?;

        // Record the initial federation version if not already stored.
        let versions = db::list_federation_versions_for_elements_wallet(&self.pool, row.id).await?;
        let version_count = versions.len();
        if version_count == 0 {
            let signer_count = i32::try_from(self.fed_signer_indices.len()).unwrap_or(0);
            let threshold = i32::try_from(self.fed_threshold).unwrap_or(0);
            let snapshot = serde_json::json!({ "descriptor": row.descriptor });
            let _ = db::insert_federation_version(
                &self.pool,
                &db::NewFederationVersion {
                    wallet_id: None,
                    elements_wallet_id: Some(row.id),
                    version_index: 0,
                    descriptor: &row.descriptor,
                    threshold,
                    signer_count,
                    federation_snapshot: &snapshot,
                    wallet_handle: &row.daemon_wallet_name,
                    blinding_key: Some(&row.master_blinding_key),
                },
            )
            .await
            .ok();
        }

        let base_mbk = derive_master_blinding_key(user_id, row.account_idx);

        // Rebind to the CURRENT federation, like the Bitcoin path (Anomaly #1).
        // The migration tool records a new Elements federation version but never
        // updates `elements_wallets.descriptor`, so a naive load pins the wallet
        // (used for balance + Send) to the OLD federation while the swept funds
        // live at the new-federation addresses — leaving migrated Liquid
        // unspendable ("script pubkey didn't match the descriptor"). When the
        // latest stored version's descriptor differs from the row, adopt it (and
        // its blinding key, in case it was rotated) and re-persist the row.
        let (descriptor, mbk, drifted) = match versions.last() {
            Some(latest) if latest.descriptor != row.descriptor => {
                let cur_mbk = latest
                    .blinding_key
                    .as_deref()
                    .and_then(parse_mbk_hex)
                    .unwrap_or(base_mbk);
                (latest.descriptor.clone(), cur_mbk, true)
            }
            _ => (row.descriptor.clone(), base_mbk, false),
        };
        if drifted {
            let blinding_hex = versions
                .last()
                .and_then(|v| v.blinding_key.clone())
                .unwrap_or_else(|| row.master_blinding_key.clone());
            if let Err(e) = db::update_elements_wallet_descriptor(
                &self.pool,
                row.id,
                &descriptor,
                &blinding_hex,
            )
            .await
            {
                tracing::warn!(wallet_id = %row.id, error = %e, "failed to persist Elements descriptor self-heal");
            }
            tracing::warn!(
                wallet_id = %row.id,
                account_idx = row.account_idx,
                old_descriptor = %row.descriptor,
                new_descriptor = %descriptor,
                "self-healed post-migration Elements descriptor drift: rebound to \
                 current federation so swept funds are spendable"
            );
        }

        Ok(UserElementsWallet {
            user_id,
            wallet_id: row.id,
            account_idx: row.account_idx,
            network: self.network,
            lwk_net,
            descriptor,
            mbk,
            daemon_wallet_name: row.daemon_wallet_name,
            signers: signers_arc,
            federation_version_count: version_count.max(1),
            pool: self.pool.clone(),
            rpc_url: self.rpc_url.clone(),
            rpc_user: self.rpc_user.clone(),
            rpc_pass: self.rpc_pass.clone(),
            elements_backend: self.elements_backend,
            electrum_url: self.electrum_url.clone(),
            esplora_url: self.esplora_url.clone(),
            esplora_auth: self.esplora_auth.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// View structs (unchanged API for the handlers)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ElementsRevealedAddress {
    pub index: u32,
    pub address: String,
    pub received: f64,
    pub unspent: f64,
}

#[derive(Debug, Clone)]
pub struct ElementsAddressReceipt {
    pub txid: String,
    pub vout: u32,
    pub amount: f64,
    pub confirmations: u32,
    pub is_spent: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ElementsAddressActivity {
    pub tip_height: u64,
    pub total_received: f64,
    pub unspent: f64,
    pub receipts: Vec<ElementsAddressReceipt>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ElementsBroadcastTransaction {
    pub txid: String,
    pub recipient: String,
    pub amount_sat: i64,
    pub fee_sat: i64,
}

pub struct UserElementsWallet {
    user_id: Uuid,
    wallet_id: Uuid,
    account_idx: i32,
    network: ElementsNetwork,
    lwk_net: LwkNetwork,
    descriptor: String,
    mbk: [u8; 32],
    daemon_wallet_name: String,
    signers: SignerSet,
    federation_version_count: usize,
    pool: PgPool,
    rpc_url: String,
    rpc_user: String,
    rpc_pass: String,
    elements_backend: ElementsChainBackend,
    electrum_url: Option<String>,
    esplora_url: Option<String>,
    esplora_auth: Option<TokenProvider>,
}

impl UserElementsWallet {
    fn wallet_key(&self) -> WalletId {
        WalletId::from_bytes(*self.wallet_id.as_bytes())
    }

    fn rpc_cfg(&self) -> (String, String, String) {
        (
            self.rpc_url.clone(),
            self.rpc_user.clone(),
            self.rpc_pass.clone(),
        )
    }
}

#[allow(dead_code)]
impl UserElementsWallet {
    #[must_use]
    pub fn user_id(&self) -> Uuid {
        self.user_id
    }
    #[must_use]
    pub fn wallet_id(&self) -> Uuid {
        self.wallet_id
    }
    #[must_use]
    pub fn network(&self) -> ElementsNetwork {
        self.network
    }
    #[must_use]
    pub fn account_idx(&self) -> i32 {
        self.account_idx
    }
    #[must_use]
    pub fn descriptor(&self) -> &str {
        &self.descriptor
    }
    #[must_use]
    pub fn federation_version_count(&self) -> usize {
        self.federation_version_count
    }
    #[must_use]
    pub fn daemon_wallet_name(&self) -> &str {
        &self.daemon_wallet_name
    }

    /// The concrete LWK network (node policy asset + genesis).
    #[must_use]
    pub fn lwk_network(&self) -> LwkNetwork {
        self.lwk_net
    }

    /// This wallet's 32-byte SLIP-77 master blinding key.
    #[must_use]
    pub fn master_blinding_key(&self) -> [u8; 32] {
        self.mbk
    }

    /// A clone of this wallet's HSM signer set (for migration signing).
    #[must_use]
    pub fn signer_set(&self) -> SignerSet {
        self.signers.clone()
    }

    /// All unspent captured UTXOs for this wallet (from the block-scan store).
    pub async fn captured_utxos(
        &self,
    ) -> Result<Vec<emvault::elements::CapturedUtxo>, ElementsWalletError> {
        let store = PgWalletUtxoStore::new(self.pool.clone());
        let wid = self.wallet_key();
        tokio::task::spawn_blocking(move || store.list_unspent(wid).map_err(pipeline_err))
            .await
            .expect("spawn_blocking join")
    }

    pub async fn tip_height(&self) -> Result<u64, ElementsWalletError> {
        let (url, user, pass) = self.rpc_cfg();
        let h = tokio::task::spawn_blocking(move || -> Result<u32, ElementsWalletError> {
            let chain = RpcChainSource::new(&url, &user, &pass).map_err(pipeline_err)?;
            chain.tip_height().map_err(pipeline_err)
        })
        .await
        .expect("spawn_blocking join")?;
        Ok(u64::from(h))
    }

    /// Balance from captured UTXOs (all confirmed → "trusted"). Mempool is not
    /// tracked, so `untrusted_pending`/`immature` are zero.
    pub async fn balance(&self) -> Result<ElementsBalances, ElementsWalletError> {
        let store = PgWalletUtxoStore::new(self.pool.clone());
        let wid = self.wallet_key();
        let sats = tokio::task::spawn_blocking(move || -> Result<u64, ElementsWalletError> {
            Ok(store
                .list_unspent(wid)
                .map_err(pipeline_err)?
                .iter()
                .map(emvault::elements::CapturedUtxo::value)
                .sum())
        })
        .await
        .expect("spawn_blocking join")?;
        #[allow(clippy::cast_precision_loss)]
        let btc = sats as f64 / 100_000_000.0;
        Ok(ElementsBalances {
            trusted: btc,
            untrusted_pending: 0.0,
            immature: 0.0,
        })
    }

    pub async fn reveal_addresses(
        &self,
        count: u32,
    ) -> Result<Vec<ElementsRevealedAddress>, ElementsWalletError> {
        self.derive_addresses(count, KeychainKind::External).await
    }

    pub async fn change_addresses(
        &self,
        count: u32,
    ) -> Result<Vec<ElementsRevealedAddress>, ElementsWalletError> {
        self.derive_addresses(count, KeychainKind::Internal).await
    }

    async fn derive_addresses(
        &self,
        count: u32,
        chain_kind: KeychainKind,
    ) -> Result<Vec<ElementsRevealedAddress>, ElementsWalletError> {
        self.derive_addresses_for_descriptor(count, chain_kind, self.descriptor.clone(), self.mbk)
            .await
    }

    /// Derive `count` addresses on `chain_kind` for an arbitrary descriptor
    /// (any federation version), annotated with each address's unspent balance
    /// from the captured-UTXO store. Address derivation uses the descriptor's
    /// embedded SLIP-77 key, so `mbk` need only be valid 32 bytes.
    async fn derive_addresses_for_descriptor(
        &self,
        count: u32,
        chain_kind: KeychainKind,
        descriptor: String,
        mbk: [u8; 32],
    ) -> Result<Vec<ElementsRevealedAddress>, ElementsWalletError> {
        if count == 0 {
            return Ok(Vec::new());
        }
        let store = PgWalletUtxoStore::new(self.pool.clone());
        let wid = self.wallet_key();
        let net = self.network;
        let lwk = self.lwk_net;

        tokio::task::spawn_blocking(
            move || -> Result<Vec<ElementsRevealedAddress>, ElementsWalletError> {
                let utxos = store.list_for_wallet(wid).map_err(pipeline_err)?;
                let (received, unspent) = balances_by_spk(&utxos);
                derive_with_balances(
                    &descriptor,
                    mbk,
                    net,
                    lwk,
                    count,
                    chain_kind,
                    &received,
                    &unspent,
                )
            },
        )
        .await
        .expect("spawn_blocking join")
    }

    /// Receive addresses grouped by federation version (newest last), each with
    /// per-address unspent balances — this is what drives the multi-federation
    /// tabs on the receive page. Returns `(version_index, wallet_handle, addrs)`.
    pub async fn reveal_addresses_all_versions(
        &self,
        count: u32,
    ) -> Result<Vec<(usize, String, Vec<ElementsRevealedAddress>)>, ElementsWalletError> {
        let versions =
            db::list_federation_versions_for_elements_wallet(&self.pool, self.wallet_id).await?;
        if versions.is_empty() {
            let addrs = self.reveal_addresses(count).await?;
            return Ok(vec![(0, self.daemon_wallet_name.clone(), addrs)]);
        }

        // (version_index, wallet_handle, descriptor, mbk)
        let specs: Vec<(usize, String, String, [u8; 32])> = versions
            .iter()
            .map(|v| {
                let mbk = v
                    .blinding_key
                    .as_deref()
                    .and_then(parse_mbk_hex)
                    .unwrap_or(self.mbk);
                (
                    usize::try_from(v.version_index).unwrap_or(0),
                    v.wallet_handle.clone(),
                    v.descriptor.clone(),
                    mbk,
                )
            })
            .collect();

        let store = PgWalletUtxoStore::new(self.pool.clone());
        let wid = self.wallet_key();
        let net = self.network;
        let lwk = self.lwk_net;
        tokio::task::spawn_blocking(
            move || -> Result<Vec<(usize, String, Vec<ElementsRevealedAddress>)>, ElementsWalletError> {
                let utxos = store.list_for_wallet(wid).map_err(pipeline_err)?;
                let (received, unspent) = balances_by_spk(&utxos);
                let mut groups = Vec::with_capacity(specs.len());
                for (vidx, handle, desc, mbk) in specs {
                    let addrs = derive_with_balances(
                        &desc, mbk, net, lwk, count, KeychainKind::External, &received, &unspent,
                    )?;
                    groups.push((vidx, handle, addrs));
                }
                Ok(groups)
            },
        )
        .await
        .expect("spawn_blocking join")
    }

    /// Change addresses for a specific federation version's descriptor.
    pub async fn change_addresses_for_version(
        &self,
        count: u32,
        descriptor: &str,
        _daemon_wallet: &str,
    ) -> Result<Vec<ElementsRevealedAddress>, ElementsWalletError> {
        // Address derivation only needs the descriptor's embedded SLIP-77 key.
        self.derive_addresses_for_descriptor(
            count,
            KeychainKind::Internal,
            descriptor.to_string(),
            [0u8; 32],
        )
        .await
    }

    /// Per-address activity from captured UTXOs (spent and unspent), so
    /// "total received" reflects history even after the funds were spent (e.g.
    /// migrated to a new federation).
    pub async fn address_history(
        &self,
        address: &str,
    ) -> Result<ElementsAddressActivity, ElementsWalletError> {
        let target_spk = elements::Address::from_str(address)
            .map(|a| a.script_pubkey())
            .map_err(|e| ElementsWalletError::BadAddress {
                addr: address.to_string(),
                reason: e.to_string(),
            })?;
        let store = PgWalletUtxoStore::new(self.pool.clone());
        let wid = self.wallet_key();
        let (url, user, pass) = self.rpc_cfg();

        tokio::task::spawn_blocking(
            move || -> Result<ElementsAddressActivity, ElementsWalletError> {
                let chain = RpcChainSource::new(&url, &user, &pass).map_err(pipeline_err)?;
                let tip = chain.tip_height().map_err(pipeline_err)?;
                let utxos = store.list_for_wallet(wid).map_err(pipeline_err)?;

                let mut received = 0u64;
                let mut unspent = 0u64;
                let mut receipts = Vec::new();
                for u in utxos.iter().filter(|u| *u.script_pubkey() == target_spk) {
                    received += u.value();
                    if !u.is_spent {
                        unspent += u.value();
                    }
                    let confs = tip.saturating_sub(u.height).saturating_add(1);
                    #[allow(clippy::cast_precision_loss)]
                    let amount = u.value() as f64 / 100_000_000.0;
                    receipts.push(ElementsAddressReceipt {
                        txid: u.outpoint.txid.to_string(),
                        vout: u.outpoint.vout,
                        amount,
                        confirmations: confs,
                        is_spent: u.is_spent,
                    });
                }
                #[allow(clippy::cast_precision_loss)]
                let received_btc = received as f64 / 100_000_000.0;
                #[allow(clippy::cast_precision_loss)]
                let unspent_btc = unspent as f64 / 100_000_000.0;
                Ok(ElementsAddressActivity {
                    tip_height: u64::from(tip),
                    total_received: received_btc,
                    unspent: unspent_btc,
                    receipts,
                })
            },
        )
        .await
        .expect("spawn_blocking join")
    }

    /// Build a spend from captured UTXOs, sign with the HSM federation, and
    /// broadcast.
    pub async fn build_sign_and_broadcast(
        &self,
        recipient: &str,
        amount_btc: f64,
        fee_rate_sat_vb: u64,
        label: Option<String>,
    ) -> Result<ElementsBroadcastTransaction, ElementsWalletError> {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let amount_sat = (amount_btc * 100_000_000.0).round() as u64;
        // sat/vB → sat/kvB for LWK's TxBuilder.
        #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
        let fee_rate_kvb = (fee_rate_sat_vb as f64 * 1000.0) as f32;

        let store = PgWalletUtxoStore::new(self.pool.clone());
        let wid = self.wallet_key();
        let (url, user, pass) = self.rpc_cfg();
        let desc = self.descriptor.clone();
        let mbk = self.mbk;
        let net = self.network;
        let lwk = self.lwk_net;
        let signers: Vec<_> = self.signers.iter().cloned().collect();
        let recipient_owned = recipient.to_string();
        let elements_backend = self.elements_backend;
        let electrum_url = self.electrum_url.clone();
        let esplora_url = self.esplora_url.clone();
        let esplora_auth = self.esplora_auth.clone();

        let (txid, fee_sat, raw_hex) = tokio::task::spawn_blocking(
            move || -> Result<(String, i64, String), ElementsWalletError> {
                let wollet = ElementsWollet::from_descriptor_str(&desc, mbk, net, lwk)
                    .map_err(|e| ElementsWalletError::Descriptor(e.to_string()))?;
                let utxos = store.list_unspent(wid).map_err(pipeline_err)?;
                if utxos.is_empty() {
                    return Err(ElementsWalletError::BuildPset("no spendable UTXOs".into()));
                }
                let recipient_addr =
                    elements::Address::from_str(&recipient_owned).map_err(|e| {
                        ElementsWalletError::BadAddress {
                            addr: recipient_owned.clone(),
                            reason: e.to_string(),
                        }
                    })?;

                let blinded =
                    build_spend_pset(&wollet, &utxos, &recipient_addr, amount_sat, fee_rate_kvb)
                        .map_err(|e| ElementsWalletError::BuildPset(e.to_string()))?;
                let mut pset = blinded.into_pset();

                let mut total_signed = 0usize;
                for signer in &signers {
                    total_signed += signer
                        .sign_pset(&mut pset)
                        .map_err(|e| ElementsWalletError::Sign(e.to_string()))?;
                }
                tracing::debug!(total_signed, "PSET signed by HSM federation");

                finalize_p2wsh_pset(&mut pset)
                    .map_err(|e| ElementsWalletError::Finalize(e.to_string()))?;
                let tx = pset
                    .extract_tx()
                    .map_err(|e| ElementsWalletError::Finalize(e.to_string()))?;

                // Fee = the explicit fee output (empty scriptPubKey) value.
                let fee_sat = tx
                    .output
                    .iter()
                    .find(|o| o.script_pubkey.is_empty())
                    .and_then(|o| o.value.explicit())
                    .and_then(|v| i64::try_from(v).ok())
                    .unwrap_or(0);

                let raw_hex = elements::encode::serialize_hex(&tx);
                let txid = broadcast_via_backend(
                    elements_backend,
                    electrum_url.as_deref(),
                    esplora_url.as_deref(),
                    esplora_auth.as_ref(),
                    lwk,
                    (&url, &user, &pass),
                    &tx,
                )?;
                Ok((txid.to_string(), fee_sat, raw_hex))
            },
        )
        .await
        .expect("spawn_blocking join")?;

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let amount_sat_i = (amount_btc * 100_000_000.0).round() as i64;

        db::insert_elements_transaction(
            &self.pool,
            &db::NewElementsTransaction {
                wallet_id: self.wallet_id,
                txid: &txid,
                recipient,
                amount_sat: amount_sat_i,
                fee_sat,
                raw_tx_hex: &raw_hex,
                label: label.as_deref(),
            },
        )
        .await?;

        Ok(ElementsBroadcastTransaction {
            txid,
            recipient: recipient.to_string(),
            amount_sat: amount_sat_i,
            fee_sat,
        })
    }

    /// Sweep all captured UTXOs to `recipient` (drains the wallet).
    /// Preview a Send-Max drain: the net amount (`total − fee`) a full-balance
    /// sweep to `recipient` would deliver, without signing or broadcasting.
    /// Drives the Elements Send page's **Max** button. Builds the same sweep
    /// PSET as [`Self::sweep_to`] (the fee is fixed at build time), so the
    /// previewed amount matches the sweep that follows.
    ///
    /// # Errors
    /// [`ElementsWalletError::BuildPset`] / [`ElementsWalletError::BadAddress`]
    /// as for a real sweep (including an empty balance).
    pub async fn compute_drain_amount(
        &self,
        recipient: &str,
        fee_rate_sat_vb: u64,
    ) -> Result<u64, ElementsWalletError> {
        #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
        let fee_rate_kvb = (fee_rate_sat_vb as f64 * 1000.0) as f32;
        let store = PgWalletUtxoStore::new(self.pool.clone());
        let wid = self.wallet_key();
        let desc = self.descriptor.clone();
        let mbk = self.mbk;
        let net = self.network;
        let lwk = self.lwk_net;
        let recipient_owned = recipient.to_string();

        let amount_sat =
            tokio::task::spawn_blocking(move || -> Result<u64, ElementsWalletError> {
                let wollet = ElementsWollet::from_descriptor_str(&desc, mbk, net, lwk)
                    .map_err(|e| ElementsWalletError::Descriptor(e.to_string()))?;
                let utxos = store.list_unspent(wid).map_err(pipeline_err)?;
                if utxos.is_empty() {
                    return Err(ElementsWalletError::BuildPset("no balance to sweep".into()));
                }
                let total: u64 = utxos
                    .iter()
                    .map(emvault::elements::CapturedUtxo::value)
                    .sum();
                let recipient_addr =
                    elements::Address::from_str(&recipient_owned).map_err(|e| {
                        ElementsWalletError::BadAddress {
                            addr: recipient_owned.clone(),
                            reason: e.to_string(),
                        }
                    })?;
                let blinded = emvault::elements::build_sweep_pset(
                    &wollet,
                    &utxos,
                    &recipient_addr,
                    fee_rate_kvb,
                )
                .map_err(|e| ElementsWalletError::BuildPset(e.to_string()))?;
                let pset = blinded.into_pset();
                // The fee output is the explicit, script-less output; everything
                // else is swept to the recipient.
                let fee_sat: u64 = pset
                    .outputs()
                    .iter()
                    .find(|o| o.script_pubkey.is_empty())
                    .and_then(|o| o.amount)
                    .unwrap_or(0);
                Ok(total.saturating_sub(fee_sat))
            })
            .await
            .expect("spawn_blocking join")?;
        Ok(amount_sat)
    }

    pub async fn sweep_to(
        &self,
        recipient: &str,
        fee_rate_sat_vb: u64,
        label: Option<String>,
    ) -> Result<ElementsBroadcastTransaction, ElementsWalletError> {
        #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
        let fee_rate_kvb = (fee_rate_sat_vb as f64 * 1000.0) as f32;
        let store = PgWalletUtxoStore::new(self.pool.clone());
        let wid = self.wallet_key();
        let (url, user, pass) = self.rpc_cfg();
        let desc = self.descriptor.clone();
        let mbk = self.mbk;
        let net = self.network;
        let lwk = self.lwk_net;
        let signers: Vec<_> = self.signers.iter().cloned().collect();
        let recipient_owned = recipient.to_string();
        let elements_backend = self.elements_backend;
        let electrum_url = self.electrum_url.clone();
        let esplora_url = self.esplora_url.clone();
        let esplora_auth = self.esplora_auth.clone();

        let (txid, amount_sat, fee_sat, raw_hex) = tokio::task::spawn_blocking(
            move || -> Result<(String, i64, i64, String), ElementsWalletError> {
                let wollet = ElementsWollet::from_descriptor_str(&desc, mbk, net, lwk)
                    .map_err(|e| ElementsWalletError::Descriptor(e.to_string()))?;
                let utxos = store.list_unspent(wid).map_err(pipeline_err)?;
                if utxos.is_empty() {
                    return Err(ElementsWalletError::BuildPset("no balance to sweep".into()));
                }
                let total: u64 = utxos
                    .iter()
                    .map(emvault::elements::CapturedUtxo::value)
                    .sum();
                let recipient_addr =
                    elements::Address::from_str(&recipient_owned).map_err(|e| {
                        ElementsWalletError::BadAddress {
                            addr: recipient_owned.clone(),
                            reason: e.to_string(),
                        }
                    })?;

                let blinded = emvault::elements::build_sweep_pset(
                    &wollet,
                    &utxos,
                    &recipient_addr,
                    fee_rate_kvb,
                )
                .map_err(|e| ElementsWalletError::BuildPset(e.to_string()))?;
                let mut pset = blinded.into_pset();
                for signer in &signers {
                    signer
                        .sign_pset(&mut pset)
                        .map_err(|e| ElementsWalletError::Sign(e.to_string()))?;
                }
                finalize_p2wsh_pset(&mut pset)
                    .map_err(|e| ElementsWalletError::Finalize(e.to_string()))?;
                let tx = pset
                    .extract_tx()
                    .map_err(|e| ElementsWalletError::Finalize(e.to_string()))?;
                let fee_sat = tx
                    .output
                    .iter()
                    .find(|o| o.script_pubkey.is_empty())
                    .and_then(|o| o.value.explicit())
                    .and_then(|v| i64::try_from(v).ok())
                    .unwrap_or(0);
                let amount_sat = i64::try_from(total).unwrap_or(0) - fee_sat;

                let raw_hex = elements::encode::serialize_hex(&tx);
                let txid = broadcast_via_backend(
                    elements_backend,
                    electrum_url.as_deref(),
                    esplora_url.as_deref(),
                    esplora_auth.as_ref(),
                    lwk,
                    (&url, &user, &pass),
                    &tx,
                )?;
                Ok((txid.to_string(), amount_sat, fee_sat, raw_hex))
            },
        )
        .await
        .expect("spawn_blocking join")?;

        db::insert_elements_transaction(
            &self.pool,
            &db::NewElementsTransaction {
                wallet_id: self.wallet_id,
                txid: &txid,
                recipient,
                amount_sat,
                fee_sat,
                raw_tx_hex: &raw_hex,
                label: label.as_deref(),
            },
        )
        .await?;

        Ok(ElementsBroadcastTransaction {
            txid,
            recipient: recipient.to_string(),
            amount_sat,
            fee_sat,
        })
    }

    /// Sign a PSET with this wallet's HSM signers (matching-fingerprint inputs
    /// only). Used by the federation-migration tooling.
    pub fn sign_pset_with_signers(&self, pset: &mut elements::pset::PartiallySignedTransaction) {
        for signer in self.signers.iter() {
            let _ = signer.sign_pset(pset);
        }
    }

    /// Sign only the inputs at `input_indices` with this account's HSM signers.
    ///
    /// In a cross-account migration PSET every account is signed by the *same*
    /// physical HSM tokens (same master fingerprints, different derivation
    /// paths), so a naive sign would mis-derive other accounts' inputs. We
    /// temporarily clear `bip32_derivation` on the other inputs so this
    /// account's signers skip them, then restore it — mirroring the Bitcoin
    /// `sign_migration_inputs`.
    pub fn sign_migration_pset_inputs(
        &self,
        pset: &mut elements::pset::PartiallySignedTransaction,
        input_indices: &[usize],
    ) {
        let mut saved = Vec::new();
        for (i, inp) in pset.inputs_mut().iter_mut().enumerate() {
            if !input_indices.contains(&i) {
                saved.push((i, std::mem::take(&mut inp.bip32_derivation)));
            }
        }
        for signer in self.signers.iter() {
            let _ = signer.sign_pset(pset);
        }
        for (i, derivation) in saved {
            pset.inputs_mut()[i].bip32_derivation = derivation;
        }
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn derive_master_blinding_key(user_id: Uuid, account_idx: i32) -> [u8; 32] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    user_id.hash(&mut hasher);
    account_idx.hash(&mut hasher);
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

// `hex_encode` now lives in `emvault::config` (imported above) — deduplicated
// in extraction phase E5b.

/// Parse a 64-char hex string into a 32-byte SLIP-77 master blinding key.
fn parse_mbk_hex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Per-script-pubkey totals across captured UTXOs: `(total_received, unspent)`.
/// `total_received` includes spent UTXOs (historical), `unspent` excludes them.
fn balances_by_spk(
    utxos: &[emvault::elements::CapturedUtxo],
) -> (
    HashMap<elements::Script, u64>,
    HashMap<elements::Script, u64>,
) {
    let mut received: HashMap<elements::Script, u64> = HashMap::new();
    let mut unspent: HashMap<elements::Script, u64> = HashMap::new();
    for u in utxos {
        let spk = u.script_pubkey().clone();
        *received.entry(spk.clone()).or_default() += u.value();
        if !u.is_spent {
            *unspent.entry(spk).or_default() += u.value();
        }
    }
    (received, unspent)
}

/// Derive `count` addresses for a descriptor and annotate each with its
/// historical received total and current unspent balance (in L-BTC).
fn derive_with_balances(
    descriptor: &str,
    mbk: [u8; 32],
    net: ElementsNetwork,
    lwk: LwkNetwork,
    count: u32,
    chain_kind: KeychainKind,
    received: &HashMap<elements::Script, u64>,
    unspent: &HashMap<elements::Script, u64>,
) -> Result<Vec<ElementsRevealedAddress>, ElementsWalletError> {
    let wollet = ElementsWollet::from_descriptor_str(descriptor, mbk, net, lwk)
        .map_err(|e| ElementsWalletError::Descriptor(e.to_string()))?;
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        let addr = wollet
            .address(chain_kind, i)
            .map_err(|e| ElementsWalletError::Descriptor(e.to_string()))?;
        let spk = addr.script_pubkey();
        #[allow(clippy::cast_precision_loss)]
        let received_btc = received.get(&spk).copied().unwrap_or(0) as f64 / 100_000_000.0;
        #[allow(clippy::cast_precision_loss)]
        let unspent_btc = unspent.get(&spk).copied().unwrap_or(0) as f64 / 100_000_000.0;
        out.push(ElementsRevealedAddress {
            index: i,
            address: addr.to_string(),
            received: received_btc,
            unspent: unspent_btc,
        });
    }
    Ok(out)
}
