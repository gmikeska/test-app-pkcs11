//! Per-user Elements/Liquid wallet manager.
//!
//! Client-side model: each user wallet is an [`ElementsWollet`] (descriptor +
//! SLIP-77 key) whose UTXOs are captured by the shared block-scan pipeline
//! ([`crate::elements_sync`] + [`crate::elements_ingest`]) into Postgres, *not*
//! by per-user daemon wallets (which do not scale). Balance/addresses read from
//! [`PgWalletUtxoStore`]; sends build a PSET via
//! [`asterism_elements::build_spend_pset`], sign with the HSM federation, and
//! broadcast through [`RpcChainSource`].
//!
//! The `daemon_wallet_name` column is retained as a vestigial label (federation
//! history + the migration example still reference it); no daemon wallet is
//! created or queried.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use asterism_elements::descriptor::{CtDescriptorBuilder, CtKeyMode, to_multipath_string};
use asterism_elements::signer::ElementsSigner;
use asterism_elements::sync::{ElementsChainSource, KeychainKind, WalletId, WalletUtxoStore};
use asterism_elements::{
    ElementsNetwork, ElementsWollet, LwkNetwork, build_spend_pset, finalize_p2wsh_pset,
};
use sqlx::PgPool;
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

use crate::config::AppConfig;
use crate::db;
use crate::elements_rpc::{ElementsBalances, ElementsRpc, ElementsRpcError};
use crate::elements_sync::{PgWalletUtxoStore, RpcChainSource, node_lwk_network};
use crate::hsm::{HsmError, HsmFleet, SignerSet};
use crate::models::ElementsWalletRow;
use crate::wallet::NetworkPatchedSigner;

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

        let mbk = derive_master_blinding_key(user_id, row.account_idx);

        Ok(UserElementsWallet {
            user_id,
            wallet_id: row.id,
            account_idx: row.account_idx,
            network: self.network,
            lwk_net,
            descriptor: row.descriptor,
            mbk,
            daemon_wallet_name: row.daemon_wallet_name,
            signers: signers_arc,
            federation_version_count: version_count.max(1),
            pool: self.pool.clone(),
            rpc_url: self.rpc_url.clone(),
            rpc_user: self.rpc_user.clone(),
            rpc_pass: self.rpc_pass.clone(),
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
                .map(asterism_elements::CapturedUtxo::value)
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
        if count == 0 {
            return Ok(Vec::new());
        }
        let store = PgWalletUtxoStore::new(self.pool.clone());
        let wid = self.wallet_key();
        // `ElementsWollet` isn't `Send`; build it inside the blocking task.
        let desc = self.descriptor.clone();
        let mbk = self.mbk;
        let net = self.network;
        let lwk = self.lwk_net;

        tokio::task::spawn_blocking(
            move || -> Result<Vec<ElementsRevealedAddress>, ElementsWalletError> {
                let wollet = ElementsWollet::from_descriptor_str(&desc, mbk, net, lwk)
                    .map_err(|e| ElementsWalletError::Descriptor(e.to_string()))?;
                let utxos = store.list_unspent(wid).map_err(pipeline_err)?;

                let mut unspent_by_spk: HashMap<elements::Script, u64> = HashMap::new();
                for u in &utxos {
                    *unspent_by_spk.entry(u.script_pubkey().clone()).or_default() += u.value();
                }

                let mut out = Vec::with_capacity(count as usize);
                for i in 0..count {
                    let addr = wollet
                        .address(chain_kind, i)
                        .map_err(|e| ElementsWalletError::Descriptor(e.to_string()))?;
                    let spk = addr.script_pubkey();
                    #[allow(clippy::cast_precision_loss)]
                    let unspent =
                        unspent_by_spk.get(&spk).copied().unwrap_or(0) as f64 / 100_000_000.0;
                    out.push(ElementsRevealedAddress {
                        index: i,
                        address: addr.to_string(),
                        received: unspent,
                        unspent,
                    });
                }
                Ok(out)
            },
        )
        .await
        .expect("spawn_blocking join")
    }

    /// Single-version view (federation migration is a separate phase).
    pub async fn reveal_addresses_all_versions(
        &self,
        count: u32,
    ) -> Result<Vec<(usize, String, Vec<ElementsRevealedAddress>)>, ElementsWalletError> {
        let addrs = self.reveal_addresses(count).await?;
        Ok(vec![(0, self.daemon_wallet_name.clone(), addrs)])
    }

    pub async fn change_addresses_for_version(
        &self,
        count: u32,
        _descriptor: &str,
        _daemon_wallet: &str,
    ) -> Result<Vec<ElementsRevealedAddress>, ElementsWalletError> {
        self.change_addresses(count).await
    }

    /// Per-address activity from captured (unspent) UTXOs. Spent history is not
    /// retained in this coarse model, so receipts reflect current holdings.
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
                let utxos = store.list_unspent(wid).map_err(pipeline_err)?;

                let mut unspent = 0u64;
                let mut receipts = Vec::new();
                for u in utxos.iter().filter(|u| *u.script_pubkey() == target_spk) {
                    unspent += u.value();
                    let confs = tip.saturating_sub(u.height).saturating_add(1);
                    #[allow(clippy::cast_precision_loss)]
                    let amount = u.value() as f64 / 100_000_000.0;
                    receipts.push(ElementsAddressReceipt {
                        txid: u.outpoint.txid.to_string(),
                        vout: u.outpoint.vout,
                        amount,
                        confirmations: confs,
                        is_spent: false,
                    });
                }
                #[allow(clippy::cast_precision_loss)]
                let unspent_btc = unspent as f64 / 100_000_000.0;
                Ok(ElementsAddressActivity {
                    tip_height: u64::from(tip),
                    total_received: unspent_btc,
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

        let (txid, fee_sat) =
            tokio::task::spawn_blocking(move || -> Result<(String, i64), ElementsWalletError> {
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

                let chain = RpcChainSource::new(&url, &user, &pass).map_err(pipeline_err)?;
                let txid = chain
                    .broadcast(&tx)
                    .map_err(|e| ElementsWalletError::BroadcastRejected(e.to_string()))?;
                Ok((txid.to_string(), fee_sat))
            })
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
                raw_tx_hex: "",
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

        let (txid, amount_sat, fee_sat) = tokio::task::spawn_blocking(
            move || -> Result<(String, i64, i64), ElementsWalletError> {
                let wollet = ElementsWollet::from_descriptor_str(&desc, mbk, net, lwk)
                    .map_err(|e| ElementsWalletError::Descriptor(e.to_string()))?;
                let utxos = store.list_unspent(wid).map_err(pipeline_err)?;
                if utxos.is_empty() {
                    return Err(ElementsWalletError::BuildPset("no balance to sweep".into()));
                }
                let total: u64 = utxos
                    .iter()
                    .map(asterism_elements::CapturedUtxo::value)
                    .sum();
                let recipient_addr =
                    elements::Address::from_str(&recipient_owned).map_err(|e| {
                        ElementsWalletError::BadAddress {
                            addr: recipient_owned.clone(),
                            reason: e.to_string(),
                        }
                    })?;

                let blinded = asterism_elements::build_sweep_pset(
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

                let chain = RpcChainSource::new(&url, &user, &pass).map_err(pipeline_err)?;
                let txid = chain
                    .broadcast(&tx)
                    .map_err(|e| ElementsWalletError::BroadcastRejected(e.to_string()))?;
                Ok((txid.to_string(), amount_sat, fee_sat))
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
                raw_tx_hex: "",
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
    "asterism-elements-mbk-v1".hash(&mut hasher2);
    let h2 = hasher2.finish();

    let mut key = [0u8; 32];
    key[..8].copy_from_slice(&h1.to_le_bytes());
    key[8..16].copy_from_slice(&h2.to_le_bytes());
    key[16..24].copy_from_slice(&h1.to_be_bytes());
    key[24..32].copy_from_slice(&h2.to_be_bytes());
    key
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
