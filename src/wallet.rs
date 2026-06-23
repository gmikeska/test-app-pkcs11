//! Per-user BDK wallet manager.
//!
//! `WalletManager` owns the Bitcoin Core RPC client and a cache of
//! `UserWallet`s. Each `UserWallet` ties a `bdk_wallet::Wallet` to one
//! user via that user's BIP-48 account index, and bundles the per-user
//! m-of-n federation built from `HsmFleet` signers.
//!
//! Concurrency model mirrors test-app-xpub:
//!
//! - `cache` is an `AsyncMutex<HashMap<Uuid, Arc<UserWallet>>>`. The
//!   mutex is held only during cache lookup / insertion, never across
//!   BDK or RPC work.
//! - `UserWallet::inner` is an `AsyncMutex<Wallet>` so concurrent
//!   requests for the same user serialize. Different users sign in
//!   parallel.

use std::collections::HashMap;
use std::sync::Arc;

use asterism_core::descriptor::{KeyMode, to_multipath_string};
use asterism_core::federated_wallet::FederatedWallet as FederatedWalletTrait;
use asterism_core::network::NetworkType;
use asterism_core::psbt::{SigningCoordinator, UnsignedPsbt};
use asterism_core::signer::{Signer, SignerCapabilities, SignerHealth, SignerId, SignerType};
use asterism_core::{BtcFederatedWallet, Federation, FederationWallet, error::SignerError};
use asterism_pkcs11::Pkcs11Signer;
use bdk_bitcoind_rpc::{Emitter, NO_EXPECTED_MEMPOOL_TXS};
use bdk_wallet::chain::{ChainPosition, Merge};
use bdk_wallet::signer::SignerOrdering;
use bdk_wallet::{AddressInfo, ChangeSet, KeychainKind, SignOptions, Wallet};
use bitcoin::address::NetworkUnchecked;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use bitcoin::consensus::Encodable;
use bitcoin::{Address, Amount, FeeRate, Network, NetworkKind, ScriptBuf, Txid};
use bitcoincore_rpc::{Auth, Client as RpcClient, RpcApi};
use sqlx::PgPool;
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

use crate::config::AppConfig;
use crate::db;
use crate::hsm::{HsmError, HsmFleet};
use crate::models::WalletRow;

/// Default reveal target: addresses 0..REVEAL_COUNT-1 are eagerly
/// surfaced on every receive-tab render.
pub const REVEAL_COUNT: u32 = 20;

// ---------------------------------------------------------------------------
// Network-patched signer wrapper
// ---------------------------------------------------------------------------

/// Adapter around [`Pkcs11Signer`] that re-stamps the xpub network kind.
///
/// The dev-shim backend (and the default `HsmBackend::read_xpub`
/// implementation) always reports an xpub with `NetworkKind::Main`,
/// while the wallet runs on `Network::Regtest`. `DescriptorBuilder`
/// rejects that mismatch with `DescriptorError::NetworkMismatch`. This
/// wrapper carries a cloned xpub with the `network` field corrected so
/// federation construction succeeds; the underlying chain code, public
/// key, and BIP-32 metadata are untouched, and the actual `cryptoki`
/// signing path runs through the inner [`Pkcs11Signer`] (registered
/// separately on `bdk_wallet::Wallet` via `add_signer`).
#[derive(Clone, Debug)]
pub struct NetworkPatchedSigner {
    inner: Pkcs11Signer,
    patched_xpub: Xpub,
}

impl NetworkPatchedSigner {
    /// Wrap `inner` with an xpub network kind matching `network`.
    #[must_use]
    pub fn new(inner: Pkcs11Signer, network: Network) -> Self {
        let mut xpub = *inner.xpub();
        xpub.network = NetworkKind::from(network);
        Self {
            inner,
            patched_xpub: xpub,
        }
    }

    /// Borrow the inner [`Pkcs11Signer`].
    #[must_use]
    #[allow(dead_code)]
    pub fn inner(&self) -> &Pkcs11Signer {
        &self.inner
    }
}

impl Signer for NetworkPatchedSigner {
    fn id(&self) -> SignerId {
        self.inner.id()
    }
    fn label(&self) -> Option<&str> {
        self.inner.label()
    }
    fn xpub(&self) -> &Xpub {
        &self.patched_xpub
    }
    fn fingerprint(&self) -> Fingerprint {
        self.inner.fingerprint()
    }
    fn derivation_path(&self) -> &DerivationPath {
        self.inner.derivation_path()
    }
    fn signer_type(&self) -> SignerType {
        self.inner.signer_type()
    }
    fn supported_networks(&self) -> Vec<NetworkType> {
        self.inner.supported_networks()
    }
    fn capabilities(&self) -> SignerCapabilities {
        self.inner.capabilities()
    }
    fn health_check(&self) -> Result<SignerHealth, SignerError> {
        self.inner.health_check()
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors raised by the wallet layer.
#[allow(dead_code)] // some variants are reserved for future endpoints
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    /// No `wallets` row for the given user.
    #[error("wallet for user `{0}` not found")]
    NotFound(Uuid),

    /// Externally-supplied address didn't parse / didn't match the
    /// wallet network.
    #[error("address `{addr}` is not a valid `{network}` address: {reason}")]
    BadAddress {
        /// Raw input.
        addr: String,
        /// Expected network.
        network: Network,
        /// Human-readable parse reason.
        reason: String,
    },

    /// User supplied a fee rate `bdk_wallet::FeeRate` rejected (zero, etc.).
    #[error("invalid fee rate `{sat_per_vb}` sat/vB")]
    BadFeeRate {
        /// Raw form value.
        sat_per_vb: u64,
    },

    /// User-supplied amount didn't parse.
    #[error("invalid amount `{amount}`: {reason}")]
    BadAmount {
        /// Raw input.
        amount: String,
        /// Parse reason.
        reason: String,
    },

    /// `Wallet::build_tx().finish()` failed (no spendable UTXOs, dust
    /// output, fee floor not met, etc.).
    #[error("transaction construction failed: {0}")]
    BuildTx(String),

    /// `SigningCoordinator` reported insufficient signatures, finalize
    /// rejection, or any other PSBT-pipeline failure.
    #[error("federation signing error: {0}")]
    Sign(String),

    /// `sendrawtransaction` rejected the broadcast.
    #[error("bitcoind rejected broadcast: {0}")]
    BroadcastRejected(String),

    /// Bitcoin Core RPC error.
    #[error("bitcoind RPC error: {0}")]
    Rpc(#[from] bitcoincore_rpc::Error),

    /// Couldn't construct the JSON-RPC client.
    #[error("failed to construct bitcoind RPC client: {0}")]
    RpcClientInit(bitcoincore_rpc::Error),

    /// JSON-encoding the merged BDK changeset failed.
    #[error("failed to JSON-encode wallet changeset: {0}")]
    EncodeChangeSet(#[source] serde_json::Error),

    /// Stored BDK changeset wouldn't deserialize.
    #[error("stored bdk_changeset for wallet `{id}` is malformed: {source}")]
    DecodeChangeSet {
        /// Wallet id.
        id: Uuid,
        /// Underlying serde error.
        #[source]
        source: serde_json::Error,
    },

    /// `Wallet::create_*` rejected the descriptor.
    #[error("BDK rejected wallet creation: {0}")]
    CreateWallet(String),

    /// `Wallet::load_wallet_no_persist` rejected the stored changeset.
    #[error("BDK rejected wallet load: {0}")]
    LoadWallet(String),

    /// Connecting a freshly-emitted block to the local chain failed.
    #[error("applying block at height {height} failed: {source}")]
    ApplyBlock {
        /// Block height we tried to apply.
        height: u32,
        /// Underlying BDK error.
        #[source]
        source: bdk_wallet::chain::local_chain::ApplyHeaderError,
    },

    /// Underlying HSM error (signer derivation, PKCS#11 calls).
    #[error("HSM error: {0}")]
    Hsm(#[from] HsmError),

    /// `DescriptorBuilder` (via `Federation`) rejected the federation.
    #[error("descriptor builder error: {0}")]
    Descriptor(#[from] asterism_core::DescriptorError),

    /// `Federation::with_key_mode` rejected the inputs.
    #[error("federation construction failed: {0}")]
    Federation(#[from] asterism_core::error::FederationError),

    /// `UnsignedPsbt::new` / `SigningCoordinator` rejected the PSBT.
    #[error("PSBT pipeline error: {0}")]
    Psbt(#[from] asterism_core::error::PsbtError),

    /// Configuration error (e.g. invalid derivation index).
    #[error("config error: {0}")]
    Config(#[from] crate::config::ConfigError),

    /// `Psbt::extract_tx` failed (only on malformed PSBTs).
    #[error("failed to extract transaction: {0}")]
    ExtractTx(String),

    /// Database error.
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

/// Cache + factory for [`UserWallet`]s.
pub struct WalletManager {
    pool: PgPool,
    rpc: Arc<RpcClient>,
    network: Network,
    bip48_coin_index: u32,
    fed_threshold: u32,
    hsm: Arc<HsmFleet>,
    cache: AsyncMutex<HashMap<Uuid, Arc<UserWallet>>>,
}

#[allow(dead_code)]
impl WalletManager {
    /// Construct the manager.
    ///
    /// # Errors
    /// [`WalletError::RpcClientInit`] if the bitcoind RPC client setup
    /// fails.
    pub fn new(pool: PgPool, config: &AppConfig, hsm: Arc<HsmFleet>) -> Result<Self, WalletError> {
        let auth = Auth::UserPass(
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        );
        let rpc =
            RpcClient::new(&config.bitcoin_rpc_url, auth).map_err(WalletError::RpcClientInit)?;
        Ok(Self {
            pool,
            rpc: Arc::new(rpc),
            network: config.network,
            bip48_coin_index: config.bip48_coin_index,
            fed_threshold: config.fed_threshold,
            hsm,
            cache: AsyncMutex::new(HashMap::new()),
        })
    }

    /// Wallet network.
    #[must_use]
    pub fn network(&self) -> Network {
        self.network
    }

    /// Compute the BIP-48 derivation path for `account_idx` given the
    /// configured coin index.
    pub fn derivation_path_for(&self, account_idx: u32) -> Result<DerivationPath, WalletError> {
        let parts = [
            bitcoin::bip32::ChildNumber::from_hardened_idx(48)
                .map_err(|e| WalletError::Sign(format!("48': {e}")))?,
            bitcoin::bip32::ChildNumber::from_hardened_idx(self.bip48_coin_index)
                .map_err(|e| WalletError::Sign(format!("coin: {e}")))?,
            bitcoin::bip32::ChildNumber::from_hardened_idx(account_idx)
                .map_err(|e| WalletError::Sign(format!("account: {e}")))?,
            bitcoin::bip32::ChildNumber::from_hardened_idx(2)
                .map_err(|e| WalletError::Sign(format!("script-type: {e}")))?,
        ];
        Ok(DerivationPath::from(parts.to_vec()))
    }

    /// Look up (or lazily build) the wallet for `user_id`.
    ///
    /// On cache miss: ensures a `wallets` row exists (creating one with
    /// the next free `account_idx` if not), pulls the user's
    /// HSM-resident signers, builds the federation, and constructs (or
    /// loads from `bdk_changeset`) the BDK wallet.
    ///
    /// # Errors
    /// See [`WalletError`].
    pub async fn load_or_init(&self, user_id: Uuid) -> Result<Arc<UserWallet>, WalletError> {
        if let Some(uw) = self.cache.lock().await.get(&user_id).cloned() {
            return Ok(uw);
        }

        let row = match db::find_wallet_for_user(&self.pool, user_id).await? {
            Some(r) => r,
            None => self.create_wallet_for_user(user_id).await?,
        };
        let uw = Arc::new(self.build_user_wallet(user_id, row).await?);
        let mut cache = self.cache.lock().await;
        Ok(cache.entry(user_id).or_insert(uw).clone())
    }

    /// Load a wallet from an existing database row. Used by the migration
    /// tool to load all wallets without going through user lookup.
    ///
    /// # Errors
    /// See [`WalletError`].
    pub async fn load_wallet_from_row(
        &self,
        row: WalletRow,
    ) -> Result<Arc<UserWallet>, WalletError> {
        let user_id = row.user_id;
        if let Some(uw) = self.cache.lock().await.get(&user_id).cloned() {
            return Ok(uw);
        }
        let uw = Arc::new(self.build_user_wallet(user_id, row).await?);
        let mut cache = self.cache.lock().await;
        Ok(cache.entry(user_id).or_insert(uw).clone())
    }

    /// Eagerly create the user's wallet row if it doesn't exist. Idempotent.
    ///
    /// Returns the (possibly pre-existing) row. Used by the boot path
    /// to seed test1/2/3 wallets so first-page-load is responsive.
    ///
    /// # Errors
    /// See [`WalletError`].
    pub async fn ensure_wallet_for_user(&self, user_id: Uuid) -> Result<WalletRow, WalletError> {
        if let Some(row) = db::find_wallet_for_user(&self.pool, user_id).await? {
            return Ok(row);
        }
        self.create_wallet_for_user(user_id).await
    }

    async fn create_wallet_for_user(&self, user_id: Uuid) -> Result<WalletRow, WalletError> {
        let account_idx = db::next_account_idx(&self.pool).await?;
        let account_idx_u32 = u32::try_from(account_idx).unwrap_or(0);
        let path = self.derivation_path_for(account_idx_u32)?;

        let signers = self.hsm.signers_for(user_id, &path).await?;
        let patched: Vec<NetworkPatchedSigner> = signers
            .iter()
            .cloned()
            .map(|s| NetworkPatchedSigner::new(s, self.network))
            .collect();
        let fed = Federation::with_key_mode(
            self.fed_threshold,
            patched,
            NetworkType::Bitcoin(self.network),
            KeyMode::Ranged,
        )?;
        let multipath = to_multipath_string(
            fed.try_descriptor()
                .expect("Bitcoin federation has a descriptor"),
        );

        let mut probe = Wallet::create_from_two_path_descriptor(multipath.clone())
            .network(self.network)
            .create_wallet_no_persist()
            .map_err(|e| WalletError::CreateWallet(e.to_string()))?;
        let initial = probe.take_staged().unwrap_or_default();
        let json = serde_json::to_value(&initial).map_err(WalletError::EncodeChangeSet)?;
        let tip = i32::try_from(probe.latest_checkpoint().height()).unwrap_or(0);

        let row = db::insert_wallet(
            &self.pool,
            &db::NewWallet {
                user_id,
                account_idx,
                descriptor: &multipath,
                bdk_changeset: &json,
                chain_tip_height: tip,
            },
        )
        .await?;
        tracing::info!(
            %user_id,
            account_idx = row.account_idx,
            descriptor = %multipath,
            "created user wallet"
        );
        Ok(row)
    }

    /// Construct a `BtcFederatedWallet` from stored federation versions, or
    /// bootstrap with the current federation if no versions are recorded yet.
    async fn build_federated_wallet(
        &self,
        wallet_id: Uuid,
        current_federation: &Federation<NetworkPatchedSigner>,
    ) -> Result<BtcFederatedWallet<NetworkPatchedSigner>, WalletError> {
        let versions = db::list_federation_versions_for_wallet(&self.pool, wallet_id).await?;

        if versions.is_empty() {
            // Bootstrap: record the current (and only) federation as version 0.
            let descriptor_str = to_multipath_string(
                current_federation
                    .try_descriptor()
                    .expect("Bitcoin federation has a descriptor"),
            );
            let snapshot = serde_json::json!({ "threshold": current_federation.threshold(), "signer_count": current_federation.total_signers() });
            let _ = db::insert_federation_version(
                &self.pool,
                &db::NewFederationVersion {
                    wallet_id: Some(wallet_id),
                    elements_wallet_id: None,
                    version_index: 0,
                    descriptor: &descriptor_str,
                    threshold: i32::try_from(current_federation.threshold()).unwrap_or(0),
                    signer_count: i32::try_from(current_federation.total_signers()).unwrap_or(0),
                    federation_snapshot: &snapshot,
                    wallet_handle: &wallet_id.to_string(),
                    blinding_key: None,
                },
            )
            .await
            .ok();

            let metadata_wallet = Self::create_metadata_wallet(current_federation, self.network)?;
            return BtcFederatedWallet::new(current_federation.clone(), metadata_wallet)
                .map_err(|e| WalletError::CreateWallet(e.to_string()));
        }

        if versions.len() == 1 {
            // Single stored version — this is the common pre-federation-change
            // case. Use the live current_federation directly rather than
            // attempting reconstruction (which requires signer discovery from
            // Phase 3 of the federation-changes plan).
            let metadata_wallet = Self::create_metadata_wallet(current_federation, self.network)?;
            return BtcFederatedWallet::new(current_federation.clone(), metadata_wallet)
                .map_err(|e| WalletError::CreateWallet(e.to_string()));
        }

        // Multi-version reconstruction: the first version initializes
        // the FederatedWallet, subsequent versions are chained via
        // with_federation(). Each version creates its own metadata wallet
        // from the stored descriptor.
        let first = &versions[0];
        let first_fed = self.reconstruct_federation_from_version(first).await?;
        let first_wallet = Self::create_metadata_wallet(&first_fed, self.network)?;
        let mut fw = BtcFederatedWallet::new(first_fed, first_wallet)
            .map_err(|e| WalletError::CreateWallet(e.to_string()))?;

        for v in &versions[1..] {
            let fed = self.reconstruct_federation_from_version(v).await?;
            let w = Self::create_metadata_wallet(&fed, self.network)?;
            fw = fw
                .with_federation(fed, w)
                .map_err(|e| WalletError::CreateWallet(e.to_string()))?;
        }

        Ok(fw)
    }

    /// Build a read-only BDK wallet from a federation's descriptor (for
    /// metadata queries — balance, UTXOs, address derivation).
    fn create_metadata_wallet(
        federation: &Federation<NetworkPatchedSigner>,
        network: Network,
    ) -> Result<Wallet, WalletError> {
        let desc = to_multipath_string(
            federation
                .try_descriptor()
                .expect("Bitcoin federation has a descriptor"),
        );
        Wallet::create_from_two_path_descriptor(desc)
            .network(network)
            .create_wallet_no_persist()
            .map_err(|e| WalletError::CreateWallet(e.to_string()))
    }

    /// Reconstruct a `Federation<NetworkPatchedSigner>` from a stored
    /// federation version row. Rebuilds signers from the HSM fleet at the
    /// stored derivation path.
    #[allow(clippy::unused_async)]
    async fn reconstruct_federation_from_version(
        &self,
        _version: &crate::models::FederationVersionRow,
    ) -> Result<Federation<NetworkPatchedSigner>, WalletError> {
        // For now, federation reconstruction from stored versions will be
        // fully implemented when federation changes are supported. The
        // stored descriptor and snapshot contain enough information to
        // rebuild the federation, but the signer-discovery path (matching
        // HSM keys to stored fingerprints) is part of the federation-changes
        // plan (Phase 1 of that plan). For the initial integration, this
        // codepath is only reached if there are stored versions, which only
        // happens once federation changes are exercised.
        Err(WalletError::CreateWallet(
            "federation reconstruction from stored versions not yet implemented \
             (single-federation path bootstraps from current state)"
                .into(),
        ))
    }

    async fn build_user_wallet(
        &self,
        user_id: Uuid,
        row: WalletRow,
    ) -> Result<UserWallet, WalletError> {
        let wallet_id = row.id;
        let account_idx = row.account_idx;
        let account_idx_u32 = u32::try_from(account_idx).unwrap_or(0);
        let path = self.derivation_path_for(account_idx_u32)?;

        let signers_arc = self.hsm.signers_for(user_id, &path).await?;
        let patched_owned: Vec<NetworkPatchedSigner> = signers_arc
            .iter()
            .cloned()
            .map(|s| NetworkPatchedSigner::new(s, self.network))
            .collect();
        let federation = Federation::with_key_mode(
            self.fed_threshold,
            patched_owned,
            NetworkType::Bitcoin(self.network),
            KeyMode::Ranged,
        )?;

        let (mut wallet, initial_changeset) = if let Some(json) = row.bdk_changeset.clone() {
            let aggregate: ChangeSet =
                serde_json::from_value(json).map_err(|source| WalletError::DecodeChangeSet {
                    id: wallet_id,
                    source,
                })?;
            let w = Wallet::load()
                .check_network(self.network)
                .load_wallet_no_persist(aggregate.clone())
                .map_err(|e| WalletError::LoadWallet(e.to_string()))?
                .ok_or_else(|| WalletError::LoadWallet("empty changeset".into()))?;
            (w, aggregate)
        } else {
            let multipath = row.descriptor.clone();
            let w = Wallet::create_from_two_path_descriptor(multipath)
                .network(self.network)
                .create_wallet_no_persist()
                .map_err(|e| WalletError::CreateWallet(e.to_string()))?;
            (w, ChangeSet::default())
        };

        // Register all Pkcs11Signers on both keychains.
        for s in signers_arc.iter() {
            let arc: Arc<Pkcs11Signer> = Arc::new(s.clone());
            wallet.add_signer(
                KeychainKind::External,
                SignerOrdering::default(),
                arc.clone(),
            );
            wallet.add_signer(KeychainKind::Internal, SignerOrdering::default(), arc);
        }

        // Build the FederatedWallet from stored federation versions, or
        // bootstrap with just the current federation if none are stored yet.
        let federated_wallet = self.build_federated_wallet(wallet_id, &federation).await?;

        Ok(UserWallet {
            user_id,
            wallet_id,
            account_idx,
            network: self.network,
            federation,
            federated_wallet,
            inner: AsyncMutex::new(wallet),
            aggregate: AsyncMutex::new(initial_changeset),
            pool: self.pool.clone(),
            rpc: self.rpc.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// UserWallet
// ---------------------------------------------------------------------------

/// View-model for an address rendered on the receive tab.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RevealedAddress {
    /// Derivation index.
    pub index: u32,
    /// Keychain (almost always External here).
    pub keychain: KeychainKind,
    /// String form of the address.
    pub address: String,
    /// Total received on this address.
    pub received: Amount,
    /// Currently unspent on this address.
    pub unspent: Amount,
}

/// Single confirmed/unconfirmed UTXO that paid into a specific address.
#[derive(Debug, Clone)]
pub struct AddressReceipt {
    /// Transaction id of the payment.
    pub txid: Txid,
    /// Output index within the transaction.
    pub vout: u32,
    /// Output amount.
    pub amount: Amount,
    /// `Some(height)` if confirmed, `None` if still in mempool.
    pub confirmation_height: Option<u32>,
    /// Confirmations relative to the wallet's current chain tip.
    pub confirmations: u32,
    /// Whether this output has been spent in a tracked transaction.
    pub is_spent: bool,
}

/// Summary of an address's history.
#[derive(Debug, Clone)]
pub struct AddressActivity {
    /// Wallet's chain tip height.
    pub tip_height: u32,
    /// Sum of all values received at this address.
    pub total_received: Amount,
    /// Sum of unspent value at this address.
    pub unspent: Amount,
    /// Confirmed-first list of payments.
    pub receipts: Vec<AddressReceipt>,
}

/// Result of a successful build/sign/broadcast cycle.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct BroadcastTransaction {
    /// Broadcast txid.
    pub txid: Txid,
    /// Recipient address (input form).
    pub recipient: String,
    /// Amount sent in satoshis (recipient output).
    pub amount_sat: i64,
    /// Fee paid in satoshis.
    pub fee_sat: i64,
}

/// Summary of one sync pass.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct SyncSummary {
    /// Wallet's chain tip after the pass.
    pub tip_height: u32,
    /// Number of blocks pulled in this pass.
    pub new_blocks: u32,
    /// Number of mempool transactions ingested in this pass.
    pub new_mempool_txs: u32,
}

/// Per-user wallet handle.
#[allow(dead_code)]
pub struct UserWallet {
    user_id: Uuid,
    wallet_id: Uuid,
    account_idx: i32,
    network: Network,
    federation: Federation<NetworkPatchedSigner>,
    federated_wallet: BtcFederatedWallet<NetworkPatchedSigner>,
    inner: AsyncMutex<Wallet>,
    aggregate: AsyncMutex<ChangeSet>,
    pool: PgPool,
    rpc: Arc<RpcClient>,
}

#[allow(dead_code)]
impl UserWallet {
    /// Owning user id.
    #[must_use]
    pub fn user_id(&self) -> Uuid {
        self.user_id
    }

    /// Wallet row id.
    #[must_use]
    pub fn wallet_id(&self) -> Uuid {
        self.wallet_id
    }

    /// Wallet network.
    #[must_use]
    pub fn network(&self) -> Network {
        self.network
    }

    /// BIP-48 account index.
    #[must_use]
    pub fn account_idx(&self) -> i32 {
        self.account_idx
    }

    /// Borrow the per-user federation (m-of-n HSM signers).
    #[must_use]
    pub fn federation(&self) -> &Federation<NetworkPatchedSigner> {
        &self.federation
    }

    /// Borrow the federated wallet spanning all historical federation versions.
    #[must_use]
    pub fn federated_wallet(&self) -> &BtcFederatedWallet<NetworkPatchedSigner> {
        &self.federated_wallet
    }

    /// Number of federation versions in this wallet's history.
    #[must_use]
    pub fn federation_count(&self) -> usize {
        self.federated_wallet.federation_count()
    }

    /// All federation-wallet pairs where the given signer appears.
    pub fn federations_for_signer(
        &self,
        id: &SignerId,
    ) -> Vec<&FederationWallet<NetworkPatchedSigner, Arc<bdk_wallet::Wallet>>> {
        self.federated_wallet.find_by_signer(id)
    }

    /// Whether the given signer is a member of the current federation.
    #[must_use]
    pub fn signer_is_current(&self, id: &SignerId) -> bool {
        self.federated_wallet.signer_is_current(id)
    }

    /// Drive `bdk_bitcoind_rpc::Emitter` until the wallet matches
    /// bitcoind's tip, apply mempool transactions, and persist the
    /// resulting changeset.
    ///
    /// # Errors
    /// See [`WalletError`]. RPC and DB errors propagate.
    pub async fn sync(&self) -> Result<SyncSummary, WalletError> {
        let (summary, delta) = {
            let mut wallet = self.inner.lock().await;
            let cp = wallet.latest_checkpoint();
            let start_height = cp.height();
            let mut emitter = Emitter::new(&*self.rpc, cp, start_height, NO_EXPECTED_MEMPOOL_TXS);

            let mut new_blocks: u32 = 0;
            while let Some(block_event) = emitter.next_block()? {
                let height = block_event.block_height();
                let connected_to = block_event.connected_to();
                wallet
                    .apply_block_connected_to(&block_event.block, height, connected_to)
                    .map_err(|source| WalletError::ApplyBlock { height, source })?;
                new_blocks = new_blocks.saturating_add(1);
            }

            let mempool = emitter.mempool()?;
            let new_mempool_txs = u32::try_from(mempool.update.len()).unwrap_or(u32::MAX);
            wallet.apply_unconfirmed_txs(mempool.update);

            let tip_height = wallet.latest_checkpoint().height();
            let delta = wallet.take_staged();
            drop(wallet);
            (
                SyncSummary {
                    tip_height,
                    new_blocks,
                    new_mempool_txs,
                },
                delta,
            )
        };

        if let Some(delta) = delta {
            let mut agg = self.aggregate.lock().await;
            agg.merge(delta);
            let json = serde_json::to_value(&*agg).map_err(WalletError::EncodeChangeSet)?;
            drop(agg);
            db::update_wallet_changeset(
                &self.pool,
                self.wallet_id,
                &json,
                i32::try_from(summary.tip_height).unwrap_or(i32::MAX),
            )
            .await?;
        } else {
            db::update_wallet_tip_only(
                &self.pool,
                self.wallet_id,
                i32::try_from(summary.tip_height).unwrap_or(i32::MAX),
            )
            .await?;
        }

        Ok(summary)
    }

    /// Reveal external-keychain addresses `0..target_count` (idempotent),
    /// returning view-models for every revealed address.
    ///
    /// # Errors
    /// See [`WalletError`]. Persistence errors propagate.
    pub async fn reveal_addresses(
        &self,
        target_count: u32,
    ) -> Result<Vec<RevealedAddress>, WalletError> {
        if target_count == 0 {
            return Ok(Vec::new());
        }
        let target_index = target_count - 1;
        let (results, delta, tip) = {
            let mut wallet = self.inner.lock().await;
            let _newly: Vec<AddressInfo> = wallet
                .reveal_addresses_to(KeychainKind::External, target_index)
                .collect();

            let results: Vec<RevealedAddress> = (0..target_count)
                .map(|index| {
                    let info = wallet.peek_address(KeychainKind::External, index);
                    let spk = info.address.script_pubkey();
                    let mut received = Amount::ZERO;
                    let mut unspent = Amount::ZERO;
                    for utxo in wallet.list_output() {
                        if utxo.txout.script_pubkey == spk {
                            received += utxo.txout.value;
                            if !utxo.is_spent {
                                unspent += utxo.txout.value;
                            }
                        }
                    }
                    RevealedAddress {
                        index,
                        keychain: info.keychain,
                        address: info.address.to_string(),
                        received,
                        unspent,
                    }
                })
                .collect();

            let delta = wallet.take_staged();
            let tip = wallet.latest_checkpoint().height();
            drop(wallet);
            (results, delta, tip)
        };

        if let Some(delta) = delta {
            let mut agg = self.aggregate.lock().await;
            agg.merge(delta);
            let json = serde_json::to_value(&*agg).map_err(WalletError::EncodeChangeSet)?;
            drop(agg);
            db::update_wallet_changeset(
                &self.pool,
                self.wallet_id,
                &json,
                i32::try_from(tip).unwrap_or(i32::MAX),
            )
            .await?;
        }

        Ok(results)
    }

    /// List Internal (change) keychain addresses that have ever received funds.
    pub async fn change_addresses(&self) -> Vec<RevealedAddress> {
        let wallet = self.inner.lock().await;
        let outputs: Vec<_> = wallet.list_output().collect();
        let mut seen = std::collections::BTreeMap::<u32, (Amount, Amount)>::new();
        for utxo in &outputs {
            if let Some((KeychainKind::Internal, idx)) =
                wallet.derivation_of_spk(utxo.txout.script_pubkey.clone())
            {
                let entry = seen.entry(idx).or_insert((Amount::ZERO, Amount::ZERO));
                entry.0 += utxo.txout.value;
                if !utxo.is_spent {
                    entry.1 += utxo.txout.value;
                }
            }
        }
        seen.into_iter()
            .map(|(index, (received, unspent))| {
                let info = wallet.peek_address(KeychainKind::Internal, index);
                RevealedAddress {
                    index,
                    keychain: info.keychain,
                    address: info.address.to_string(),
                    received,
                    unspent,
                }
            })
            .collect()
    }

    /// Resolve a user-supplied address string into a [`Address`] tied
    /// to this wallet's network.
    ///
    /// # Errors
    /// [`WalletError::BadAddress`] if the input is malformed or for a
    /// different network.
    pub fn parse_address(&self, raw: &str) -> Result<Address, WalletError> {
        let unchecked: Address<NetworkUnchecked> =
            raw.parse()
                .map_err(|e: bitcoin::address::ParseError| WalletError::BadAddress {
                    addr: raw.to_string(),
                    network: self.network,
                    reason: e.to_string(),
                })?;
        unchecked
            .require_network(self.network)
            .map_err(|e| WalletError::BadAddress {
                addr: raw.to_string(),
                network: self.network,
                reason: e.to_string(),
            })
    }

    /// Look up the keychain + derivation index BDK has assigned to the
    /// given address, if any.
    pub async fn locate_address(&self, address: &Address) -> Option<(KeychainKind, u32)> {
        let wallet = self.inner.lock().await;
        wallet.derivation_of_spk(address.script_pubkey())
    }

    /// Return every wallet transaction that pays into `address`.
    pub async fn address_history(&self, address: &Address) -> Result<AddressActivity, WalletError> {
        let target_spk: ScriptBuf = address.script_pubkey();

        let wallet = self.inner.lock().await;
        let tip_height = wallet.latest_checkpoint().height();

        let spent_status: HashMap<_, _> = wallet
            .list_output()
            .map(|o| (o.outpoint, o.is_spent))
            .collect();

        let mut receipts: Vec<AddressReceipt> = Vec::new();
        let mut total_received = Amount::ZERO;
        let mut unspent = Amount::ZERO;

        for wtx in wallet.transactions() {
            let txid = wtx.tx_node.txid;
            let tx = wtx.tx_node.tx.as_ref();
            for (vout, txout) in tx.output.iter().enumerate() {
                if txout.script_pubkey != target_spk {
                    continue;
                }
                let vout32 = u32::try_from(vout).unwrap_or(u32::MAX);
                let outpoint = bitcoin::OutPoint::new(txid, vout32);
                let is_spent = spent_status.get(&outpoint).copied().unwrap_or(false);
                let (confirmation_height, confirmations) = match wtx.chain_position {
                    ChainPosition::Confirmed { anchor, .. } => {
                        let h = anchor.block_id.height;
                        let confs = tip_height.saturating_sub(h).saturating_add(1);
                        (Some(h), confs)
                    }
                    ChainPosition::Unconfirmed { .. } => (None, 0),
                };
                total_received += txout.value;
                if !is_spent {
                    unspent += txout.value;
                }
                receipts.push(AddressReceipt {
                    txid,
                    vout: vout32,
                    amount: txout.value,
                    confirmation_height,
                    confirmations,
                    is_spent,
                });
            }
        }
        drop(wallet);

        receipts.sort_by_key(|r| r.confirmation_height.unwrap_or(u32::MAX));

        Ok(AddressActivity {
            tip_height,
            total_received,
            unspent,
            receipts,
        })
    }

    /// Wallet's current local-chain tip height.
    pub async fn tip_height(&self) -> u32 {
        self.inner.lock().await.latest_checkpoint().height()
    }

    /// Snapshot the wallet's current balance.
    pub async fn balance(&self) -> bdk_wallet::Balance {
        self.inner.lock().await.balance()
    }

    /// Return all unspent outputs (UTXOs) in this wallet.
    pub async fn list_unspent(&self) -> Vec<bdk_wallet::LocalOutput> {
        self.inner
            .lock()
            .await
            .list_output()
            .filter(|o| !o.is_spent)
            .collect()
    }

    /// Build → sign (m-of-n) → finalize → broadcast → persist.
    ///
    /// # Errors
    /// See [`WalletError`].
    pub async fn build_sign_and_broadcast(
        &self,
        recipient: &Address,
        amount: Amount,
        fee_rate_sat_vb: u64,
        label: Option<String>,
    ) -> Result<BroadcastTransaction, WalletError> {
        let fee_rate =
            FeeRate::from_sat_per_vb(fee_rate_sat_vb).ok_or(WalletError::BadFeeRate {
                sat_per_vb: fee_rate_sat_vb,
            })?;

        let recipient_spk = recipient.script_pubkey();

        // Build, sign, finalize, drain delta — all under the wallet
        // mutex so concurrent requests for the same user serialize.
        let (raw_tx, txid, fee_sat, recipient_sat, delta, tip) = {
            let mut wallet = self.inner.lock().await;
            let psbt = {
                let mut builder = wallet.build_tx();
                builder
                    .add_recipient(recipient_spk.clone(), amount)
                    .fee_rate(fee_rate);
                builder
                    .finish()
                    .map_err(|e| WalletError::BuildTx(e.to_string()))?
            };

            let unsigned = UnsignedPsbt::new(psbt)?;
            let mut coord = SigningCoordinator::new(&self.federation, unsigned);
            // Dispatches via Wallet::sign to all 3 registered Pkcs11Signers.
            // `try_finalize: false` is critical: the default BDK SignOptions
            // calls miniscript's finalizer immediately after each signer
            // runs, which moves partial signatures into `final_script_witness`
            // and empties `partial_sigs`. SigningCoordinator's
            // `signers_with_sigs` would then count zero partial sigs and
            // refuse to finalize.
            let sign_only = SignOptions {
                try_finalize: false,
                ..SignOptions::default()
            };
            let _actions = coord
                .request_signatures(&wallet, sign_only)
                .map_err(|e| WalletError::Sign(e.to_string()))?;
            let finalized = coord
                .finalize(&wallet, SignOptions::default())
                .map_err(|e| WalletError::Sign(e.to_string()))?;

            let txid = finalized.txid();
            let tx = finalized.transaction().clone();

            // Recompute fee + recipient amount from the finalized tx so
            // the persisted record exactly matches what was broadcast.
            let mut output_total: u64 = 0;
            let mut recipient_total: u64 = 0;
            for txout in &tx.output {
                output_total = output_total.saturating_add(txout.value.to_sat());
                if txout.script_pubkey == recipient_spk {
                    recipient_total = recipient_total.saturating_add(txout.value.to_sat());
                }
            }
            let mut input_total: u64 = 0;
            for txin in &tx.input {
                if let Some(utxo) = wallet.get_utxo(txin.previous_output) {
                    input_total = input_total.saturating_add(utxo.txout.value.to_sat());
                }
            }
            let fee_sat = input_total.saturating_sub(output_total);

            // bitcoincore_rpc accepts hex; we encode the consensus tx
            // ourselves to avoid an extra dep.
            let mut raw = Vec::new();
            tx.consensus_encode(&mut raw)
                .map_err(|e| WalletError::ExtractTx(e.to_string()))?;

            let delta = wallet.take_staged();
            let tip = wallet.latest_checkpoint().height();
            drop(wallet);
            (raw, txid, fee_sat, recipient_total, delta, tip)
        };

        // Persist any reveal-induced changeset (BDK may have revealed a
        // fresh internal address for change).
        if let Some(delta) = delta {
            let mut agg = self.aggregate.lock().await;
            agg.merge(delta);
            let json = serde_json::to_value(&*agg).map_err(WalletError::EncodeChangeSet)?;
            drop(agg);
            db::update_wallet_changeset(
                &self.pool,
                self.wallet_id,
                &json,
                i32::try_from(tip).unwrap_or(i32::MAX),
            )
            .await?;
        }

        // Broadcast. If bitcoind rejects, surface a 502; the wallet
        // state has already swallowed the change-address reveal but
        // that's fine — the next build will reuse the same internal
        // index because BDK's index doesn't advance on broadcast
        // failure (the spend never landed in our tx graph).
        let raw_clone = raw_tx.clone();
        let rpc = self.rpc.clone();
        let txid_after_broadcast =
            tokio::task::spawn_blocking(move || rpc.send_raw_transaction(&raw_clone[..]))
                .await
                .map_err(|e| WalletError::BroadcastRejected(e.to_string()))?
                .map_err(|e| WalletError::BroadcastRejected(e.to_string()))?;
        debug_assert_eq!(txid_after_broadcast, txid);

        let recipient_str = recipient.to_string();
        let amount_sat_i64 = i64::try_from(recipient_sat).unwrap_or(i64::MAX);
        let fee_sat_i64 = i64::try_from(fee_sat).unwrap_or(i64::MAX);
        let raw_hex = bitcoin::hex::DisplayHex::to_lower_hex_string(raw_tx.as_slice());
        db::insert_transaction(
            &self.pool,
            &db::NewTransaction {
                wallet_id: self.wallet_id,
                txid: &txid.to_string(),
                recipient: &recipient_str,
                amount_sat: amount_sat_i64,
                fee_sat: fee_sat_i64,
                raw_tx_hex: &raw_hex,
                label: label.as_deref(),
            },
        )
        .await?;

        Ok(BroadcastTransaction {
            txid,
            recipient: recipient_str,
            amount_sat: amount_sat_i64,
            fee_sat: fee_sat_i64,
        })
    }
}
