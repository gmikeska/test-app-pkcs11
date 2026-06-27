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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use asterism::core::chain_sync::{self, ChainSyncError, InitWalletError};
use asterism::core::descriptor::{KeyMode, to_multipath_string};
use asterism::core::error::PsbtError;
use asterism::core::federated_wallet::FederatedWallet as FederatedWalletTrait;
use asterism::core::network::NetworkType;
use asterism::core::psbt as core_psbt;
use asterism::core::psbt::{SigningCoordinator, UnsignedPsbt};
use asterism::core::signer::{Signer, SignerId};
use asterism::core::{BtcFederatedWallet, Federation, FederationWallet};
use asterism::pkcs11::Pkcs11Signer;
// `Emitter`/`NO_EXPECTED_MEMPOOL_TXS` remain for the best-effort version-wallet
// fan-out sync below; the primary wallet sync uses `chain_sync::emitter_sync`.
use bdk_bitcoind_rpc::{Emitter, NO_EXPECTED_MEMPOOL_TXS};
use bdk_wallet::chain::{ChainPosition, Merge};
use bdk_wallet::signer::SignerOrdering;
use bdk_wallet::{AddressInfo, ChangeSet, KeychainKind, SignOptions, Wallet};
use bitcoin::address::NetworkUnchecked;
use bitcoin::bip32::{DerivationPath, Fingerprint};
use bitcoin::consensus::Encodable;
use bitcoin::{Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, Txid, Weight};
use bitcoincore_rpc::{Auth, Client as RpcClient, RpcApi};
use sqlx::PgPool;
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

use crate::config::AppConfig;
use crate::db;
use crate::hsm::{HsmError, HsmFleet};
use crate::models::WalletRow;

/// One PSBT input's saved `bip32_derivation` map (index + key origins), stashed
/// while migration-signing temporarily clears non-target inputs.
type SavedBip32Derivation = (
    usize,
    std::collections::BTreeMap<bitcoin::secp256k1::PublicKey, (Fingerprint, DerivationPath)>,
);

/// Default reveal target: addresses 0..REVEAL_COUNT-1 are eagerly
/// surfaced on every receive-tab render.
pub const REVEAL_COUNT: u32 = 20;

// ---------------------------------------------------------------------------
// Network-patched signer wrapper — extracted to `asterism-pkcs11`
// ---------------------------------------------------------------------------

// `NetworkPatchedSigner` now lives in `asterism-pkcs11` (every PKCS#11 consumer
// on a non-mainnet network needs it). Re-exported here so existing
// `crate::wallet::NetworkPatchedSigner` paths keep resolving.
pub use asterism::pkcs11::NetworkPatchedSigner;

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
    Descriptor(#[from] asterism::core::DescriptorError),

    /// `Federation::with_key_mode` rejected the inputs.
    #[error("federation construction failed: {0}")]
    Federation(#[from] asterism::core::error::FederationError),

    /// `UnsignedPsbt::new` / `SigningCoordinator` rejected the PSBT.
    #[error("PSBT pipeline error: {0}")]
    Psbt(#[from] asterism::core::error::PsbtError),

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

impl WalletError {
    /// Map a core [`ChainSyncError`] back into this app's `WalletError`.
    fn from_chain_sync(err: ChainSyncError) -> Self {
        match err {
            ChainSyncError::Rpc(source) => Self::Rpc(source),
            ChainSyncError::ApplyBlock { height, source } => Self::ApplyBlock { height, source },
        }
    }

    /// Map a core [`InitWalletError`] back into this app's `WalletError`,
    /// preserving the prior stringified `LoadWallet`/`CreateWallet` surfaces.
    fn from_init_wallet(id: Uuid, err: InitWalletError) -> Self {
        match err {
            InitWalletError::Decode(source) => Self::DecodeChangeSet { id, source },
            InitWalletError::Load(source) => Self::LoadWallet(source.to_string()),
            InitWalletError::EmptyChangeSet => Self::LoadWallet("empty changeset".into()),
            InitWalletError::Create(source) => Self::CreateWallet(source.to_string()),
        }
    }
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
    fed_signer_indices: Vec<usize>,
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
            fed_signer_indices: config.fed_signer_indices.clone(),
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

    /// Like [`ensure_wallet_for_user`] but forces a specific account index.
    pub async fn ensure_wallet_for_user_at(
        &self,
        user_id: Uuid,
        account_idx: i32,
    ) -> Result<WalletRow, WalletError> {
        if let Some(row) = db::find_wallet_for_user(&self.pool, user_id).await? {
            return Ok(row);
        }
        self.create_wallet_for_user_at(user_id, account_idx).await
    }

    async fn create_wallet_for_user(&self, user_id: Uuid) -> Result<WalletRow, WalletError> {
        let account_idx = db::next_account_idx(&self.pool).await?;
        self.create_wallet_for_user_at(user_id, account_idx).await
    }

    async fn create_wallet_for_user_at(
        &self,
        user_id: Uuid,
        account_idx: i32,
    ) -> Result<WalletRow, WalletError> {
        let account_idx_u32 = u32::try_from(account_idx).unwrap_or(0);
        let path = self.derivation_path_for(account_idx_u32)?;

        let all_signers = self.hsm.signers_for(user_id, &path).await?;
        let patched: Vec<NetworkPatchedSigner> = self
            .fed_signer_indices
            .iter()
            .map(|&idx| NetworkPatchedSigner::new(all_signers[idx].clone(), self.network))
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
        all_signers: &[Pkcs11Signer],
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

        // Reconstruct every stored version from its descriptor so the
        // FederatedWallet reflects what was actually persisted — not what
        // the current config says. This keeps wallet loading correct even
        // when APP_FED_SIGNERS changes between restarts or after a
        // migration tool run.
        let first = &versions[0];
        let first_fed =
            Self::reconstruct_federation_from_version(first, all_signers, self.network)?;
        let first_wallet = Self::create_metadata_wallet(&first_fed, self.network)?;
        let mut fw = BtcFederatedWallet::new(first_fed, first_wallet)
            .map_err(|e| WalletError::CreateWallet(e.to_string()))?;

        for v in &versions[1..] {
            let fed = Self::reconstruct_federation_from_version(v, all_signers, self.network)?;
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
    /// federation version row. Matches signers from the available pool
    /// by fingerprint extracted from the stored descriptor.
    fn reconstruct_federation_from_version(
        version: &crate::models::FederationVersionRow,
        all_signers: &[Pkcs11Signer],
        network: Network,
    ) -> Result<Federation<NetworkPatchedSigner>, WalletError> {
        let fingerprints: Vec<String> = extract_fingerprints_from_descriptor(&version.descriptor);
        let threshold = u32::try_from(version.threshold).unwrap_or(0);

        let mut matched: Vec<NetworkPatchedSigner> = Vec::with_capacity(fingerprints.len());
        for fp_hex in &fingerprints {
            let signer = all_signers
                .iter()
                .find(|s| format!("{}", s.fingerprint()) == *fp_hex)
                .ok_or_else(|| {
                    WalletError::CreateWallet(format!(
                        "signer with fingerprint {fp_hex} not found in HSM pool \
                         (needed for federation version {})",
                        version.version_index
                    ))
                })?;
            matched.push(NetworkPatchedSigner::new(signer.clone(), network));
        }

        Federation::with_key_mode(
            threshold,
            matched,
            NetworkType::Bitcoin(network),
            KeyMode::Ranged,
        )
        .map_err(|e| WalletError::CreateWallet(e.to_string()))
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

        // Reconstruct the current federation from the latest stored
        // version so we stay consistent with what's in the DB — even if
        // APP_FED_SIGNERS changed since the wallet was created.
        let versions = db::list_federation_versions_for_wallet(&self.pool, wallet_id).await?;
        let federation = if let Some(latest) = versions.last() {
            Self::reconstruct_federation_from_version(latest, &signers_arc, self.network)?
        } else {
            let patched_owned: Vec<NetworkPatchedSigner> = self
                .fed_signer_indices
                .iter()
                .map(|&idx| NetworkPatchedSigner::new(signers_arc[idx].clone(), self.network))
                .collect();
            Federation::with_key_mode(
                self.fed_threshold,
                patched_owned,
                NetworkType::Bitcoin(self.network),
                KeyMode::Ranged,
            )?
        };

        // Init-or-load BDK construction lives in `asterism::core::chain_sync`
        // (E3b). Core leaves the staged changeset intact on the fresh path and
        // returns an empty aggregate, matching this app's prior behavior
        // exactly (signers are registered just below, then persisted).
        let loaded = chain_sync::init_or_load_wallet(
            self.network,
            row.descriptor.clone(),
            row.bdk_changeset.clone(),
        )
        .map_err(|e| WalletError::from_init_wallet(wallet_id, e))?;
        let (mut wallet, initial_changeset) = (loaded.wallet, loaded.changeset);

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
        let federated_wallet = self
            .build_federated_wallet(wallet_id, &federation, &signers_arc)
            .await?;

        // Create mutable BDK wallets for each federation version so we
        // can sync them all against the blockchain.
        let mut version_wallets = Vec::with_capacity(federated_wallet.federation_count());
        for fw in federated_wallet.federation_wallets() {
            let vw = Self::create_metadata_wallet(&fw.federation, self.network)?;
            version_wallets.push(AsyncMutex::new(vw));
        }

        Ok(UserWallet {
            user_id,
            wallet_id,
            account_idx,
            network: self.network,
            federation,
            federated_wallet,
            version_wallets,
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
    /// Per-federation-version BDK wallets that get synced against the
    /// blockchain. Index 0 = oldest federation, last = newest (current).
    /// These mirror `federated_wallet` but are mutable for sync.
    version_wallets: Vec<AsyncMutex<Wallet>>,
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
        // Sync each federation-version wallet independently so each builds
        // its own checkpoint chain and discovers UTXOs at its descriptor's
        // addresses.
        for vw_mutex in &self.version_wallets {
            let mut vw = vw_mutex.lock().await;
            let cp = vw.latest_checkpoint();
            let start = cp.height();
            let mut emitter = Emitter::new(&*self.rpc, cp, start, NO_EXPECTED_MEMPOOL_TXS);
            while let Some(block_event) = emitter.next_block()? {
                let height = block_event.block_height();
                let connected_to = block_event.connected_to();
                let _ = vw.apply_block_connected_to(&block_event.block, height, connected_to);
            }
            let mempool = emitter.mempool()?;
            vw.apply_unconfirmed_txs(mempool.update);
        }

        let (summary, delta) = {
            let mut wallet = self.inner.lock().await;
            // Pure-BDK emitter drive lives in `asterism::core::chain_sync` (E3b);
            // persistence (changeset merge + DB write) stays here.
            let result = chain_sync::emitter_sync(&mut wallet, &*self.rpc)
                .map_err(WalletError::from_chain_sync)?;
            drop(wallet);
            (
                SyncSummary {
                    tip_height: result.tip_height,
                    new_blocks: result.blocks_synced,
                    new_mempool_txs: result.new_mempool_txs,
                },
                result.changeset,
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
        use asterism::core::federated_wallet::FederatedWallet as _;
        if target_count == 0 {
            return Ok(Vec::new());
        }
        let target_index = target_count - 1;

        // Derive receive addresses from the *current* (newest) federation
        // so new deposits go to the post-migration descriptor. Balance and
        // UTXO data still come from `self.inner` which tracks all versions.
        let current_wallet = &self.federated_wallet.current().wallet;

        let (results, delta, tip) = {
            let mut wallet = self.inner.lock().await;
            let _newly: Vec<AddressInfo> = wallet
                .reveal_addresses_to(KeychainKind::External, target_index)
                .collect();

            let results: Vec<RevealedAddress> = (0..target_count)
                .map(|index| {
                    let info = current_wallet.peek_address(KeychainKind::External, index);
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

    /// Derive external addresses for every federation version, with UTXO data
    /// from the inner wallet where available. Returns `(version_index, addresses)`
    /// pairs in oldest-first order.
    pub async fn revealed_addresses_all_versions(
        &self,
        count: u32,
    ) -> Vec<(usize, Vec<RevealedAddress>)> {
        use asterism::core::federated_wallet::FederatedWallet as _;

        let mut results = Vec::with_capacity(self.version_wallets.len());

        for (i, vw_mutex) in self.version_wallets.iter().enumerate() {
            let vw = vw_mutex.lock().await;
            let outputs: Vec<_> = vw.list_output().collect();
            let fw = &self.federated_wallet.federation_wallets()[i];

            let addrs: Vec<RevealedAddress> = (0..count)
                .map(|index| {
                    let info = fw.wallet.peek_address(KeychainKind::External, index);
                    let spk = info.address.script_pubkey();
                    let mut received = Amount::ZERO;
                    let mut unspent = Amount::ZERO;
                    for utxo in &outputs {
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
            results.push((fw.index, addrs));
        }

        results
    }

    /// List Internal (change) keychain addresses that have ever received funds.
    pub async fn change_addresses(&self) -> Vec<RevealedAddress> {
        let mut all = Vec::new();
        for vw_mutex in &self.version_wallets {
            let vw = vw_mutex.lock().await;
            let outputs: Vec<_> = vw.list_output().collect();
            let mut seen = std::collections::BTreeMap::<u32, (Amount, Amount)>::new();
            for utxo in &outputs {
                if let Some((KeychainKind::Internal, idx)) =
                    vw.derivation_of_spk(utxo.txout.script_pubkey.clone())
                {
                    let entry = seen.entry(idx).or_insert((Amount::ZERO, Amount::ZERO));
                    entry.0 += utxo.txout.value;
                    if !utxo.is_spent {
                        entry.1 += utxo.txout.value;
                    }
                }
            }
            all.extend(seen.into_iter().map(|(index, (received, unspent))| {
                let info = vw.peek_address(KeychainKind::Internal, index);
                RevealedAddress {
                    index,
                    keychain: info.keychain,
                    address: info.address.to_string(),
                    received,
                    unspent,
                }
            }));
        }
        all
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
        let spk = address.script_pubkey();

        let wallet = self.inner.lock().await;
        if let Some(result) = wallet.derivation_of_spk(spk.clone()) {
            return Some(result);
        }
        drop(wallet);

        for fw in self.federated_wallet.federation_wallets() {
            if let Some(result) = fw.wallet.derivation_of_spk(spk.clone()) {
                return Some(result);
            }
        }
        None
    }

    /// Return every wallet transaction that pays into `address`.
    pub async fn address_history(&self, address: &Address) -> Result<AddressActivity, WalletError> {
        let target_spk: ScriptBuf = address.script_pubkey();

        let tip_height = self.inner.lock().await.latest_checkpoint().height();

        let mut seen_outpoints = HashSet::new();
        let mut receipts: Vec<AddressReceipt> = Vec::new();
        let mut total_received = Amount::ZERO;
        let mut unspent = Amount::ZERO;

        for vw_mutex in &self.version_wallets {
            let vw = vw_mutex.lock().await;

            let spent_status: HashMap<_, _> =
                vw.list_output().map(|o| (o.outpoint, o.is_spent)).collect();

            for wtx in vw.transactions() {
                let txid = wtx.tx_node.txid;
                let tx = wtx.tx_node.tx.as_ref();
                for (vout, txout) in tx.output.iter().enumerate() {
                    if txout.script_pubkey != target_spk {
                        continue;
                    }
                    let vout32 = u32::try_from(vout).unwrap_or(u32::MAX);
                    let outpoint = bitcoin::OutPoint::new(txid, vout32);
                    if !seen_outpoints.insert(outpoint) {
                        continue;
                    }
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
        }

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
        let mut total = bdk_wallet::Balance::default();
        for vw_mutex in &self.version_wallets {
            let vw = vw_mutex.lock().await;
            let b = vw.balance();
            total.confirmed += b.confirmed;
            total.trusted_pending += b.trusted_pending;
            total.untrusted_pending += b.untrusted_pending;
            total.immature += b.immature;
        }
        total
    }

    /// Return all unspent outputs (UTXOs) in this wallet.
    pub async fn list_unspent(&self) -> Vec<bdk_wallet::LocalOutput> {
        let mut all = Vec::new();
        for vw_mutex in &self.version_wallets {
            let vw = vw_mutex.lock().await;
            all.extend(vw.list_output().filter(|o| !o.is_spent));
        }
        all
    }

    /// Sweep all funds to `recipient`, deducting fees automatically.
    ///
    /// Uses BDK's `drain_to` so the entire balance minus the mining fee
    /// lands in a single output at the destination address.
    pub async fn sweep_to(
        &self,
        recipient: &Address,
        fee_rate_sat_vb: u64,
        label: Option<String>,
    ) -> Result<BroadcastTransaction, WalletError> {
        let fee_rate =
            FeeRate::from_sat_per_vb(fee_rate_sat_vb).ok_or(WalletError::BadFeeRate {
                sat_per_vb: fee_rate_sat_vb,
            })?;

        let recipient_spk = recipient.script_pubkey();

        let (raw_tx, txid, fee_sat, recipient_sat, delta, tip) = {
            let mut wallet = self.inner.lock().await;
            let psbt = {
                let mut builder = wallet.build_tx();
                builder
                    .drain_wallet()
                    .drain_to(recipient_spk.clone())
                    .fee_rate(fee_rate);
                builder
                    .finish()
                    .map_err(|e| WalletError::BuildTx(e.to_string()))?
            };

            let unsigned = UnsignedPsbt::new(psbt)?;
            let mut coord = SigningCoordinator::new(&self.federation, unsigned);
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

            let mut raw = Vec::new();
            tx.consensus_encode(&mut raw)
                .map_err(|e| WalletError::ExtractTx(e.to_string()))?;

            let delta = wallet.take_staged();
            let tip = wallet.latest_checkpoint().height();
            drop(wallet);
            (raw, txid, fee_sat, recipient_total, delta, tip)
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

    /// Build a populated `psbt::Input` for a UTXO owned by this wallet,
    /// suitable for use as a foreign input in a multi-wallet migration PSBT.
    ///
    /// Searches version wallets first, then falls back to the inner wallet.
    /// The returned `Weight` is a conservative satisfaction-weight estimate
    /// for P2WSH multisig inputs (used by BDK for fee estimation).
    pub async fn psbt_input_for_utxo(
        &self,
        outpoint: OutPoint,
    ) -> Result<(bitcoin::psbt::Input, Weight), WalletError> {
        // ~260 WU for a 2-of-3 P2WSH multisig witness satisfaction.
        let satisfaction_weight = Weight::from_witness_data_size(260);

        for vw_mutex in &self.version_wallets {
            let vw = vw_mutex.lock().await;
            if vw.get_utxo(outpoint).is_some() {
                let local = vw.get_utxo(outpoint).expect("checked above");
                let psbt_input = vw
                    .get_psbt_input(local, None, false)
                    .map_err(|e| WalletError::BuildTx(e.to_string()))?;
                return Ok((psbt_input, satisfaction_weight));
            }
        }
        let wallet = self.inner.lock().await;
        let local = wallet
            .get_utxo(outpoint)
            .ok_or_else(|| WalletError::BuildTx(format!("UTXO {outpoint} not found in wallet")))?;
        let psbt_input = wallet
            .get_psbt_input(local, None, false)
            .map_err(|e| WalletError::BuildTx(e.to_string()))?;
        Ok((psbt_input, satisfaction_weight))
    }

    /// Sign specific inputs in a PSBT using this wallet's registered signers.
    ///
    /// Only inputs at `input_indices` are signed. Other inputs have their
    /// `bip32_derivation` temporarily cleared so that the PKCS#11 signers
    /// skip them (they match by fingerprint in `bip32_derivation`).
    pub async fn sign_migration_inputs(
        &self,
        psbt: &mut bitcoin::Psbt,
        input_indices: &[usize],
    ) -> Result<(), WalletError> {
        let mut saved: Vec<SavedBip32Derivation> = Vec::new();
        for (i, inp) in psbt.inputs.iter_mut().enumerate() {
            if !input_indices.contains(&i) {
                saved.push((i, std::mem::take(&mut inp.bip32_derivation)));
            }
        }

        let wallet = self.inner.lock().await;
        let sign_only = SignOptions {
            try_finalize: false,
            trust_witness_utxo: true,
            ..SignOptions::default()
        };
        let _ = wallet
            .sign(psbt, sign_only)
            .map_err(|e| WalletError::Sign(e.to_string()))?;
        drop(wallet);

        for (i, derivation) in saved {
            psbt.inputs[i].bip32_derivation = derivation;
        }
        Ok(())
    }

    /// Insert an unconfirmed transaction into all version wallets and the
    /// inner wallet. Used during migration to make chained outputs visible
    /// to `psbt_input_for_utxo` without a full sync round-trip.
    pub async fn insert_unconfirmed_tx(&self, tx: &bitcoin::Transaction) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        for vw_mutex in &self.version_wallets {
            let mut vw = vw_mutex.lock().await;
            vw.apply_unconfirmed_txs(vec![(tx.clone(), now)]);
        }
        let mut inner = self.inner.lock().await;
        inner.apply_unconfirmed_txs(vec![(tx.clone(), now)]);
    }

    /// Lock and return a guard to the inner BDK wallet.
    /// Used by the migration tool to build multi-wallet PSBTs.
    pub async fn inner_wallet(&self) -> tokio::sync::MutexGuard<'_, Wallet> {
        self.inner.lock().await
    }

    /// Borrow the shared RPC client.
    pub fn rpc(&self) -> &Arc<RpcClient> {
        &self.rpc
    }

    /// Borrow the DB pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
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
            let psbt = core_psbt::build_spend(&mut wallet, recipient_spk.clone(), amount, fee_rate)
                .map_err(|e| match e {
                    PsbtError::BuildFailed(s) => WalletError::BuildTx(s),
                    other => WalletError::BuildTx(other.to_string()),
                })?;

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

/// Extract key-origin fingerprints from a descriptor string.
///
/// Parses `[abcdef01/48'/1'/0'/2']tpub...` patterns and returns the
/// fingerprint hex strings in the order they appear.
fn extract_fingerprints_from_descriptor(descriptor: &str) -> Vec<String> {
    let mut fps = Vec::new();
    for chunk in descriptor.split('[').skip(1) {
        if let Some(fp) = chunk.split('/').next()
            && fp.len() == 8
            && fp.chars().all(|c| c.is_ascii_hexdigit())
        {
            fps.push(fp.to_string());
        }
    }
    fps
}
