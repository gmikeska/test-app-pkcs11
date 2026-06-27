//! [`HsmFleet`] — manager for the federation HSMs backing every wallet.
//!
//! ## Token initialization
//!
//! At startup, [`HsmFleet::new`] calls [`emvault::dev_signer::init_dev_token`]
//! for each discovered token. The helper is idempotent — already
//! initialized tokens are left alone.
//!
//! ## Per-signer derivation
//!
//! Each customer's BIP-48 federation lives on the same set of tokens, but
//! at a different *EmVault label*: `signer-{uuid}`. The first time
//! [`HsmFleet::signers_for`] is called for a signer ID, the fleet opens
//! authenticated sessions and either:
//!
//! 1. Loads pre-existing keys (`Pkcs11Signer::load`) if the master has
//!    been derived previously, or
//! 2. Derives a fresh master via the dev shim's vendor mechanism
//!    (`Pkcs11Signer::derive_from_seed` with an empty seed — the shim
//!    looks up the slot's preconfigured BIP-39 mnemonic).
//!
//! [`emvault::dev_signer::setup_dev_federation`] would be the obvious
//! shortcut, but it hardcodes `Network::Testnet`. We bypass it so the
//! signers honour the `BITCOIN_NETWORK` from `.env` (typically
//! `Network::Regtest`).
//!
//! Cloned [`Pkcs11Signer`]s share the inner `Arc<Mutex<...>>`, so caching
//! per signer keeps the open session count to
//! `n × distinct signers with cached wallets` instead of growing unbounded.

use std::collections::HashMap;
use std::sync::Arc;

use emvault::dev_signer::{DevBackend, DevConfig, init_dev_token};
use emvault::pkcs11::config::SlotIdentifier;
use emvault::pkcs11::{Pkcs11Config, Pkcs11Error, Pkcs11Session, Pkcs11Signer};
use bitcoin::Network;
use bitcoin::bip32::DerivationPath;
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

use crate::config::{AppConfig, HsmTokenConfig};

/// Errors raised by the HSM fleet.
#[derive(Debug, thiserror::Error)]
pub enum HsmError {
    /// Token initialization failure (programmatic `pkcs11-tool
    /// --init-token` equivalent).
    #[error("dev token initialization failed: {0}")]
    InitToken(#[from] emvault::dev_signer::DevSetupError),

    /// Underlying [`emvault::pkcs11`] error (session open, key derive,
    /// xpub read, etc.).
    #[error("PKCS#11 error: {0}")]
    Pkcs11(#[from] Pkcs11Error),

    /// PKCS#11 library at `pkcs11_library_path` doesn't exist on disk.
    #[error("PKCS11_LIB `{path}` does not exist")]
    LibraryMissing {
        /// The configured path.
        path: String,
    },
}

/// A set of [`Pkcs11Signer`]s — one per HSM token — that together form
/// the signer's federation contribution.
///
/// `Arc`'d so it can be cheaply cloned to handlers without duplicating
/// sessions.
pub type SignerSet = Arc<Vec<Pkcs11Signer>>;

/// Owns the federation HSMs: token labels/PINs, plus a per-signer cache.
pub struct HsmFleet {
    library_path: std::path::PathBuf,
    network: Network,
    tokens: Vec<HsmTokenConfig>,
    cache: AsyncMutex<HashMap<Uuid, SignerSet>>,
}

#[allow(dead_code)]
impl HsmFleet {
    /// Initialize the fleet:
    ///
    /// 1. Verify `PKCS11_LIB` exists.
    /// 2. Run `init_dev_token` for each discovered token (idempotent).
    /// 3. Stash configuration; defer session opening to first per-signer use.
    ///
    /// # Errors
    /// - [`HsmError::LibraryMissing`] if `PKCS11_LIB` doesn't exist.
    /// - [`HsmError::InitToken`] if any token init fails.
    pub fn new(config: &AppConfig) -> Result<Self, HsmError> {
        if !config.pkcs11_library_path.exists() {
            return Err(HsmError::LibraryMissing {
                path: config.pkcs11_library_path.display().to_string(),
            });
        }

        let dev_cfg = DevConfig {
            shim_library_path: config.pkcs11_library_path.clone(),
        };
        for token in &config.hsm_tokens {
            init_dev_token(&dev_cfg, &token.label, &token.so_pin, &token.pin)?;
            tracing::info!(label = %token.label, "dev token initialized");
        }

        Ok(Self {
            library_path: config.pkcs11_library_path.clone(),
            network: config.network,
            tokens: config.hsm_tokens.clone(),
            cache: AsyncMutex::new(HashMap::new()),
        })
    }

    /// Network the derived keys are stamped with. Mirrors
    /// [`AppConfig::network`].
    pub fn network(&self) -> Network {
        self.network
    }

    /// Build the EmVault-namespace label this fleet uses for `signer_id`.
    /// Matches the on-token namespace `emvault/v1/{label}/{priv,policy,sigrate}`.
    #[must_use]
    pub fn signer_label(signer_id: Uuid) -> String {
        format!("signer-{signer_id}")
    }

    /// Retrieve (or lazily build) the [`Pkcs11Signer`]s for `signer_id`.
    ///
    /// Cache-miss path opens sessions in series (one per token),
    /// and either loads pre-existing keys or derives a fresh master via
    /// the dev shim. Each call after that hits the cache.
    ///
    /// # Errors
    /// Surfaces every PKCS#11-layer failure (`HsmError::Pkcs11`).
    pub async fn signers_for(
        &self,
        signer_id: Uuid,
        derivation_path: &DerivationPath,
    ) -> Result<SignerSet, HsmError> {
        if let Some(signers) = self.cache.lock().await.get(&signer_id).cloned() {
            return Ok(signers);
        }

        let label = Self::signer_label(signer_id);
        let library_path = self.library_path.clone();
        let network = self.network;
        let tokens = self.tokens.clone();
        let path_owned = derivation_path.clone();

        let signers = tokio::task::spawn_blocking(move || {
            derive_signers(&library_path, network, &tokens, &label, &path_owned)
        })
        .await
        .expect("derive_signers join")?;

        let arc: SignerSet = Arc::new(signers);
        let mut cache = self.cache.lock().await;
        Ok(cache.entry(signer_id).or_insert(arc).clone())
    }

    /// Drop the cached signer set for `signer_id` (closing its sessions
    /// when the last clone is released). Useful for tests and debugging;
    /// never invoked by the regular request flow.
    pub async fn evict(&self, signer_id: Uuid) {
        self.cache.lock().await.remove(&signer_id);
    }

    /// Permanently delete every EmVault-namespace object for `signer_id`
    /// from each token, and evict any cached set.
    ///
    /// Used by tests and by future "reset wallet" flows. Fresh sessions
    /// are opened just for the deletion to avoid contending on a
    /// signer's mutex.
    ///
    /// # Errors
    /// Surfaces every PKCS#11-layer failure (`HsmError::Pkcs11`).
    pub async fn delete_keys(&self, signer_id: Uuid) -> Result<(), HsmError> {
        let label = Self::signer_label(signer_id);
        let library_path = self.library_path.clone();
        let tokens = self.tokens.clone();
        let label_clone = label.clone();
        tokio::task::spawn_blocking(move || {
            delete_key_objects(&library_path, &tokens, &label_clone)
        })
        .await
        .expect("delete_key_objects join")?;
        self.evict(signer_id).await;
        tracing::info!(%signer_id, %label, "deleted signer HSM keys");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Sync helpers (run on spawn_blocking)
// ---------------------------------------------------------------------------

fn derive_signers(
    library_path: &std::path::Path,
    network: Network,
    tokens: &[HsmTokenConfig],
    label: &str,
    derivation_path: &DerivationPath,
) -> Result<Vec<Pkcs11Signer>, HsmError> {
    let mut out: Vec<Pkcs11Signer> = Vec::with_capacity(tokens.len());
    for token in tokens {
        let cfg = Pkcs11Config::new(
            library_path,
            SlotIdentifier::label(&token.label),
            token.pin.clone(),
            derivation_path.clone(),
            Box::new(DevBackend),
        );
        let session = Pkcs11Session::open(&cfg, &SlotIdentifier::label(&token.label), &token.pin)?;

        let signer = match Pkcs11Signer::load(
            session,
            label,
            derivation_path.clone(),
            network,
            Box::new(DevBackend),
        ) {
            Ok(s) => {
                tracing::debug!(%label, token = %token.label, "loaded existing HSM key");
                s
            }
            Err(Pkcs11Error::ObjectNotFound(_)) => {
                tracing::info!(%label, token = %token.label, "deriving fresh HSM key");
                let session =
                    Pkcs11Session::open(&cfg, &SlotIdentifier::label(&token.label), &token.pin)?;
                Pkcs11Signer::derive_from_seed(
                    session,
                    label,
                    derivation_path,
                    network,
                    Box::new(DevBackend),
                    &[],
                )?
            }
            Err(e) => return Err(e.into()),
        };
        out.push(signer);
    }
    Ok(out)
}

fn delete_key_objects(
    library_path: &std::path::Path,
    tokens: &[HsmTokenConfig],
    label: &str,
) -> Result<(), HsmError> {
    for token in tokens {
        let cfg = Pkcs11Config::new(
            library_path,
            SlotIdentifier::label(&token.label),
            token.pin.clone(),
            DerivationPath::default(),
            Box::new(DevBackend),
        );
        let session = Pkcs11Session::open(&cfg, &SlotIdentifier::label(&token.label), &token.pin)?;
        emvault::pkcs11::key_ops::delete_key(&session, label)?;
    }
    Ok(())
}
