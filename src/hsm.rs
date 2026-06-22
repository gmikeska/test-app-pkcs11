//! [`HsmFleet`] — manager for the three federation HSMs backing every user
//! wallet in this app.
//!
//! ## Token initialization
//!
//! At startup, [`HsmFleet::new`] calls [`asterism_dev_signer::init_dev_token`]
//! for each of the three tokens. The helper is idempotent — already
//! initialized tokens are left alone.
//!
//! ## Per-user signer derivation
//!
//! Each customer's BIP-48 federation lives on the same three tokens, but
//! at a different *Asterism label*: `user-{short_id}`. The first time
//! [`HsmFleet::signers_for`] is called for a user, the fleet opens three
//! authenticated sessions and either:
//!
//! 1. Loads pre-existing keys (`Pkcs11Signer::load`) if the master has
//!    been derived previously, or
//! 2. Derives a fresh master via the dev shim's vendor mechanism
//!    (`Pkcs11Signer::derive_from_seed` with an empty seed — the shim
//!    looks up the slot's preconfigured BIP-39 mnemonic).
//!
//! [`asterism_dev_signer::setup_dev_federation`] would be the obvious
//! shortcut, but it hardcodes `Network::Testnet`. We bypass it so the
//! signers honour the `BITCOIN_NETWORK` from `.env` (typically
//! `Network::Regtest`).
//!
//! Cloned [`Pkcs11Signer`]s share the inner `Arc<Mutex<...>>`, so caching
//! a single triple per user keeps the open session count to
//! `3 × distinct users with cached wallets` instead of growing unbounded.

use std::collections::HashMap;
use std::sync::Arc;

use asterism_dev_signer::{DevBackend, DevConfig, init_dev_token};
use asterism_pkcs11::config::SlotIdentifier;
use asterism_pkcs11::{Pkcs11Config, Pkcs11Error, Pkcs11Session, Pkcs11Signer};
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
    InitToken(#[from] asterism_dev_signer::DevSetupError),

    /// Underlying [`asterism_pkcs11`] error (session open, key derive,
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

/// A user-scoped triple of [`Pkcs11Signer`]s — one per HSM token — that
/// together implement the user's 3-of-3 federation.
///
/// The triple is `Arc`'d so it can be cheaply cloned to handlers without
/// duplicating sessions.
pub type UserSigners = Arc<[Pkcs11Signer; 3]>;

/// Owns the three federation HSMs: token labels/PINs, plus a per-user
/// signer cache.
pub struct HsmFleet {
    library_path: std::path::PathBuf,
    network: Network,
    tokens: [HsmTokenConfig; 3],
    cache: AsyncMutex<HashMap<Uuid, UserSigners>>,
}

#[allow(dead_code)] // `network`/`evict`/`delete_keys_for_user` are dev/debug entry points
impl HsmFleet {
    /// Initialize the fleet:
    ///
    /// 1. Verify `PKCS11_LIB` exists.
    /// 2. Run `init_dev_token` for each of the three tokens (idempotent).
    /// 3. Stash configuration; defer session opening to first per-user use.
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

    /// Build the Asterism-namespace label this fleet uses for `user_id`.
    /// Stable, short (8 hex chars of the UUID), and matches the
    /// on-token namespace `asterism/v1/{label}/{priv,policy,sigrate}`.
    #[must_use]
    pub fn user_label(user_id: Uuid) -> String {
        let s = user_id.simple().to_string();
        format!("user-{}", &s[..8])
    }

    /// Retrieve (or lazily build) the user's three [`Pkcs11Signer`]s.
    ///
    /// Cache-miss path opens three sessions in series (3 token labels
    /// resolved against `SoftHSM`; one session per token), and either
    /// loads pre-existing keys or derives a fresh master via the dev
    /// shim. Each call after that hits the cache.
    ///
    /// Concurrent first-use calls for the same user race the cache
    /// mutex; whichever wins runs the derivation, the rest see the
    /// cached triple.
    ///
    /// # Errors
    /// Surfaces every PKCS#11-layer failure (`HsmError::Pkcs11`).
    pub async fn signers_for(
        &self,
        user_id: Uuid,
        derivation_path: &DerivationPath,
    ) -> Result<UserSigners, HsmError> {
        if let Some(signers) = self.cache.lock().await.get(&user_id).cloned() {
            return Ok(signers);
        }

        let label = Self::user_label(user_id);
        let library_path = self.library_path.clone();
        let network = self.network;
        let tokens = self.tokens.clone();
        let path_owned = derivation_path.clone();

        // Session open + master derive call into cryptoki, which is
        // synchronous and will block the runtime if held on a regular
        // tokio worker. Off-load to spawn_blocking so concurrent web
        // requests aren't stalled.
        let signers = tokio::task::spawn_blocking(move || {
            derive_user_signers(&library_path, network, &tokens, &label, &path_owned)
        })
        .await
        .expect("derive_user_signers join")?;

        let arc: UserSigners = Arc::new(signers);
        let mut cache = self.cache.lock().await;
        Ok(cache.entry(user_id).or_insert(arc).clone())
    }

    /// Drop the cached signer triple for `user_id` (closing its three
    /// sessions when the last clone is released). Useful for tests and
    /// debugging; never invoked by the regular request flow.
    pub async fn evict(&self, user_id: Uuid) {
        self.cache.lock().await.remove(&user_id);
    }

    /// Permanently delete every Asterism-namespace object for `user_id`
    /// from each of the three tokens, and evict any cached triple.
    ///
    /// Used by tests and by future "reset wallet" flows. Fresh sessions
    /// are opened just for the deletion to avoid contending on a
    /// signer's mutex.
    ///
    /// # Errors
    /// Surfaces every PKCS#11-layer failure (`HsmError::Pkcs11`).
    pub async fn delete_keys_for_user(&self, user_id: Uuid) -> Result<(), HsmError> {
        let label = Self::user_label(user_id);
        let library_path = self.library_path.clone();
        let tokens = self.tokens.clone();
        let label_clone = label.clone();
        tokio::task::spawn_blocking(move || delete_keys(&library_path, &tokens, &label_clone))
            .await
            .expect("delete_keys join")?;
        self.evict(user_id).await;
        tracing::info!(%user_id, %label, "deleted user HSM keys");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Sync helpers (run on spawn_blocking)
// ---------------------------------------------------------------------------

fn derive_user_signers(
    library_path: &std::path::Path,
    network: Network,
    tokens: &[HsmTokenConfig; 3],
    label: &str,
    derivation_path: &DerivationPath,
) -> Result<[Pkcs11Signer; 3], HsmError> {
    let mut out: Vec<Pkcs11Signer> = Vec::with_capacity(3);
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
                // Re-open: `load` consumed the session.
                let session =
                    Pkcs11Session::open(&cfg, &SlotIdentifier::label(&token.label), &token.pin)?;
                Pkcs11Signer::derive_from_seed(
                    session,
                    label,
                    derivation_path,
                    network,
                    Box::new(DevBackend),
                    // Empty seed: dev shim looks up the slot's
                    // preconfigured BIP-39 mnemonic via
                    // DEV_HSM_SLOT_*_MNEMONIC env vars.
                    &[],
                )?
            }
            Err(e) => return Err(e.into()),
        };
        out.push(signer);
    }

    // SAFETY: pushed exactly 3 elements above.
    let arr: [Pkcs11Signer; 3] = out
        .try_into()
        .map_err(|v: Vec<Pkcs11Signer>| {
            unreachable!("derive_user_signers built {} signers, expected 3", v.len())
        })
        .expect("3 signers");
    Ok(arr)
}

#[allow(dead_code)] // invoked from `delete_keys_for_user`
fn delete_keys(
    library_path: &std::path::Path,
    tokens: &[HsmTokenConfig; 3],
    label: &str,
) -> Result<(), HsmError> {
    for token in tokens {
        let cfg = Pkcs11Config::new(
            library_path,
            SlotIdentifier::label(&token.label),
            token.pin.clone(),
            // Derivation path is irrelevant for deletion — the helper
            // touches only object handles already on the token.
            DerivationPath::default(),
            Box::new(DevBackend),
        );
        let session = Pkcs11Session::open(&cfg, &SlotIdentifier::label(&token.label), &token.pin)?;
        asterism_pkcs11::key_ops::delete_key(&session, label)?;
    }
    Ok(())
}
