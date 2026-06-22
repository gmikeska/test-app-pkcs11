//! Shared application state passed by `Arc` to every Axum handler.
//!
//! Boot wiring is in `main.rs`; this module exists so `auth.rs`,
//! `handlers/*`, and `wallet.rs` can refer to a stable type before the
//! main entrypoint is built out.

use std::sync::Arc;

use sqlx::PgPool;

use crate::config::AppConfig;
use crate::elements_wallet::ElementsWalletManager;
use crate::hsm::HsmFleet;
use crate::wallet::WalletManager;

/// Bundle of long-lived resources shared across handlers.
pub struct AppState {
    /// Application config (host, network, BIP-48 coin index, etc.).
    pub config: AppConfig,
    /// Postgres connection pool.
    pub db: PgPool,
    /// HSM fleet (3 dev tokens + per-user signer cache).
    ///
    /// Currently consumed transitively via [`WalletManager`]. Kept as a
    /// top-level handle so future routes (e.g. an HSM-admin page that
    /// resets a user's keys) can reach it without going through the
    /// wallet manager.
    #[allow(dead_code)]
    pub hsm: Arc<HsmFleet>,
    /// Per-user BDK wallet cache + sign/broadcast pipeline.
    pub wallet_manager: Arc<WalletManager>,
    /// Per-user Elements/Liquid wallet cache + PSET sign/broadcast pipeline.
    pub elements_wallet_manager: Arc<ElementsWalletManager>,
}
