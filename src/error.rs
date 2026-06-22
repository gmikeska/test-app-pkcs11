//! Application error type and Axum [`IntoResponse`] impl.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use asterism_core::DescriptorError;

use crate::elements_wallet::ElementsWalletError;
use crate::hsm::HsmError;
use crate::wallet::WalletError;

/// Top-level error type for the web app.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// Database error.
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),

    /// Session-store error.
    #[error("session error: {0}")]
    Session(#[from] tower_sessions::session::Error),

    /// Template rendering error.
    #[error("template render error: {0}")]
    Render(#[from] askama::Error),

    /// Password hashing / verification error.
    #[error("password hashing error: {0}")]
    PasswordHash(String),

    /// Wallet-layer (BDK / RPC / send pipeline) error.
    #[error("wallet error: {0}")]
    Wallet(#[from] WalletError),

    /// HSM-layer error (PKCS#11 / token init / signer derivation).
    #[error("HSM error: {0}")]
    Hsm(#[from] HsmError),

    /// `asterism-core` descriptor builder rejected the federation.
    #[error("descriptor builder rejected federation: {0}")]
    DescriptorBuilderRejected(#[from] DescriptorError),

    /// Elements wallet-layer error.
    #[error("elements wallet error: {0}")]
    ElementsWallet(#[from] ElementsWalletError),

    /// Resource not found (404).
    #[error("not found: {0}")]
    NotFound(String),

    /// Bad input from the user (400). Carries the user-visible reason.
    #[error("bad request: {0}")]
    BadRequest(String),
}

impl From<password_hash::Error> for AppError {
    fn from(e: password_hash::Error) -> Self {
        Self::PasswordHash(e.to_string())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match &self {
            Self::NotFound(what) => {
                tracing::debug!(target = %what, "404");
                (StatusCode::NOT_FOUND, format!("Not found: {what}")).into_response()
            }
            Self::BadRequest(msg) => {
                tracing::debug!(reason = %msg, "400");
                (StatusCode::BAD_REQUEST, msg.clone()).into_response()
            }
            Self::Wallet(WalletError::NotFound(_)) => {
                tracing::debug!(error = %self, "404 wallet missing");
                (StatusCode::NOT_FOUND, "Wallet not found").into_response()
            }
            Self::Wallet(WalletError::BadAddress { .. } | WalletError::BadFeeRate { .. }) => {
                tracing::debug!(error = %self, "400 wallet validation");
                (StatusCode::BAD_REQUEST, format!("{self}")).into_response()
            }
            Self::Wallet(
                WalletError::BuildTx(_) | WalletError::BadAmount { .. } | WalletError::Sign(_),
            ) => {
                tracing::debug!(error = %self, "400 send validation");
                (StatusCode::BAD_REQUEST, format!("{self}")).into_response()
            }
            Self::Wallet(WalletError::BroadcastRejected(reason)) => {
                tracing::warn!(%reason, "502 broadcast rejected");
                (
                    StatusCode::BAD_GATEWAY,
                    format!("bitcoind rejected broadcast: {reason}"),
                )
                    .into_response()
            }
            _ => {
                tracing::error!(error = %self, "request failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
            }
        }
    }
}
