//! Transaction-detail handler.
//!
//! - `GET /wallet/transactions/:txid` — render the txid, recipient, amount,
//!   fee, optional label, broadcast time, and raw hex for one of the
//!   logged-in user's broadcasts.

use std::sync::Arc;

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::auth::AuthUser;
use crate::db;
use crate::error::AppError;
use crate::handlers::wallet::WalletHeader;
use crate::models::TransactionRow;
use crate::state::AppState;

/// Transaction-detail template.
#[derive(Template, WebTemplate)]
#[template(path = "transaction.html")]
struct TransactionTemplate {
    /// Wallet header (no balance/tab indicator on this page).
    header: WalletHeader,
    /// Logged-in email.
    email: String,
    /// Transaction view-model.
    transaction: TransactionDetailView,
}

/// View-model rendered for a single broadcast transaction.
#[derive(Debug, Serialize, Clone)]
pub struct TransactionDetailView {
    pub txid: String,
    pub recipient: String,
    pub amount_btc: String,
    pub fee_btc: String,
    pub label: String,
    pub broadcast_at: String,
    pub raw_tx_hex: String,
}

impl From<TransactionRow> for TransactionDetailView {
    fn from(row: TransactionRow) -> Self {
        Self {
            txid: row.txid,
            recipient: row.recipient,
            amount_btc: format_btc_sats(row.amount_sat),
            fee_btc: format_btc_sats(row.fee_sat),
            label: row.label.unwrap_or_default(),
            broadcast_at: row.broadcast_at.format("%Y-%m-%d %H:%M UTC").to_string(),
            raw_tx_hex: row.raw_tx_hex,
        }
    }
}

/// `GET /wallet/transactions/:txid`
///
/// # Errors
/// Surfaces DB errors and 404s for unknown transactions.
pub async fn show(
    State(state): State<Arc<AppState>>,
    AuthUser(user): AuthUser,
    Path(txid): Path<String>,
) -> Result<Response, AppError> {
    let uw = state.wallet_manager.load_or_init(user.id).await?;
    let row = db::find_transaction(&state.db, uw.wallet_id(), &txid)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("transaction {txid}")))?;

    let descriptor = match db::find_wallet_for_user(&state.db, user.id).await? {
        Some(w) => w.descriptor,
        None => String::new(),
    };

    let policy = {
        let t = state.config.fed_threshold;
        let n = state.config.hsm_tokens.len();
        format!("{t}-of-{n} (HSMs)")
    };

    Ok(TransactionTemplate {
        header: WalletHeader {
            email: user.email.clone(),
            account_idx: uw.account_idx(),
            network: state.config.network.to_string(),
            descriptor,
            tip_height: uw.tip_height().await,
            active_tab: "send",
            policy,
        },
        email: user.email,
        transaction: TransactionDetailView::from(row),
    }
    .into_response())
}

fn format_btc_sats(sat: i64) -> String {
    let sat_u = u64::try_from(sat).unwrap_or(0);
    format!("{:.8}", bitcoin::Amount::from_sat(sat_u).to_btc())
}
