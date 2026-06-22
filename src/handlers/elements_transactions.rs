//! Elements transaction-detail handler.

use std::sync::Arc;

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::auth::AuthUser;
use crate::db;
use crate::error::AppError;
use crate::handlers::elements_wallet::ElementsWalletHeader;
use crate::models::ElementsTransactionRow;
use crate::state::AppState;

#[derive(Template, WebTemplate)]
#[template(path = "elements_transaction.html")]
struct TransactionTemplate {
    header: ElementsWalletHeader,
    email: String,
    transaction: ElementsTransactionDetailView,
}

#[derive(Debug, Serialize, Clone)]
pub struct ElementsTransactionDetailView {
    pub txid: String,
    pub recipient: String,
    pub amount_btc: String,
    pub fee_btc: String,
    pub label: String,
    pub broadcast_at: String,
    pub raw_tx_hex: String,
}

impl From<ElementsTransactionRow> for ElementsTransactionDetailView {
    fn from(row: ElementsTransactionRow) -> Self {
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

pub async fn show(
    State(state): State<Arc<AppState>>,
    AuthUser(user): AuthUser,
    Path(txid): Path<String>,
) -> Result<Response, AppError> {
    let uw = state.elements_wallet_manager.load_or_init(user.id).await?;
    let row = db::find_elements_transaction(&state.db, uw.wallet_id(), &txid)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("elements transaction {txid}")))?;

    let tip_height = uw.tip_height().await?;

    let policy = {
        let t = state.config.fed_threshold;
        let n = state.config.hsm_tokens.len();
        format!("{t}-of-{n} (HSMs)")
    };

    Ok(TransactionTemplate {
        header: ElementsWalletHeader {
            email: user.email.clone(),
            account_idx: uw.account_idx(),
            network: uw.network().to_string(),
            descriptor: uw.descriptor().to_string(),
            tip_height,
            active_tab: "send",
            policy,
        },
        email: user.email,
        transaction: ElementsTransactionDetailView::from(row),
    }
    .into_response())
}

fn format_btc_sats(sat: i64) -> String {
    let sat_u = u64::try_from(sat).unwrap_or(0);
    format!("{:.8}", bitcoin::Amount::from_sat(sat_u).to_btc())
}
