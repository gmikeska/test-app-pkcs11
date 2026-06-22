//! Elements wallet routes — mirrors `handlers::wallet` for the Liquid/Elements
//! chain.
//!
//! - `GET  /elements/wallet/receive`               — balance + first 20 CT addresses.
//! - `GET  /elements/wallet/send`                  — send form + recent transactions.
//! - `POST /elements/wallet/send`                  — build PSET → sign → broadcast.
//! - `GET  /elements/wallet/addresses/:address`     — per-address QR + receipts.

use std::sync::Arc;

use askama::Template;
use askama_web::WebTemplate;
use axum::Form;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use qrcode::QrCode;
use qrcode::render::svg;
use serde::{Deserialize, Serialize};

use crate::auth::AuthUser;
use crate::db;
use crate::elements_wallet::ElementsAddressReceipt;
use crate::error::AppError;
use crate::models::ElementsTransactionRow;
use crate::state::AppState;

pub const REVEAL_COUNT: u32 = 20;

// ---------------------------------------------------------------------------
// View-models
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Clone)]
pub struct ElementsWalletHeader {
    pub email: String,
    pub account_idx: i32,
    pub network: String,
    pub descriptor: String,
    pub tip_height: u64,
    pub active_tab: &'static str,
}

#[derive(Debug, Serialize, Clone)]
pub struct ElementsBalanceView {
    pub total_btc: String,
    pub spendable_btc: String,
    pub confirmed_btc: String,
    pub pending_btc: String,
    pub immature_btc: String,
    pub has_pending: bool,
}

#[derive(Debug, Serialize, Clone)]
pub struct ElementsAddressView {
    pub index: u32,
    pub address: String,
    pub address_short: String,
    pub received_btc: String,
    pub unspent_btc: String,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct FlashBanner {
    pub message: String,
    pub kind: String,
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

#[derive(Template, WebTemplate)]
#[template(path = "elements_wallet_receive.html")]
struct ReceiveTemplate {
    header: ElementsWalletHeader,
    balance: ElementsBalanceView,
    addresses: Vec<ElementsAddressView>,
    flash: Option<FlashBanner>,
}

#[derive(Template, WebTemplate)]
#[template(path = "elements_wallet_send.html")]
struct SendTemplate {
    header: ElementsWalletHeader,
    balance: ElementsBalanceView,
    transactions: Vec<ElementsTransactionListView>,
    flash: Option<FlashBanner>,
}

#[derive(Template, WebTemplate)]
#[template(path = "elements_address.html")]
struct AddressTemplate {
    header: ElementsWalletHeader,
    email: String,
    address: ElementsAddressDetailView,
    receipts: Vec<ElementsReceiptView>,
}

#[derive(Debug, Serialize, Clone)]
pub struct ElementsTransactionListView {
    pub txid: String,
    pub recipient: String,
    pub amount_btc: String,
    pub fee_btc: String,
    pub label: String,
    pub broadcast_at: String,
}

impl From<ElementsTransactionRow> for ElementsTransactionListView {
    fn from(row: ElementsTransactionRow) -> Self {
        Self {
            txid: row.txid,
            recipient: row.recipient,
            amount_btc: format_btc_sats(row.amount_sat),
            fee_btc: format_btc_sats(row.fee_sat),
            label: row.label.unwrap_or_default(),
            broadcast_at: row.broadcast_at.format("%Y-%m-%d %H:%M UTC").to_string(),
        }
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct ElementsAddressDetailView {
    pub address: String,
    pub qr_uri: String,
    pub qr_svg: String,
    pub derivation_index: Option<u32>,
    pub total_received_btc: String,
    pub unspent_btc: String,
    pub receipt_count: usize,
}

#[derive(Debug, Serialize, Clone)]
pub struct ElementsReceiptView {
    pub txid: String,
    pub vout: u32,
    pub amount_btc: String,
    pub status: String,
    pub is_spent: bool,
}

impl From<ElementsAddressReceipt> for ElementsReceiptView {
    fn from(r: ElementsAddressReceipt) -> Self {
        let status = if r.confirmations == 0 {
            "Mempool".to_string()
        } else {
            let plural = if r.confirmations == 1 {
                "conf"
            } else {
                "confs"
            };
            format!("{} {plural}", r.confirmations)
        };
        Self {
            txid: r.txid,
            vout: r.vout,
            amount_btc: format!("{:.8}", r.amount),
            status,
            is_spent: r.is_spent,
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub async fn receive(
    State(state): State<Arc<AppState>>,
    AuthUser(user): AuthUser,
) -> Result<Response, AppError> {
    let uw = state.elements_wallet_manager.load_or_init(user.id).await?;
    let tip_height = uw.tip_height().await?;
    let revealed = uw.reveal_addresses(REVEAL_COUNT).await?;
    let balances = uw.balance().await?;

    let addresses = revealed
        .into_iter()
        .map(|a| {
            let address_short = abbreviate_address(&a.address, 12, 8);
            ElementsAddressView {
                index: a.index,
                address: a.address,
                address_short,
                received_btc: format!("{:.8}", a.received),
                unspent_btc: format!("{:.8}", a.unspent),
            }
        })
        .collect();

    let total = balances.trusted + balances.untrusted_pending + balances.immature;
    let has_pending = (balances.untrusted_pending + balances.immature) > 0.000_000_01;
    let balance_view = ElementsBalanceView {
        total_btc: format!("{total:.8}"),
        spendable_btc: format!("{:.8}", balances.trusted),
        confirmed_btc: format!("{:.8}", balances.trusted),
        pending_btc: format!("{:.8}", balances.untrusted_pending),
        immature_btc: format!("{:.8}", balances.immature),
        has_pending,
    };

    Ok(ReceiveTemplate {
        header: ElementsWalletHeader {
            email: user.email,
            account_idx: uw.account_idx(),
            network: uw.network().to_string(),
            descriptor: uw.descriptor().to_string(),
            tip_height,
            active_tab: "receive",
        },
        balance: balance_view,
        addresses,
        flash: None,
    }
    .into_response())
}

pub async fn send_get(
    State(state): State<Arc<AppState>>,
    AuthUser(user): AuthUser,
) -> Result<Response, AppError> {
    let uw = state.elements_wallet_manager.load_or_init(user.id).await?;
    let tip_height = uw.tip_height().await?;
    let balances = uw.balance().await?;

    let txs = db::list_elements_transactions_for_wallet(&state.db, uw.wallet_id())
        .await?
        .into_iter()
        .map(ElementsTransactionListView::from)
        .collect();

    let total = balances.trusted + balances.untrusted_pending + balances.immature;
    let has_pending = (balances.untrusted_pending + balances.immature) > 0.000_000_01;
    let balance_view = ElementsBalanceView {
        total_btc: format!("{total:.8}"),
        spendable_btc: format!("{:.8}", balances.trusted),
        confirmed_btc: format!("{:.8}", balances.trusted),
        pending_btc: format!("{:.8}", balances.untrusted_pending),
        immature_btc: format!("{:.8}", balances.immature),
        has_pending,
    };

    Ok(SendTemplate {
        header: ElementsWalletHeader {
            email: user.email,
            account_idx: uw.account_idx(),
            network: uw.network().to_string(),
            descriptor: uw.descriptor().to_string(),
            tip_height,
            active_tab: "send",
        },
        balance: balance_view,
        transactions: txs,
        flash: None,
    }
    .into_response())
}

#[derive(Debug, Deserialize)]
pub struct SendForm {
    pub recipient_address: String,
    pub amount_btc: String,
    pub fee_rate_sat_vb: u64,
    #[serde(default)]
    pub label: Option<String>,
}

pub async fn send_post(
    State(state): State<Arc<AppState>>,
    AuthUser(user): AuthUser,
    Form(form): Form<SendForm>,
) -> Result<Response, AppError> {
    if form.fee_rate_sat_vb == 0 {
        return Err(AppError::BadRequest(
            "fee_rate_sat_vb must be at least 1".to_string(),
        ));
    }
    let uw = state.elements_wallet_manager.load_or_init(user.id).await?;

    let amount: f64 = form
        .amount_btc
        .trim()
        .parse()
        .map_err(|_| AppError::BadRequest(format!("invalid amount `{}`", form.amount_btc)))?;
    if amount <= 0.0 {
        return Err(AppError::BadRequest("amount must be positive".to_string()));
    }

    let label = form
        .label
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let result = uw
        .build_sign_and_broadcast(
            form.recipient_address.trim(),
            amount,
            form.fee_rate_sat_vb,
            label,
        )
        .await?;

    tracing::info!(
        user = %user.email,
        txid = %result.txid,
        recipient = %result.recipient,
        amount_sat = result.amount_sat,
        "broadcast Elements tx"
    );

    Ok(Redirect::to(&format!("/elements/wallet/transactions/{}", result.txid)).into_response())
}

pub async fn address_show(
    State(state): State<Arc<AppState>>,
    AuthUser(user): AuthUser,
    Path(address_raw): Path<String>,
) -> Result<Response, AppError> {
    let uw = state.elements_wallet_manager.load_or_init(user.id).await?;
    let tip_height = uw.tip_height().await?;

    let revealed = uw.reveal_addresses(REVEAL_COUNT).await?;
    let derivation_index = revealed
        .iter()
        .find(|a| a.address == address_raw)
        .map(|a| a.index);

    let activity = uw.address_history(&address_raw).await?;

    let qr_uri = format!("liquidnetwork:{address_raw}");
    let qr_svg = QrCode::new(qr_uri.as_bytes())
        .map_err(|e| AppError::BadRequest(format!("Failed to encode QR: {e}")))?
        .render::<svg::Color<'_>>()
        .min_dimensions(220, 220)
        .quiet_zone(true)
        .dark_color(svg::Color("#0b0d12"))
        .light_color(svg::Color("#f4f6fb"))
        .build();

    let receipt_count = activity.receipts.len();
    let total_received = activity.total_received;
    let unspent = activity.unspent;
    let receipts: Vec<ElementsReceiptView> = activity
        .receipts
        .into_iter()
        .map(ElementsReceiptView::from)
        .collect();

    Ok(AddressTemplate {
        header: ElementsWalletHeader {
            email: user.email.clone(),
            account_idx: uw.account_idx(),
            network: uw.network().to_string(),
            descriptor: uw.descriptor().to_string(),
            tip_height,
            active_tab: "receive",
        },
        email: user.email,
        address: ElementsAddressDetailView {
            address: address_raw,
            qr_uri,
            qr_svg,
            derivation_index,
            total_received_btc: format!("{total_received:.8}"),
            unspent_btc: format!("{unspent:.8}"),
            receipt_count,
        },
        receipts,
    }
    .into_response())
}

fn format_btc_sats(sat: i64) -> String {
    let sat_u = u64::try_from(sat).unwrap_or(0);
    format!("{:.8}", bitcoin::Amount::from_sat(sat_u).to_btc())
}

fn abbreviate_address(addr: &str, prefix_len: usize, suffix_len: usize) -> String {
    if addr.len() <= prefix_len + suffix_len + 3 {
        return addr.to_string();
    }
    format!(
        "{}…{}",
        &addr[..prefix_len],
        &addr[addr.len() - suffix_len..]
    )
}
