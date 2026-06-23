//! Wallet routes.
//!
//! - `GET  /wallet/receive`           — balance + first 20 addresses.
//! - `GET  /wallet/send`              — send form + recent transactions.
//! - `POST /wallet/send`              — build → sign → broadcast.
//! - `GET  /wallet/addresses/:address`— per-address QR + receipts.

use std::sync::Arc;

use askama::Template;
use askama_web::WebTemplate;
use axum::Form;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use bdk_wallet::KeychainKind;
use bitcoin::Txid;
use qrcode::QrCode;
use qrcode::render::svg;
use serde::{Deserialize, Serialize};

use crate::auth::AuthUser;
use crate::db;
use crate::error::AppError;
use crate::models::TransactionRow;
use crate::state::AppState;
use crate::wallet::{AddressReceipt, REVEAL_COUNT};

// ---------------------------------------------------------------------------
// Shared view-models
// ---------------------------------------------------------------------------

/// Card-header info shared by every wallet template.
#[derive(Debug, Serialize, Clone)]
pub struct WalletHeader {
    /// Logged-in user email (rendered in the topbar).
    pub email: String,
    /// Wallet's BIP-48 account index.
    pub account_idx: i32,
    /// Network short name ("regtest" / "testnet" / "bitcoin").
    pub network: String,
    /// Multipath descriptor as a string.
    pub descriptor: String,
    /// Latest-known chain tip height.
    pub tip_height: u32,
    /// Currently-active tab ("receive" / "send").
    pub active_tab: &'static str,
    /// Federation policy label, e.g. "3-of-5 (HSMs)".
    pub policy: String,
}

/// Pretty-formatted balance card values.
#[derive(Debug, Serialize, Clone)]
pub struct BalanceView {
    /// Total = `confirmed + trusted_pending + untrusted_pending + immature`.
    pub total_btc: String,
    /// Spendable amount (`confirmed + trusted_pending`).
    pub spendable_btc: String,
    /// Confirmed only.
    pub confirmed_btc: String,
    /// Trusted pending (change from outgoing).
    pub trusted_pending_btc: String,
    /// Untrusted pending.
    pub untrusted_pending_btc: String,
    /// Immature coinbase outputs.
    pub immature_btc: String,
    /// Whether to show the breakdown panel (any non-confirmed value present).
    pub has_pending: bool,
}

impl From<bdk_wallet::Balance> for BalanceView {
    fn from(b: bdk_wallet::Balance) -> Self {
        let total = b.confirmed + b.trusted_pending + b.untrusted_pending + b.immature;
        let spendable = b.confirmed + b.trusted_pending;
        let has_pending = (b.trusted_pending + b.untrusted_pending + b.immature).to_sat() > 0;
        Self {
            total_btc: format_btc(total),
            spendable_btc: format_btc(spendable),
            confirmed_btc: format_btc(b.confirmed),
            trusted_pending_btc: format_btc(b.trusted_pending),
            untrusted_pending_btc: format_btc(b.untrusted_pending),
            immature_btc: format_btc(b.immature),
            has_pending,
        }
    }
}

/// One row in the receive-tab address list.
#[derive(Debug, Serialize, Clone)]
pub struct AddressView {
    /// Derivation index.
    pub index: u32,
    /// Bech32 string.
    pub address: String,
    /// Total received.
    pub received_btc: String,
    /// Currently-unspent.
    pub unspent_btc: String,
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

/// Optional flash banner shown after a redirect.
#[derive(Debug, Default, Clone, Serialize)]
pub struct FlashBanner {
    /// Plain-text message.
    pub message: String,
    /// Optional CSS class extension (e.g. `"alert-error"` / `"alert-info"`).
    pub kind: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "wallet_receive.html")]
struct ReceiveTemplate {
    header: WalletHeader,
    balance: BalanceView,
    addresses: Vec<AddressView>,
    change_addresses: Vec<AddressView>,
    flash: Option<FlashBanner>,
}

#[derive(Template, WebTemplate)]
#[template(path = "wallet_send.html")]
struct SendTemplate {
    header: WalletHeader,
    balance: BalanceView,
    transactions: Vec<TransactionListView>,
    flash: Option<FlashBanner>,
}

#[derive(Template, WebTemplate)]
#[template(path = "address.html")]
struct AddressTemplate {
    header: WalletHeader,
    email: String,
    address: AddressDetailView,
    receipts: Vec<ReceiptView>,
}

#[derive(Template, WebTemplate)]
#[template(path = "wallet_federation.html")]
struct FederationTemplate {
    header: WalletHeader,
    balance: BalanceView,
    current: FederationVersionView,
    versions: Vec<FederationHistoryView>,
    version_count: usize,
    flash: Option<FlashBanner>,
}

#[derive(Debug, Serialize, Clone)]
pub struct SignerView {
    pub id: String,
    pub label: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct FederationVersionView {
    pub version_index: i32,
    pub threshold: i32,
    pub signer_count: i32,
    pub signers: Vec<SignerView>,
}

#[derive(Debug, Serialize, Clone)]
pub struct FederationHistoryView {
    pub version_index: i32,
    pub threshold: i32,
    pub signer_count: i32,
    pub descriptor_short: String,
    pub created_at: String,
    pub is_current: bool,
    pub migration_status: String,
}

/// Row for the recent-transactions table on the send tab.
#[derive(Debug, Serialize, Clone)]
pub struct TransactionListView {
    /// Bitcoin txid as hex.
    pub txid: String,
    /// Truncated recipient.
    pub recipient: String,
    /// Amount paid (BTC).
    pub amount_btc: String,
    /// Fee paid (BTC).
    pub fee_btc: String,
    /// Optional label.
    pub label: String,
    /// Pretty timestamp.
    pub broadcast_at: String,
}

impl From<TransactionRow> for TransactionListView {
    fn from(row: TransactionRow) -> Self {
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
pub struct AddressDetailView {
    /// Bech32 string.
    pub address: String,
    /// `bitcoin:<addr>` URI (QR payload).
    pub qr_uri: String,
    /// Pre-rendered SVG.
    pub qr_svg: String,
    /// Derivation index, if known.
    pub derivation_index: Option<u32>,
    /// Keychain label ("external" / "change" / "—").
    pub keychain: String,
    /// Total received, BTC.
    pub total_received_btc: String,
    /// Currently unspent, BTC.
    pub unspent_btc: String,
    /// Receipt count.
    pub receipt_count: usize,
}

#[derive(Debug, Serialize, Clone)]
pub struct ReceiptView {
    pub txid: String,
    pub vout: u32,
    pub amount_btc: String,
    pub status: String,
    pub height: String,
    pub is_spent: bool,
}

impl From<AddressReceipt> for ReceiptView {
    fn from(r: AddressReceipt) -> Self {
        let status = r.confirmation_height.map_or_else(
            || "Mempool".to_string(),
            |h| {
                let confs = r.confirmations;
                let plural = if confs == 1 { "conf" } else { "confs" };
                format!("{confs} {plural} (h={h})")
            },
        );
        let height = r
            .confirmation_height
            .map_or_else(|| "—".to_string(), |h| h.to_string());
        Self {
            txid: r.txid.to_string(),
            vout: r.vout,
            amount_btc: format_btc(r.amount),
            status,
            height,
            is_spent: r.is_spent,
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /wallet/receive`
///
/// # Errors
/// Surfaces wallet/DB errors via [`AppError`].
pub async fn receive(
    State(state): State<Arc<AppState>>,
    AuthUser(user): AuthUser,
) -> Result<Response, AppError> {
    let uw = state.wallet_manager.load_or_init(user.id).await?;
    uw.sync().await?;
    let revealed = uw.reveal_addresses(REVEAL_COUNT).await?;
    let balance = uw.balance().await;
    let tip_height = uw.tip_height().await;

    let descriptor = lookup_descriptor(&state, user.id).await?;

    let addresses = revealed
        .into_iter()
        .map(|a| AddressView {
            index: a.index,
            address: a.address,
            received_btc: format_btc(a.received),
            unspent_btc: format_btc(a.unspent),
        })
        .collect();

    let change_addresses = uw
        .change_addresses()
        .await
        .into_iter()
        .map(|a| AddressView {
            index: a.index,
            address: a.address,
            received_btc: format_btc(a.received),
            unspent_btc: format_btc(a.unspent),
        })
        .collect();

    Ok(ReceiveTemplate {
        header: WalletHeader {
            email: user.email,
            account_idx: uw.account_idx(),
            network: state.config.network.to_string(),
            descriptor,
            tip_height,
            active_tab: "receive",
            policy: policy_label(&state),
        },
        balance: BalanceView::from(balance),
        addresses,
        change_addresses,
        flash: None,
    }
    .into_response())
}

/// `GET /wallet/send`
///
/// # Errors
/// Surfaces wallet/DB errors via [`AppError`].
pub async fn send_get(
    State(state): State<Arc<AppState>>,
    AuthUser(user): AuthUser,
) -> Result<Response, AppError> {
    let uw = state.wallet_manager.load_or_init(user.id).await?;
    uw.sync().await?;
    let balance = uw.balance().await;
    let tip_height = uw.tip_height().await;

    let descriptor = lookup_descriptor(&state, user.id).await?;
    let txs = db::list_transactions_for_wallet(&state.db, uw.wallet_id())
        .await?
        .into_iter()
        .map(TransactionListView::from)
        .collect();

    Ok(SendTemplate {
        header: WalletHeader {
            email: user.email,
            account_idx: uw.account_idx(),
            network: state.config.network.to_string(),
            descriptor,
            tip_height,
            active_tab: "send",
            policy: policy_label(&state),
        },
        balance: BalanceView::from(balance),
        transactions: txs,
        flash: None,
    }
    .into_response())
}

/// `POST /wallet/send` form.
#[derive(Debug, Deserialize)]
pub struct SendForm {
    /// Destination address (validated against the wallet's network).
    pub recipient_address: String,
    /// Amount, decimal BTC string.
    pub amount_btc: String,
    /// Fee rate (sat/vB).
    pub fee_rate_sat_vb: u64,
    /// Optional label.
    #[serde(default)]
    pub label: Option<String>,
}

/// `POST /wallet/send`
///
/// # Errors
/// Bad input → `400`; broadcast rejection → `502`; everything else → `500`.
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
    let uw = state.wallet_manager.load_or_init(user.id).await?;
    uw.sync().await?;

    let address = uw.parse_address(form.recipient_address.trim())?;
    let amount = parse_btc_amount(form.amount_btc.trim())?;
    let label = form
        .label
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let result = uw
        .build_sign_and_broadcast(&address, amount, form.fee_rate_sat_vb, label)
        .await?;

    tracing::info!(
        user = %user.email,
        txid = %result.txid,
        recipient = %result.recipient,
        amount_sat = result.amount_sat,
        "broadcast tx"
    );

    Ok(Redirect::to(&format!("/wallet/transactions/{}", result.txid)).into_response())
}

/// `GET /wallet/addresses/:address`
///
/// # Errors
/// Bad/unknown addresses → `404`; QR build errors → `400`; otherwise `500`.
pub async fn address_show(
    State(state): State<Arc<AppState>>,
    AuthUser(user): AuthUser,
    Path(address_raw): Path<String>,
) -> Result<Response, AppError> {
    let uw = state.wallet_manager.load_or_init(user.id).await?;
    uw.sync().await?;
    let _ = uw.reveal_addresses(REVEAL_COUNT).await?;

    let address = uw.parse_address(&address_raw)?;
    let derivation = uw.locate_address(&address).await;
    if derivation.is_none() {
        return Err(AppError::NotFound(format!(
            "address {address_raw} for wallet of {}",
            user.email
        )));
    }
    let (keychain, index) = derivation.map_or((None, None), |(k, i)| (Some(k), Some(i)));
    let keychain_str = keychain.map_or_else(|| "—".to_string(), keychain_label);

    let activity = uw.address_history(&address).await?;
    let descriptor = lookup_descriptor(&state, user.id).await?;
    let tip_height = activity.tip_height;

    let qr_uri = format!("bitcoin:{address}");
    let qr_svg = QrCode::new(qr_uri.as_bytes())
        .map_err(|e| AppError::BadRequest(format!("Failed to encode QR: {e}")))?
        .render::<svg::Color<'_>>()
        .min_dimensions(220, 220)
        .quiet_zone(true)
        .dark_color(svg::Color("#0b0d12"))
        .light_color(svg::Color("#f4f6fb"))
        .build();

    let receipts = activity
        .receipts
        .iter()
        .cloned()
        .map(ReceiptView::from)
        .collect();

    Ok(AddressTemplate {
        header: WalletHeader {
            email: user.email.clone(),
            account_idx: uw.account_idx(),
            network: state.config.network.to_string(),
            descriptor,
            tip_height,
            active_tab: "receive",
            policy: policy_label(&state),
        },
        email: user.email,
        address: AddressDetailView {
            address: address.to_string(),
            qr_uri,
            qr_svg,
            derivation_index: index,
            keychain: keychain_str,
            total_received_btc: format_btc(activity.total_received),
            unspent_btc: format_btc(activity.unspent),
            receipt_count: activity.receipts.len(),
        },
        receipts,
    }
    .into_response())
}

/// `GET /wallet/federation`
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub async fn federation(
    State(state): State<Arc<AppState>>,
    AuthUser(user): AuthUser,
) -> Result<Response, AppError> {
    let uw = state.wallet_manager.load_or_init(user.id).await?;
    uw.sync().await?;
    let balance = uw.balance().await;
    let tip_height = uw.tip_height().await;
    let descriptor = lookup_descriptor(&state, user.id).await?;

    let versions = db::list_federation_versions_for_wallet(&state.db, uw.wallet_id()).await?;
    let version_count = versions.len();

    let current_fed = uw.federation();
    let current = FederationVersionView {
        version_index: version_count.saturating_sub(1) as i32,
        threshold: current_fed.threshold() as i32,
        signer_count: current_fed.total_signers() as i32,
        signers: build_signer_views(current_fed, &state),
    };

    let history: Vec<FederationHistoryView> = versions
        .iter()
        .map(|v| {
            let is_current = v.version_index == (version_count.saturating_sub(1) as i32);
            FederationHistoryView {
                version_index: v.version_index,
                threshold: v.threshold,
                signer_count: v.signer_count,
                descriptor_short: truncate_descriptor(&v.descriptor, 40),
                created_at: v.created_at.format("%Y-%m-%d %H:%M UTC").to_string(),
                is_current,
                migration_status: v.migration_status.clone(),
            }
        })
        .collect();

    Ok(FederationTemplate {
        header: WalletHeader {
            email: user.email,
            account_idx: uw.account_idx(),
            network: state.config.network.to_string(),
            descriptor,
            tip_height,
            active_tab: "federation",
            policy: policy_label(&state),
        },
        balance: BalanceView::from(balance),
        current,
        versions: history,
        version_count,
        flash: None,
    }
    .into_response())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_signer_views(
    federation: &asterism_core::Federation<crate::wallet::NetworkPatchedSigner>,
    state: &AppState,
) -> Vec<SignerView> {
    use asterism_core::signer::Signer;
    federation
        .signers()
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let id_str = s.id().as_str().to_string();
            let label = state
                .config
                .hsm_tokens
                .get(i)
                .map(|t| t.label.clone())
                .unwrap_or_default();
            SignerView { id: id_str, label }
        })
        .collect()
}

fn truncate_descriptor(desc: &str, max_len: usize) -> String {
    if desc.len() <= max_len {
        desc.to_string()
    } else {
        let half = max_len / 2;
        format!("{}...{}", &desc[..half], &desc[desc.len() - half..])
    }
}

fn policy_label(state: &AppState) -> String {
    let t = state.config.fed_threshold;
    let n = state.config.hsm_tokens.len();
    format!("{t}-of-{n} (HSMs)")
}

async fn lookup_descriptor(state: &Arc<AppState>, user_id: uuid::Uuid) -> Result<String, AppError> {
    let row = db::find_wallet_for_user(&state.db, user_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("wallet for user {user_id}")))?;
    Ok(row.descriptor)
}

fn keychain_label(k: KeychainKind) -> String {
    match k {
        KeychainKind::External => "external".to_string(),
        KeychainKind::Internal => "change".to_string(),
    }
}

fn format_btc(amount: bitcoin::Amount) -> String {
    format!("{:.8}", amount.to_btc())
}

fn format_btc_sats(sat: i64) -> String {
    let sat_u = u64::try_from(sat).unwrap_or(0);
    format!("{:.8}", bitcoin::Amount::from_sat(sat_u).to_btc())
}

fn parse_btc_amount(input: &str) -> Result<bitcoin::Amount, AppError> {
    bitcoin::Amount::from_str_in(input, bitcoin::Denomination::Bitcoin)
        .map_err(|e| AppError::BadRequest(format!("invalid BTC amount `{input}`: {e}")))
}

#[allow(dead_code)]
fn _txid_str(t: &Txid) -> String {
    t.to_string()
}
