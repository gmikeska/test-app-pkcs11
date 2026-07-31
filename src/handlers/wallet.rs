//! Wallet routes.
//!
//! - `GET  /wallet/receive`           — balance + first 20 addresses.
//! - `GET  /wallet/send`              — send form + recent transactions.
//! - `POST /wallet/send`              — build → sign → broadcast.
//! - `GET  /wallet/addresses/:address`— per-address QR + receipts.

use std::sync::Arc;

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Form, Json};
use emvault::core::bdk_wallet::{self, KeychainKind};
use emvault::core::bitcoin::{self, Txid};
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

/// Addresses grouped by federation version for the tabbed receive page.
#[derive(Debug, Serialize, Clone)]
pub struct FederationAddressGroup {
    /// Federation version index (0 = oldest).
    pub version: usize,
    /// Tab label, e.g. "v3 (current)" or "v2".
    pub label: String,
    /// Whether this is the newest (current) federation.
    pub is_current: bool,
    /// External keychain addresses for this federation.
    pub addresses: Vec<AddressView>,
    /// Change addresses with funds for this federation.
    pub change_addresses: Vec<AddressView>,
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
    federation_groups: Vec<FederationAddressGroup>,
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
    /// Full BIP-48 derivation path, e.g. `m/48'/1'/0'/2'/0/0`.
    pub derivation_path: String,
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
    use emvault::core::federated_wallet::FederatedWallet as _;

    let uw = state.wallet_manager.load_or_init(user.id).await?;
    uw.sync().await?;
    let _revealed = uw.reveal_addresses(REVEAL_COUNT).await?;
    let balance = uw.balance().await;
    let tip_height = uw.tip_height().await;

    let descriptor = lookup_descriptor(&state, user.id).await?;

    let fw = uw.federated_wallet();
    let total_versions = fw.federation_count();
    let change_addrs = uw.change_addresses().await;

    let revealed = uw.revealed_addresses_all_versions(REVEAL_COUNT).await;

    let mut federation_groups: Vec<FederationAddressGroup> = revealed
        .into_iter()
        .rev()
        .map(|(version_idx, addrs)| {
            let is_current = version_idx == total_versions - 1;
            let label = if is_current {
                format!("v{} (current)", version_idx + 1)
            } else {
                format!("v{}", version_idx + 1)
            };

            let addresses = addrs
                .into_iter()
                .map(|a| AddressView {
                    index: a.index,
                    address: a.address,
                    received_btc: format_btc(a.received),
                    unspent_btc: format_btc(a.unspent),
                })
                .collect();

            FederationAddressGroup {
                version: version_idx,
                label,
                is_current,
                addresses,
                change_addresses: Vec::new(),
            }
        })
        .collect();

    if let Some(current_group) = federation_groups.iter_mut().find(|g| g.is_current) {
        current_group.change_addresses = change_addrs
            .into_iter()
            .map(|a| AddressView {
                index: a.index,
                address: a.address,
                received_btc: format_btc(a.received),
                unspent_btc: format_btc(a.unspent),
            })
            .collect();
    }

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
        federation_groups,
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
    // No sync here: the Send *form* renders instantly off the shared cached
    // wallet (Receive/dashboard keep it fresh). The actual send in `send_post`
    // still syncs before building the tx, so spends use current UTXOs.
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
    /// `"true"` when the **Max** button armed a full-balance drain; the amount
    /// field is then ignored and the wallet is swept to the recipient.
    #[serde(default)]
    pub send_max: Option<String>,
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
    let label = form
        .label
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    // "Send Max" drains the whole balance to the recipient (fee out of the
    // swept amount); otherwise send the requested amount.
    let result = if matches!(form.send_max.as_deref(), Some("true")) {
        uw.sweep_to(&address, form.fee_rate_sat_vb, label).await?
    } else {
        let amount = parse_btc_amount(form.amount_btc.trim())?;
        uw.build_sign_and_broadcast(&address, amount, form.fee_rate_sat_vb, label)
            .await?
    };

    tracing::info!(
        user = %user.email,
        txid = %result.txid,
        recipient = %result.recipient,
        amount_sat = result.amount_sat,
        "broadcast tx"
    );

    Ok(Redirect::to(&format!("/wallet/transactions/{}", result.txid)).into_response())
}

/// Query for [`max_spend`]: the destination + fee rate to price the drain at.
#[derive(Debug, Deserialize)]
pub struct MaxSpendQuery {
    /// Recipient address the sweep would pay.
    pub recipient_address: String,
    /// Fee rate (sat/vB) used to size the drain.
    pub fee_rate_sat_vb: u64,
}

/// JSON reply for [`max_spend`]: the net drainable amount.
#[derive(Debug, Serialize)]
pub struct MaxSpendResponse {
    /// Net amount in satoshis (balance − fee).
    pub max_sat: u64,
    /// Same amount formatted as BTC with 8 decimals, for the amount field.
    pub max_btc: String,
}

/// `GET /wallet/max-spend?recipient_address=…&fee_rate_sat_vb=…`
///
/// Prices a full-balance sweep so the Send page's **Max** button can prefill
/// the exact net amount. Does not sign or broadcast.
///
/// # Errors
/// Zero fee rate / bad address → `400`; wallet/DB errors via [`AppError`].
pub async fn max_spend(
    State(state): State<Arc<AppState>>,
    AuthUser(user): AuthUser,
    Query(q): Query<MaxSpendQuery>,
) -> Result<Json<MaxSpendResponse>, AppError> {
    if q.fee_rate_sat_vb == 0 {
        return Err(AppError::BadRequest(
            "fee_rate_sat_vb must be at least 1".to_string(),
        ));
    }
    let uw = state.wallet_manager.load_or_init(user.id).await?;
    uw.sync().await?;
    let address = uw.parse_address(q.recipient_address.trim())?;
    let amount = uw.compute_drain_amount(&address, q.fee_rate_sat_vb).await?;
    Ok(Json(MaxSpendResponse {
        max_sat: amount.to_sat(),
        max_btc: format!("{:.8}", amount.to_btc()),
    }))
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
    let derivation_path = match (keychain, index) {
        (Some(k), Some(i)) => {
            let chain = match k {
                KeychainKind::External => 0,
                KeychainKind::Internal => 1,
            };
            format!(
                "m/48'/{}'/{}'/2'/{chain}/{i}",
                state.config.bip48_coin_index,
                uw.account_idx(),
            )
        }
        _ => "—".to_string(),
    };

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
            derivation_path,
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
    // No sync here: the Federation view renders instantly off the shared cached
    // wallet; Receive/dashboard keep the balance fresh.
    let balance = uw.balance().await;
    let tip_height = uw.tip_height().await;
    let descriptor = lookup_descriptor(&state, user.id).await?;

    let versions = db::list_federation_versions_for_wallet(&state.db, uw.wallet_id()).await?;
    let version_count = versions.len();

    let current_fed = uw.federation();
    let acct_idx_u32 = u32::try_from(uw.account_idx()).unwrap_or(0);
    let path = state.wallet_manager.derivation_path_for(acct_idx_u32)?;
    let all_signers = state.hsm.signers_for(user.id, &path).await?;
    let current = FederationVersionView {
        version_index: version_count.saturating_sub(1) as i32,
        threshold: current_fed.threshold() as i32,
        signer_count: current_fed.total_signers() as i32,
        signers: build_signer_views(current_fed, &all_signers, &state),
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
    federation: &emvault::core::Federation<crate::wallet::NetworkPatchedSigner>,
    all_signers: &[emvault::pkcs11::Pkcs11Signer],
    state: &AppState,
) -> Vec<SignerView> {
    use emvault::core::signer::Signer;
    federation
        .signers()
        .iter()
        .map(|s| {
            let id_str = s.id().as_str().to_string();
            let fp = format!("{}", s.fingerprint());
            let label = all_signers
                .iter()
                .enumerate()
                .find(|(_, ps)| format!("{}", ps.fingerprint()) == fp)
                .and_then(|(idx, _)| state.config.hsm_tokens.get(idx))
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
    let n = state.config.fed_signer_indices.len();
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
