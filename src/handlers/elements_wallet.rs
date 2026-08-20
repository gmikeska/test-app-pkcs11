//! Elements wallet routes — mirrors `handlers::wallet` for the Liquid/Elements
//! chain.
//!
//! - `GET  /elements/wallet/receive`               — balance + first 20 CT addresses.
//! - `GET  /elements/wallet/send`                  — send form + recent transactions.
//! - `POST /elements/wallet/send`                  — build PSET → sign → broadcast.
//! - `GET  /elements/wallet/addresses/:address`     — per-address QR + receipts.

use emvault::core::bitcoin;
use std::sync::Arc;

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Form, Json};
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
    pub policy: String,
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

#[derive(Debug, Serialize, Clone)]
pub struct ElementsFederationAddressGroup {
    pub version: usize,
    pub label: String,
    pub is_current: bool,
    /// One entry per asset (policy asset first) — the asset sub-tabs.
    pub assets: Vec<ElementsAssetGroupView>,
}

/// One asset's address rows within a federation version (an asset sub-tab).
#[derive(Debug, Serialize, Clone)]
pub struct ElementsAssetGroupView {
    /// Full asset id (used for the panel id + the `?asset=` deep link).
    pub asset_id: String,
    /// Tab title: "L-BTC" for the policy asset, else the first 4 id chars.
    pub asset_label: String,
    pub is_policy: bool,
    /// Whether this asset's tab is active by default (the policy asset).
    pub is_active: bool,
    pub addresses: Vec<ElementsAddressView>,
    pub change_addresses: Vec<ElementsAddressView>,
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

#[derive(Template, WebTemplate)]
#[template(path = "elements_wallet_receive.html")]
struct ReceiveTemplate {
    header: ElementsWalletHeader,
    balance: ElementsBalanceView,
    asset_balances: Vec<AssetBalanceView>,
    federation_groups: Vec<ElementsFederationAddressGroup>,
    flash: Option<FlashBanner>,
}

/// One asset's balance row on the receive page.
struct AssetBalanceView {
    asset_id: String,
    /// Whether this is the policy asset (rendered as "L-BTC").
    is_policy: bool,
    amount: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "elements_wallet_send.html")]
struct SendTemplate {
    header: ElementsWalletHeader,
    balance: ElementsBalanceView,
    transactions: Vec<ElementsTransactionListView>,
    /// Asset dropdown options — L-BTC first (empty value = L-BTC send), then
    /// each held issued asset by id.
    asset_options: Vec<SendAssetOption>,
    flash: Option<FlashBanner>,
}

/// One option in the send-page asset dropdown.
#[derive(Debug, Serialize, Clone)]
pub struct SendAssetOption {
    /// Form value: empty string for L-BTC (the policy asset), else the asset id.
    pub value: String,
    /// Display label: "L-BTC" for the policy asset, else the asset id.
    pub label: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "elements_address.html")]
struct AddressTemplate {
    header: ElementsWalletHeader,
    email: String,
    address: ElementsAddressDetailView,
    /// One entry per asset with activity at this address (the asset tabs).
    asset_activities: Vec<AddressAssetActivityView>,
}

/// One asset's activity panel on the address-detail page (an asset tab).
#[derive(Debug, Serialize, Clone)]
pub struct AddressAssetActivityView {
    pub asset_id: String,
    pub asset_label: String,
    pub is_policy: bool,
    /// Whether this tab is active (from `?asset=`, else the policy asset).
    pub is_active: bool,
    pub total_received_btc: String,
    pub unspent_btc: String,
    pub receipt_count: usize,
    pub receipts: Vec<ElementsReceiptView>,
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

#[derive(Template, WebTemplate)]
#[template(path = "elements_wallet_federation.html")]
struct ElementsFederationTemplate {
    header: ElementsWalletHeader,
    balance: ElementsBalanceView,
    current: ElementsFederationVersionView,
    versions: Vec<ElementsFederationHistoryView>,
    version_count: usize,
    flash: Option<FlashBanner>,
}

#[derive(Debug, Serialize, Clone)]
pub struct ElementsSignerView {
    pub id: String,
    pub label: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct ElementsFederationVersionView {
    pub version_index: i32,
    pub threshold: i32,
    pub signer_count: i32,
    pub signers: Vec<ElementsSignerView>,
}

#[derive(Debug, Serialize, Clone)]
pub struct ElementsFederationHistoryView {
    pub version_index: i32,
    pub threshold: i32,
    pub signer_count: i32,
    pub wallet_handle: String,
    pub blinding_key_rotated: String,
    pub descriptor_short: String,
    pub created_at: String,
    pub is_current: bool,
    pub migration_status: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
pub async fn receive(
    State(state): State<Arc<AppState>>,
    AuthUser(user): AuthUser,
) -> Result<Response, AppError> {
    let uw = state.elements_wallet_manager.load_or_init(user.id).await?;
    let tip_height = uw.tip_height().await?;
    let balances = uw.balance().await?;

    let to_view = |a: crate::elements_wallet::ElementsRevealedAddress| {
        let address_short = abbreviate_address(&a.address, 12, 8);
        ElementsAddressView {
            index: a.index,
            address: a.address,
            address_short,
            received_btc: format!("{:.8}", if a.received <= 0.0 { 0.0 } else { a.received }),
            unspent_btc: format!("{:.8}", if a.unspent <= 0.0 { 0.0 } else { a.unspent }),
        }
    };

    let policy_asset = uw.lwk_network().policy_asset().to_string();
    let asset_label = |asset_id: &str, is_policy: bool| -> String {
        if is_policy {
            "L-BTC".to_string()
        } else {
            asset_id.chars().take(4).collect()
        }
    };

    let version_groups = uw
        .reveal_addresses_all_versions_by_asset(REVEAL_COUNT)
        .await?;
    let total_versions = version_groups.len();

    let versions_for_change =
        db::list_federation_versions_for_elements_wallet(&state.db, uw.wallet_id()).await?;

    let mut federation_groups: Vec<ElementsFederationAddressGroup> = Vec::new();
    for vg in version_groups.into_iter().rev() {
        let is_current = vg.version_index == total_versions - 1;
        let label = if is_current {
            format!("v{} (current)", vg.version_index + 1)
        } else {
            format!("v{}", vg.version_index + 1)
        };

        // Per-asset change addresses (current version only), keyed by asset id.
        let mut change_by_asset: std::collections::HashMap<String, Vec<ElementsAddressView>> =
            std::collections::HashMap::new();
        if is_current {
            let desc = versions_for_change
                .iter()
                .find(|v| v.wallet_handle == vg.wallet_handle)
                .map_or(uw.descriptor(), |v| v.descriptor.as_str());
            for ag in uw
                .change_addresses_by_asset(REVEAL_COUNT, desc)
                .await
                .unwrap_or_default()
            {
                let views: Vec<ElementsAddressView> = ag
                    .addresses
                    .into_iter()
                    .filter(|a| a.unspent > 0.000_000_01)
                    .map(&to_view)
                    .collect();
                change_by_asset.insert(ag.asset_id, views);
            }
        }

        let assets: Vec<ElementsAssetGroupView> = vg
            .assets
            .into_iter()
            .map(|ag| {
                let change_addresses = change_by_asset.remove(&ag.asset_id).unwrap_or_default();
                ElementsAssetGroupView {
                    asset_label: asset_label(&ag.asset_id, ag.is_policy),
                    is_active: ag.is_policy,
                    is_policy: ag.is_policy,
                    addresses: ag.addresses.into_iter().map(&to_view).collect(),
                    change_addresses,
                    asset_id: ag.asset_id,
                }
            })
            .collect();

        federation_groups.push(ElementsFederationAddressGroup {
            version: vg.version_index,
            label,
            is_current,
            assets,
        });
    }

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

    let asset_balances = uw
        .asset_balances()
        .await?
        .into_iter()
        .map(|b| AssetBalanceView {
            is_policy: b.asset_id == policy_asset,
            asset_id: b.asset_id,
            amount: format!("{:.8}", b.amount),
        })
        .collect();

    Ok(ReceiveTemplate {
        header: ElementsWalletHeader {
            email: user.email,
            account_idx: uw.account_idx(),
            network: uw.network().to_string(),
            descriptor: uw.descriptor().to_string(),
            tip_height,
            active_tab: "receive",
            policy: elements_policy_label(&state),
        },
        balance: balance_view,
        asset_balances,
        federation_groups,
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

    // Asset dropdown: L-BTC first (empty value ⇒ plain L-BTC send), then each
    // held issued asset (by id). The policy asset is folded into the L-BTC row.
    let policy_asset = uw.lwk_network().policy_asset().to_string();
    let mut asset_options = vec![SendAssetOption {
        value: String::new(),
        label: "L-BTC".to_string(),
    }];
    for b in uw.asset_balances().await? {
        if b.asset_id != policy_asset {
            asset_options.push(SendAssetOption {
                value: b.asset_id.clone(),
                label: b.asset_id,
            });
        }
    }

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
            policy: elements_policy_label(&state),
        },
        balance: balance_view,
        transactions: txs,
        asset_options,
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
    /// `"true"` when the **Max** button armed a full-balance drain; the amount
    /// field is then ignored and the wallet is swept to the recipient.
    #[serde(default)]
    pub send_max: Option<String>,
    /// Optional Liquid asset id (hex). When present and non-empty, `amount_btc`
    /// is interpreted as units of that asset (L-BTC still pays the fee) rather
    /// than L-BTC. Empty/absent → a plain L-BTC send.
    #[serde(default)]
    pub asset_id: Option<String>,
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

    let label = form
        .label
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let asset_id = form
        .asset_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    // "Send Max": L-BTC drains the wallet (fee out of the swept amount); an
    // asset drains its full balance (fee paid separately in L-BTC). Otherwise
    // send the requested amount.
    let result = if matches!(form.send_max.as_deref(), Some("true")) {
        if let Some(asset) = asset_id {
            uw.build_sign_and_broadcast_asset_max(
                form.recipient_address.trim(),
                asset,
                form.fee_rate_sat_vb,
                label,
            )
            .await?
        } else {
            uw.sweep_to(form.recipient_address.trim(), form.fee_rate_sat_vb, label)
                .await?
        }
    } else {
        let amount: f64 =
            form.amount_btc.trim().parse().map_err(|_| {
                AppError::BadRequest(format!("invalid amount `{}`", form.amount_btc))
            })?;
        if amount <= 0.0 {
            return Err(AppError::BadRequest("amount must be positive".to_string()));
        }
        if let Some(asset) = asset_id {
            uw.build_sign_and_broadcast_asset(
                form.recipient_address.trim(),
                asset,
                amount,
                form.fee_rate_sat_vb,
                label,
            )
            .await?
        } else {
            uw.build_sign_and_broadcast(
                form.recipient_address.trim(),
                amount,
                form.fee_rate_sat_vb,
                label,
            )
            .await?
        }
    };

    tracing::info!(
        user = %user.email,
        txid = %result.txid,
        recipient = %result.recipient,
        amount_sat = result.amount_sat,
        "broadcast Elements tx"
    );

    Ok(Redirect::to(&format!("/elements/wallet/transactions/{}", result.txid)).into_response())
}

/// Query for [`max_spend`]: the destination + fee rate to price the drain at.
#[derive(Debug, Deserialize)]
pub struct MaxSpendQuery {
    /// Recipient address the sweep would pay.
    pub recipient_address: String,
    /// Fee rate (sat/vB) used to size the drain.
    pub fee_rate_sat_vb: u64,
    /// Optional Liquid asset id. When present, the "max" is the full asset
    /// balance (the L-BTC fee is separate, so nothing is subtracted).
    #[serde(default)]
    pub asset_id: Option<String>,
}

/// JSON reply for [`max_spend`]: the net drainable amount.
#[derive(Debug, Serialize)]
pub struct MaxSpendResponse {
    /// Net amount in satoshis (balance − fee).
    pub max_sat: u64,
    /// Same amount formatted as L-BTC with 8 decimals, for the amount field.
    pub max_btc: String,
}

/// `GET /elements/wallet/max-spend?recipient_address=…&fee_rate_sat_vb=…`
///
/// Prices a full-balance sweep so the Elements Send page's **Max** button can
/// prefill the exact net amount. Does not sign or broadcast.
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
    let uw = state.elements_wallet_manager.load_or_init(user.id).await?;
    let asset_id = q
        .asset_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    // Asset max = full asset balance (fee is separate L-BTC); L-BTC max =
    // balance − fee via a priced sweep.
    let max_sat = if let Some(asset) = asset_id {
        uw.asset_total_sat(asset).await?
    } else {
        uw.compute_drain_amount(q.recipient_address.trim(), q.fee_rate_sat_vb)
            .await?
    };
    #[allow(clippy::cast_precision_loss)]
    let max_btc = format!("{:.8}", max_sat as f64 / 100_000_000.0);
    Ok(Json(MaxSpendResponse { max_sat, max_btc }))
}

/// Query string for the address-detail page: which asset tab to preselect.
#[derive(Debug, Deserialize)]
pub struct AddressAssetQuery {
    /// Full asset id of the tab to open; defaults to the policy asset.
    #[serde(default)]
    pub asset: Option<String>,
}

pub async fn address_show(
    State(state): State<Arc<AppState>>,
    AuthUser(user): AuthUser,
    Path(address_raw): Path<String>,
    Query(q): Query<AddressAssetQuery>,
) -> Result<Response, AppError> {
    let uw = state.elements_wallet_manager.load_or_init(user.id).await?;
    let tip_height = uw.tip_height().await?;

    let revealed = uw.reveal_addresses(REVEAL_COUNT).await?;
    let change = uw.change_addresses(REVEAL_COUNT).await?;
    let derivation_index = revealed
        .iter()
        .chain(change.iter())
        .find(|a| a.address == address_raw)
        .map(|a| a.index);

    let qr_uri = format!("liquidnetwork:{address_raw}");
    let qr_svg = QrCode::new(qr_uri.as_bytes())
        .map_err(|e| AppError::BadRequest(format!("Failed to encode QR: {e}")))?
        .render::<svg::Color<'_>>()
        .min_dimensions(220, 220)
        .quiet_zone(true)
        .dark_color(svg::Color("#0b0d12"))
        .light_color(svg::Color("#f4f6fb"))
        .build();

    let mut asset_activities: Vec<AddressAssetActivityView> = uw
        .address_history_by_asset(&address_raw)
        .await?
        .into_iter()
        .map(|a| {
            let is_active = match q.asset.as_deref() {
                Some(sel) => sel == a.asset_id,
                None => a.is_policy,
            };
            AddressAssetActivityView {
                asset_label: if a.is_policy {
                    "L-BTC".to_string()
                } else {
                    a.asset_id.chars().take(4).collect()
                },
                is_policy: a.is_policy,
                is_active,
                total_received_btc: format!(
                    "{:.8}",
                    if a.total_received <= 0.0 {
                        0.0
                    } else {
                        a.total_received
                    }
                ),
                unspent_btc: format!("{:.8}", if a.unspent <= 0.0 { 0.0 } else { a.unspent }),
                receipt_count: a.receipts.len(),
                receipts: a
                    .receipts
                    .into_iter()
                    .map(ElementsReceiptView::from)
                    .collect(),
                asset_id: a.asset_id,
            }
        })
        .collect();
    // Guarantee exactly one active tab even if `?asset=` names an asset with no
    // activity at this address (or the policy asset has none here).
    let none_active = !asset_activities.iter().any(|v| v.is_active);
    if let (true, Some(first)) = (none_active, asset_activities.first_mut()) {
        first.is_active = true;
    }

    Ok(AddressTemplate {
        header: ElementsWalletHeader {
            email: user.email.clone(),
            account_idx: uw.account_idx(),
            network: uw.network().to_string(),
            descriptor: uw.descriptor().to_string(),
            tip_height,
            active_tab: "receive",
            policy: elements_policy_label(&state),
        },
        email: user.email,
        address: ElementsAddressDetailView {
            address: address_raw,
            qr_uri,
            qr_svg,
            derivation_index,
        },
        asset_activities,
    }
    .into_response())
}

#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub async fn federation(
    State(state): State<Arc<AppState>>,
    AuthUser(user): AuthUser,
) -> Result<Response, AppError> {
    let uw = state.elements_wallet_manager.load_or_init(user.id).await?;
    let tip_height = uw.tip_height().await?;
    let balances = uw.balance().await?;

    let versions =
        db::list_federation_versions_for_elements_wallet(&state.db, uw.wallet_id()).await?;
    let version_count = versions.len();

    // Current federation signers, resolved from the ACTUAL live wallet
    // descriptor rather than the `.env` default — otherwise a migrated wallet
    // keeps showing its boot-time signer set. Each descriptor origin
    // fingerprint is mapped back to its HSM token label via the fleet; the
    // per-token master fingerprints are stable across users/accounts, so any
    // signer set works for the lookup.
    let signers =
        current_federation_signers(&state, user.id, uw.account_idx(), uw.descriptor()).await;
    let current = ElementsFederationVersionView {
        version_index: version_count.saturating_sub(1) as i32,
        threshold: versions
            .last()
            .map_or(state.config.fed_threshold as i32, |v| v.threshold),
        signer_count: signers.len() as i32,
        signers,
    };

    let history: Vec<ElementsFederationHistoryView> = versions
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let is_current = v.version_index == (version_count.saturating_sub(1) as i32);
            let blinding_key_rotated = if i == 0 {
                "N/A (initial)".to_string()
            } else {
                let prev = &versions[i - 1];
                if v.blinding_key == prev.blinding_key {
                    "No".to_string()
                } else {
                    "Yes".to_string()
                }
            };
            ElementsFederationHistoryView {
                version_index: v.version_index,
                threshold: v.threshold,
                signer_count: v.signer_count,
                wallet_handle: v.wallet_handle.clone(),
                blinding_key_rotated,
                descriptor_short: truncate_descriptor(&v.descriptor, 40),
                created_at: v.created_at.format("%Y-%m-%d %H:%M UTC").to_string(),
                is_current,
                migration_status: v.migration_status.clone(),
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

    Ok(ElementsFederationTemplate {
        header: ElementsWalletHeader {
            email: user.email,
            account_idx: uw.account_idx(),
            network: uw.network().to_string(),
            descriptor: uw.descriptor().to_string(),
            tip_height,
            active_tab: "federation",
            policy: elements_policy_label(&state),
        },
        balance: balance_view,
        current,
        versions: history,
        version_count,
        flash: None,
    }
    .into_response())
}

/// Resolve the signers of a wallet's **current** federation from its live
/// descriptor (rather than the `.env` default), each origin fingerprint mapped
/// back to its HSM token label via the fleet. Per-token master fingerprints are
/// stable across users/accounts, so any signer set answers the lookup; on any
/// derivation error the fingerprints are shown verbatim.
async fn current_federation_signers(
    state: &AppState,
    user_id: uuid::Uuid,
    account_idx: i32,
    descriptor: &str,
) -> Vec<ElementsSignerView> {
    use emvault::core::signer::Signer as _;
    let acct = u32::try_from(account_idx).unwrap_or(0);
    let fp_to_label: std::collections::HashMap<bitcoin::bip32::Fingerprint, String> =
        match state.elements_wallet_manager.derivation_path_for(acct) {
            Ok(path) => match state.hsm.signers_for(user_id, &path).await {
                Ok(set) => state
                    .config
                    .hsm_tokens
                    .iter()
                    .zip(set.iter())
                    .map(|(t, s)| (s.fingerprint(), t.label.clone()))
                    .collect(),
                Err(_) => std::collections::HashMap::new(),
            },
            Err(_) => std::collections::HashMap::new(),
        };
    origin_fingerprints(descriptor)
        .into_iter()
        .map(|fp| {
            let label = fp_to_label
                .get(&fp)
                .cloned()
                .unwrap_or_else(|| fp.to_string());
            ElementsSignerView {
                id: label.clone(),
                label,
            }
        })
        .collect()
}

/// Extract the BIP32 key-origin fingerprints (`[abcd1234/…]`) from a descriptor
/// string, in order of appearance. The SLIP-77 blinding key (`slip77(<hex>)`,
/// no `[` bracket) is intentionally skipped, so only the multisig cosigner
/// fingerprints are returned.
fn origin_fingerprints(descriptor: &str) -> Vec<bitcoin::bip32::Fingerprint> {
    use std::str::FromStr;
    descriptor
        .split('[')
        .skip(1)
        .filter_map(|seg| {
            let hex = seg.split(['/', ']']).next()?;
            let is_fp = hex.len() == 8 && hex.bytes().all(|c| c.is_ascii_hexdigit());
            is_fp
                .then(|| bitcoin::bip32::Fingerprint::from_str(hex).ok())
                .flatten()
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

fn elements_policy_label(state: &AppState) -> String {
    let t = state.config.fed_threshold;
    let n = state.config.fed_signer_indices.len();
    format!("{t}-of-{n} (HSMs)")
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
