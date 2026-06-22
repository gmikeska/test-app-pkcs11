//! Row structs mirroring `migrations/*.sql`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// `users` row.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct UserRow {
    /// User id.
    pub id: Uuid,
    /// Login email.
    pub email: String,
    /// Argon2id-encoded password hash (PHC string).
    pub password_hash: String,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// `wallets` row.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct WalletRow {
    /// Wallet id.
    pub id: Uuid,
    /// Owning user (1:1).
    pub user_id: Uuid,
    /// BIP-48 account index (third hardened component).
    pub account_idx: i32,
    /// Multipath `wsh(sortedmulti(...))` descriptor with `/<0;1>/*`.
    pub descriptor: String,
    /// JSON-encoded `bdk_wallet::ChangeSet`. Populated immediately on
    /// wallet creation.
    pub bdk_changeset: Option<serde_json::Value>,
    /// Cached chain tip from the last sync. `None` before first sync.
    pub chain_tip_height: Option<i32>,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// `transactions` row.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct TransactionRow {
    /// Transaction row id.
    pub id: Uuid,
    /// Owning wallet.
    pub wallet_id: Uuid,
    /// Bitcoin txid (hex).
    pub txid: String,
    /// Recipient address (canonical, network-checked).
    pub recipient: String,
    /// Amount paid to the recipient, in satoshis.
    pub amount_sat: i64,
    /// Total fee paid, in satoshis.
    pub fee_sat: i64,
    /// Hex-encoded raw transaction (consensus-serialized).
    pub raw_tx_hex: String,
    /// Optional human-readable label.
    pub label: Option<String>,
    /// `sendrawtransaction` timestamp.
    pub broadcast_at: DateTime<Utc>,
}

/// `elements_wallets` row.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ElementsWalletRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub account_idx: i32,
    pub descriptor: String,
    pub master_blinding_key: String,
    pub daemon_wallet_name: String,
    pub chain_tip_height: Option<i32>,
    pub created_at: DateTime<Utc>,
}

/// `elements_transactions` row.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ElementsTransactionRow {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub txid: String,
    pub recipient: String,
    pub amount_sat: i64,
    pub fee_sat: i64,
    pub raw_tx_hex: String,
    pub label: Option<String>,
    pub broadcast_at: DateTime<Utc>,
}

/// `federation_versions` row.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct FederationVersionRow {
    pub id: Uuid,
    pub wallet_id: Option<Uuid>,
    pub elements_wallet_id: Option<Uuid>,
    pub version_index: i32,
    pub descriptor: String,
    pub threshold: i32,
    pub signer_count: i32,
    pub federation_snapshot: serde_json::Value,
    pub wallet_handle: String,
    pub blinding_key: Option<String>,
    pub created_at: DateTime<Utc>,
}
