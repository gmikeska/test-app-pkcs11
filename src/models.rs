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
