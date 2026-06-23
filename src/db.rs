//! Thin `sqlx` query helpers wrapping the schema in `migrations/`.

use serde_json::Value as JsonValue;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{
    ElementsTransactionRow, ElementsWalletRow, FederationVersionRow, TransactionRow, UserRow,
    WalletRow,
};

/// Run all `migrations/*.sql` against `pool`.
///
/// # Errors
/// Propagates [`sqlx::migrate::MigrateError`] verbatim.
pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

// ---------------------------------------------------------------------------
// users
// ---------------------------------------------------------------------------

/// Insert a user if no row already exists with the same email.
///
/// Returns `true` if a row was inserted.
///
/// # Errors
/// Propagates any underlying SQL error.
pub async fn upsert_user_if_absent(
    pool: &PgPool,
    email: &str,
    password_hash: &str,
) -> sqlx::Result<bool> {
    let result = sqlx::query(
        "INSERT INTO users (email, password_hash) VALUES ($1, $2) \
         ON CONFLICT (email) DO NOTHING",
    )
    .bind(email)
    .bind(password_hash)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Look up a user by email (case-insensitive on the indexed column).
///
/// # Errors
/// Propagates any underlying SQL error.
pub async fn find_user_by_email(pool: &PgPool, email: &str) -> sqlx::Result<Option<UserRow>> {
    sqlx::query_as::<_, UserRow>(
        "SELECT id, email, password_hash, created_at \
         FROM users WHERE lower(email) = lower($1)",
    )
    .bind(email)
    .fetch_optional(pool)
    .await
}

/// Look up a user by id.
///
/// # Errors
/// Propagates any underlying SQL error.
pub async fn find_user_by_id(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<UserRow>> {
    sqlx::query_as::<_, UserRow>(
        "SELECT id, email, password_hash, created_at FROM users WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

// ---------------------------------------------------------------------------
// wallets
// ---------------------------------------------------------------------------

/// Inputs for [`insert_wallet`].
#[derive(Debug, Clone)]
pub struct NewWallet<'a> {
    /// Owning user.
    pub user_id: Uuid,
    /// Pre-allocated BIP-48 account index.
    pub account_idx: i32,
    /// Descriptor in BIP-389 multipath form.
    pub descriptor: &'a str,
    /// Initial JSON-encoded `bdk_wallet::ChangeSet`.
    pub bdk_changeset: &'a JsonValue,
    /// Initial chain tip (typically zero on a fresh BDK wallet).
    pub chain_tip_height: i32,
}

/// Insert the wallet row created at first login.
///
/// # Errors
/// Propagates any underlying SQL error. Notably, a duplicate `account_idx`
/// or `user_id` triggers a unique-constraint violation that the caller is
/// expected to handle (re-allocate the index and retry).
pub async fn insert_wallet(pool: &PgPool, spec: &NewWallet<'_>) -> sqlx::Result<WalletRow> {
    sqlx::query_as::<_, WalletRow>(
        "INSERT INTO wallets \
            (user_id, account_idx, descriptor, bdk_changeset, chain_tip_height) \
         VALUES ($1, $2, $3, $4, $5) \
         RETURNING id, user_id, account_idx, descriptor, bdk_changeset, \
                   chain_tip_height, created_at",
    )
    .bind(spec.user_id)
    .bind(spec.account_idx)
    .bind(spec.descriptor)
    .bind(spec.bdk_changeset)
    .bind(spec.chain_tip_height)
    .fetch_one(pool)
    .await
}

/// Find the wallet for `user_id`, if any.
///
/// # Errors
/// Propagates any underlying SQL error.
pub async fn find_wallet_for_user(pool: &PgPool, user_id: Uuid) -> sqlx::Result<Option<WalletRow>> {
    sqlx::query_as::<_, WalletRow>(
        "SELECT id, user_id, account_idx, descriptor, bdk_changeset, \
                chain_tip_height, created_at \
         FROM wallets WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
}

/// Compute the next free `account_idx` (`max(account_idx) + 1`, or `0`
/// if the table is empty).
///
/// Caller is responsible for serialising allocations: in this app, the
/// boot path eager-seeds the three test users sequentially, and per-user
/// allocation only ever happens once (idempotent first login).
///
/// # Errors
/// Propagates any underlying SQL error.
pub async fn next_account_idx(pool: &PgPool) -> sqlx::Result<i32> {
    let next: Option<i32> =
        sqlx::query_scalar("SELECT COALESCE(MAX(account_idx) + 1, 0) FROM wallets")
            .fetch_one(pool)
            .await?;
    Ok(next.unwrap_or(0))
}

/// Persist the merged BDK changeset and chain tip.
///
/// # Errors
/// Propagates any underlying SQL error.
pub async fn update_wallet_changeset(
    pool: &PgPool,
    wallet_id: Uuid,
    changeset: &JsonValue,
    tip_height: i32,
) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE wallets \
         SET bdk_changeset = $1, chain_tip_height = $2 \
         WHERE id = $3",
    )
    .bind(changeset)
    .bind(tip_height)
    .bind(wallet_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Update only the cached chain tip.
///
/// # Errors
/// Propagates any underlying SQL error.
pub async fn update_wallet_tip_only(
    pool: &PgPool,
    wallet_id: Uuid,
    tip_height: i32,
) -> sqlx::Result<()> {
    sqlx::query("UPDATE wallets SET chain_tip_height = $1 WHERE id = $2")
        .bind(tip_height)
        .bind(wallet_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// transactions
// ---------------------------------------------------------------------------

/// Inputs for [`insert_transaction`].
#[derive(Debug, Clone)]
pub struct NewTransaction<'a> {
    /// Owning wallet.
    pub wallet_id: Uuid,
    /// Bitcoin txid (hex).
    pub txid: &'a str,
    /// Canonical recipient address.
    pub recipient: &'a str,
    /// Amount paid to the recipient (sats).
    pub amount_sat: i64,
    /// Total fee paid (sats).
    pub fee_sat: i64,
    /// Hex-encoded raw tx.
    pub raw_tx_hex: &'a str,
    /// Optional label.
    pub label: Option<&'a str>,
}

/// Insert one row per broadcast (idempotent on `(wallet_id, txid)`).
///
/// Returns `Some(_)` if the row was inserted, `None` if the conflict
/// fired (caller has already broadcast this tx).
///
/// # Errors
/// Propagates any underlying SQL error.
pub async fn insert_transaction(
    pool: &PgPool,
    spec: &NewTransaction<'_>,
) -> sqlx::Result<Option<TransactionRow>> {
    sqlx::query_as::<_, TransactionRow>(
        "INSERT INTO transactions \
            (wallet_id, txid, recipient, amount_sat, fee_sat, raw_tx_hex, label) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (wallet_id, txid) DO NOTHING \
         RETURNING id, wallet_id, txid, recipient, amount_sat, fee_sat, \
                   raw_tx_hex, label, broadcast_at",
    )
    .bind(spec.wallet_id)
    .bind(spec.txid)
    .bind(spec.recipient)
    .bind(spec.amount_sat)
    .bind(spec.fee_sat)
    .bind(spec.raw_tx_hex)
    .bind(spec.label)
    .fetch_optional(pool)
    .await
}

/// All broadcast transactions for a wallet, newest first.
///
/// # Errors
/// Propagates any underlying SQL error.
pub async fn list_transactions_for_wallet(
    pool: &PgPool,
    wallet_id: Uuid,
) -> sqlx::Result<Vec<TransactionRow>> {
    sqlx::query_as::<_, TransactionRow>(
        "SELECT id, wallet_id, txid, recipient, amount_sat, fee_sat, \
                raw_tx_hex, label, broadcast_at \
         FROM transactions WHERE wallet_id = $1 \
         ORDER BY broadcast_at DESC",
    )
    .bind(wallet_id)
    .fetch_all(pool)
    .await
}

/// Look up one transaction by `(wallet_id, txid)`.
///
/// # Errors
/// Propagates any underlying SQL error.
pub async fn find_transaction(
    pool: &PgPool,
    wallet_id: Uuid,
    txid: &str,
) -> sqlx::Result<Option<TransactionRow>> {
    sqlx::query_as::<_, TransactionRow>(
        "SELECT id, wallet_id, txid, recipient, amount_sat, fee_sat, \
                raw_tx_hex, label, broadcast_at \
         FROM transactions WHERE wallet_id = $1 AND txid = $2",
    )
    .bind(wallet_id)
    .bind(txid)
    .fetch_optional(pool)
    .await
}

// ---------------------------------------------------------------------------
// elements_wallets
// ---------------------------------------------------------------------------

pub struct NewElementsWallet<'a> {
    pub user_id: Uuid,
    pub account_idx: i32,
    pub descriptor: &'a str,
    pub master_blinding_key: &'a str,
    pub daemon_wallet_name: &'a str,
}

pub async fn insert_elements_wallet(
    pool: &PgPool,
    spec: &NewElementsWallet<'_>,
) -> sqlx::Result<ElementsWalletRow> {
    sqlx::query_as::<_, ElementsWalletRow>(
        "INSERT INTO elements_wallets \
            (user_id, account_idx, descriptor, master_blinding_key, daemon_wallet_name) \
         VALUES ($1, $2, $3, $4, $5) \
         RETURNING id, user_id, account_idx, descriptor, master_blinding_key, \
                   daemon_wallet_name, chain_tip_height, created_at",
    )
    .bind(spec.user_id)
    .bind(spec.account_idx)
    .bind(spec.descriptor)
    .bind(spec.master_blinding_key)
    .bind(spec.daemon_wallet_name)
    .fetch_one(pool)
    .await
}

pub async fn find_elements_wallet_for_user(
    pool: &PgPool,
    user_id: Uuid,
) -> sqlx::Result<Option<ElementsWalletRow>> {
    sqlx::query_as::<_, ElementsWalletRow>(
        "SELECT id, user_id, account_idx, descriptor, master_blinding_key, \
                daemon_wallet_name, chain_tip_height, created_at \
         FROM elements_wallets WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
}

pub async fn next_elements_account_idx(pool: &PgPool) -> sqlx::Result<i32> {
    let next: Option<i32> =
        sqlx::query_scalar("SELECT COALESCE(MAX(account_idx) + 1, 0) FROM elements_wallets")
            .fetch_one(pool)
            .await?;
    Ok(next.unwrap_or(0))
}

#[allow(dead_code)]
pub async fn update_elements_wallet_tip(
    pool: &PgPool,
    wallet_id: Uuid,
    tip_height: i32,
) -> sqlx::Result<()> {
    sqlx::query("UPDATE elements_wallets SET chain_tip_height = $1 WHERE id = $2")
        .bind(tip_height)
        .bind(wallet_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// elements_transactions
// ---------------------------------------------------------------------------

pub struct NewElementsTransaction<'a> {
    pub wallet_id: Uuid,
    pub txid: &'a str,
    pub recipient: &'a str,
    pub amount_sat: i64,
    pub fee_sat: i64,
    pub raw_tx_hex: &'a str,
    pub label: Option<&'a str>,
}

pub async fn insert_elements_transaction(
    pool: &PgPool,
    spec: &NewElementsTransaction<'_>,
) -> sqlx::Result<Option<ElementsTransactionRow>> {
    sqlx::query_as::<_, ElementsTransactionRow>(
        "INSERT INTO elements_transactions \
            (wallet_id, txid, recipient, amount_sat, fee_sat, raw_tx_hex, label) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (wallet_id, txid) DO NOTHING \
         RETURNING id, wallet_id, txid, recipient, amount_sat, fee_sat, \
                   raw_tx_hex, label, broadcast_at",
    )
    .bind(spec.wallet_id)
    .bind(spec.txid)
    .bind(spec.recipient)
    .bind(spec.amount_sat)
    .bind(spec.fee_sat)
    .bind(spec.raw_tx_hex)
    .bind(spec.label)
    .fetch_optional(pool)
    .await
}

pub async fn list_elements_transactions_for_wallet(
    pool: &PgPool,
    wallet_id: Uuid,
) -> sqlx::Result<Vec<ElementsTransactionRow>> {
    sqlx::query_as::<_, ElementsTransactionRow>(
        "SELECT id, wallet_id, txid, recipient, amount_sat, fee_sat, \
                raw_tx_hex, label, broadcast_at \
         FROM elements_transactions WHERE wallet_id = $1 \
         ORDER BY broadcast_at DESC",
    )
    .bind(wallet_id)
    .fetch_all(pool)
    .await
}

pub async fn find_elements_transaction(
    pool: &PgPool,
    wallet_id: Uuid,
    txid: &str,
) -> sqlx::Result<Option<ElementsTransactionRow>> {
    sqlx::query_as::<_, ElementsTransactionRow>(
        "SELECT id, wallet_id, txid, recipient, amount_sat, fee_sat, \
                raw_tx_hex, label, broadcast_at \
         FROM elements_transactions WHERE wallet_id = $1 AND txid = $2",
    )
    .bind(wallet_id)
    .bind(txid)
    .fetch_optional(pool)
    .await
}

// ---------------------------------------------------------------------------
// federation_versions
// ---------------------------------------------------------------------------

pub struct NewFederationVersion<'a> {
    pub wallet_id: Option<Uuid>,
    pub elements_wallet_id: Option<Uuid>,
    pub version_index: i32,
    pub descriptor: &'a str,
    pub threshold: i32,
    pub signer_count: i32,
    pub federation_snapshot: &'a serde_json::Value,
    pub wallet_handle: &'a str,
    pub blinding_key: Option<&'a str>,
}

pub async fn insert_federation_version(
    pool: &PgPool,
    spec: &NewFederationVersion<'_>,
) -> sqlx::Result<FederationVersionRow> {
    sqlx::query_as::<_, FederationVersionRow>(
        "INSERT INTO federation_versions \
            (wallet_id, elements_wallet_id, version_index, descriptor, \
             threshold, signer_count, federation_snapshot, wallet_handle, blinding_key) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (wallet_id, version_index) WHERE wallet_id IS NOT NULL DO NOTHING \
         RETURNING id, wallet_id, elements_wallet_id, version_index, descriptor, \
                   threshold, signer_count, federation_snapshot, wallet_handle, \
                   blinding_key, migration_status, created_at",
    )
    .bind(spec.wallet_id)
    .bind(spec.elements_wallet_id)
    .bind(spec.version_index)
    .bind(spec.descriptor)
    .bind(spec.threshold)
    .bind(spec.signer_count)
    .bind(spec.federation_snapshot)
    .bind(spec.wallet_handle)
    .bind(spec.blinding_key)
    .fetch_one(pool)
    .await
}

pub async fn list_federation_versions_for_wallet(
    pool: &PgPool,
    wallet_id: Uuid,
) -> sqlx::Result<Vec<FederationVersionRow>> {
    sqlx::query_as::<_, FederationVersionRow>(
        "SELECT id, wallet_id, elements_wallet_id, version_index, descriptor, \
                threshold, signer_count, federation_snapshot, wallet_handle, \
                blinding_key, migration_status, created_at \
         FROM federation_versions WHERE wallet_id = $1 \
         ORDER BY version_index ASC",
    )
    .bind(wallet_id)
    .fetch_all(pool)
    .await
}

pub async fn list_federation_versions_for_elements_wallet(
    pool: &PgPool,
    elements_wallet_id: Uuid,
) -> sqlx::Result<Vec<FederationVersionRow>> {
    sqlx::query_as::<_, FederationVersionRow>(
        "SELECT id, wallet_id, elements_wallet_id, version_index, descriptor, \
                threshold, signer_count, federation_snapshot, wallet_handle, \
                blinding_key, migration_status, created_at \
         FROM federation_versions WHERE elements_wallet_id = $1 \
         ORDER BY version_index ASC",
    )
    .bind(elements_wallet_id)
    .fetch_all(pool)
    .await
}

pub async fn federation_version_count_for_wallet(
    pool: &PgPool,
    wallet_id: Uuid,
) -> sqlx::Result<i64> {
    let count: Option<i64> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM federation_versions WHERE wallet_id = $1",
    )
    .bind(wallet_id)
    .fetch_one(pool)
    .await?;
    Ok(count.unwrap_or(0))
}

pub async fn federation_version_count_for_elements_wallet(
    pool: &PgPool,
    elements_wallet_id: Uuid,
) -> sqlx::Result<i64> {
    let count: Option<i64> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM federation_versions WHERE elements_wallet_id = $1",
    )
    .bind(elements_wallet_id)
    .fetch_one(pool)
    .await?;
    Ok(count.unwrap_or(0))
}

pub async fn update_migration_status(
    pool: &PgPool,
    version_id: Uuid,
    status: &str,
) -> sqlx::Result<()> {
    sqlx::query("UPDATE federation_versions SET migration_status = $1 WHERE id = $2")
        .bind(status)
        .bind(version_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn set_pending_migration_for_older_versions(
    pool: &PgPool,
    wallet_id: Uuid,
    current_version_index: i32,
) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE federation_versions \
         SET migration_status = 'pending' \
         WHERE wallet_id = $1 AND version_index < $2 \
           AND migration_status = 'not_applicable'",
    )
    .bind(wallet_id)
    .bind(current_version_index)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn has_in_progress_migration(
    pool: &PgPool,
    wallet_id: Uuid,
) -> sqlx::Result<bool> {
    let count: Option<i64> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM federation_versions \
         WHERE wallet_id = $1 AND migration_status = 'in_progress'",
    )
    .bind(wallet_id)
    .fetch_one(pool)
    .await?;
    Ok(count.unwrap_or(0) > 0)
}
