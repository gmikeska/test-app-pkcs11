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

/// List every wallet in the system, ordered by `account_idx`.
///
/// # Errors
/// Propagates any underlying SQL error.
pub async fn list_all_wallets(pool: &PgPool) -> sqlx::Result<Vec<WalletRow>> {
    sqlx::query_as::<_, WalletRow>(
        "SELECT id, user_id, account_idx, descriptor, bdk_changeset, \
                chain_tip_height, created_at \
         FROM wallets ORDER BY account_idx",
    )
    .fetch_all(pool)
    .await
}

/// Allocate the next `account_idx` for a Bitcoin wallet.
///
/// # ▶ Why this is a sequence and not `MAX(account_idx) + 1`
///
/// It used to be `SELECT COALESCE(MAX(account_idx) + 1, 0) FROM wallets`, which
/// is a high-water mark of **surviving** rows rather than an allocator. Deleting
/// a wallet freed its index, and the next user provisioned derived
/// `m/48'/{coin}'/{account_idx}'/2'` to the *same* HSM keys, the same
/// `wsh(sortedmulti(..))` descriptor and the same addresses as the deleted
/// user — able to spend whatever was still sitting there, and to silently
/// receive any later deposit meant for the previous holder (EMV-8).
///
/// ▶ `UNIQUE (account_idx)` did not and could not catch that: it constrains rows
/// that *exist*, and the violated invariant is over rows that **ever existed**.
/// Deleting before re-inserting slips past it without the constraint ever being
/// consulted.
///
/// `nextval` is monotonic, is not rolled back by a failed transaction, and is
/// indifferent to deletes — so a reissued index is unrepresentable rather than
/// merely unlikely. Migration `0010` seeds the sequence above the existing
/// maximum plus a margin, because indices held by already-deleted rows cannot be
/// recovered from the surviving table.
///
/// # Errors
/// Propagates any underlying SQL error.
pub async fn next_account_idx(pool: &PgPool) -> sqlx::Result<i32> {
    let next: i64 = sqlx::query_scalar("SELECT nextval('wallets_account_idx_seq')")
        .fetch_one(pool)
        .await?;
    Ok(i32::try_from(next).unwrap_or(i32::MAX))
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

/// Rebind a wallet row to a new descriptor and reset its BDK changeset + tip.
///
/// Used to self-heal post-migration descriptor drift: the migration tool
/// records a new federation version but never updates `wallets.descriptor`,
/// so the app's spendable `inner` wallet stays pinned to the OLD federation.
/// This rewrites the row to the current federation's descriptor with a fresh
/// (revealed-but-unscanned) changeset; the next sync repopulates it from chain.
///
/// # Errors
/// Propagates any underlying SQL error.
pub async fn update_wallet_descriptor_and_changeset(
    pool: &PgPool,
    wallet_id: Uuid,
    descriptor: &str,
    changeset: &JsonValue,
) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE wallets \
         SET descriptor = $1, bdk_changeset = $2, chain_tip_height = 0 \
         WHERE id = $3",
    )
    .bind(descriptor)
    .bind(changeset)
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

/// Allocate the next `account_idx` for an Elements/Liquid wallet.
///
/// Same reasoning as [`next_account_idx`] — see its doc comment for why a
/// sequence replaced `MAX(account_idx) + 1`.
///
/// ▶ The consequence is slightly worse on this chain. `daemon_wallet_name` is
/// built as `format!("elements-user-{account_idx}")` and is `UNIQUE`, so a
/// reused index also reuses a **user-visible wallet label** — and that
/// constraint is defeated by the identical delete-then-insert ordering, so it
/// was never a guard either. Two guards, neither able to see the violation.
///
/// # Errors
/// Propagates any underlying SQL error.
pub async fn next_elements_account_idx(pool: &PgPool) -> sqlx::Result<i32> {
    let next: i64 = sqlx::query_scalar("SELECT nextval('elements_wallets_account_idx_seq')")
        .fetch_one(pool)
        .await?;
    Ok(i32::try_from(next).unwrap_or(i32::MAX))
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

/// Rebind an Elements wallet row to a new descriptor + master blinding key.
///
/// Self-heals post-migration descriptor drift: the migration tool records a new
/// Elements federation version but never updates `elements_wallets.descriptor`,
/// so the wallet used for balance + Send stays pinned to the OLD federation and
/// the swept funds (at new-federation addresses) are unspendable. This rewrites
/// the row to the current federation's descriptor + blinding key.
///
/// # Errors
/// Propagates any underlying SQL error.
pub async fn update_elements_wallet_descriptor(
    pool: &PgPool,
    wallet_id: Uuid,
    descriptor: &str,
    master_blinding_key: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE elements_wallets \
         SET descriptor = $1, master_blinding_key = $2 \
         WHERE id = $3",
    )
    .bind(descriptor)
    .bind(master_blinding_key)
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
                   blinding_key, migration_status, migration_sweep_txid, created_at",
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
                blinding_key, migration_status, migration_sweep_txid, created_at \
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
                blinding_key, migration_status, migration_sweep_txid, created_at \
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
    let count: Option<i64> =
        sqlx::query_scalar("SELECT COUNT(*) FROM federation_versions WHERE wallet_id = $1")
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

/// Flip a version to `complete` **and** record the migration sweep txid that
/// moved its funds forward (migration `0008`). The recorded txid is the key
/// reorg-reconciliation checks against wallet ground-truth (is this sweep still
/// present in the rebuilt tx graph?) to decide whether the sweep was reorged
/// out; see [`reconcile_migration`]. Called by the migration tool at the same
/// point it previously only flipped the status.
///
/// # Errors
/// Propagates any underlying SQL error.
pub async fn set_migration_complete(
    pool: &PgPool,
    version_id: Uuid,
    sweep_txid: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE federation_versions \
         SET migration_status = 'complete', migration_sweep_txid = $1 \
         WHERE id = $2",
    )
    .bind(sweep_txid)
    .bind(version_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Revert an optimistically-completed migration whose sweep was reorged out:
/// `migration_status: complete → pending` and `migration_sweep_txid: <txid> →
/// NULL`, putting the predecessor version back into the re-sweepable state the
/// migration tool looks for. `sweep_txid` is the version's own recorded sweep
/// txid (the caller has already established, from wallet ground-truth, that it is
/// no longer present on-chain).
///
/// Guarded on `migration_status = 'complete'` **and** a matching
/// `migration_sweep_txid`, so it is a no-op (returns `Ok(false)`) after the first
/// revert (idempotent) and can never fire on a healthy version or on a version
/// whose sweep is a *different* txid. Returns `Ok(true)` iff it reverted a row.
///
/// Keyed by the version's primary `id`, so it serves both the Bitcoin and
/// Elements paths (the `federation_versions` table is shared); no separate
/// `_elements_` twin is needed.
///
/// # Errors
/// Propagates any underlying SQL error.
pub async fn reconcile_migration(
    pool: &PgPool,
    version_id: Uuid,
    sweep_txid: &str,
) -> sqlx::Result<bool> {
    let result = sqlx::query(
        "UPDATE federation_versions \
         SET migration_status = 'pending', migration_sweep_txid = NULL \
         WHERE id = $1 AND migration_status = 'complete' \
           AND migration_sweep_txid = $2",
    )
    .bind(version_id)
    .bind(sweep_txid)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
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

pub async fn has_in_progress_migration(pool: &PgPool, wallet_id: Uuid) -> sqlx::Result<bool> {
    let count: Option<i64> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM federation_versions \
         WHERE wallet_id = $1 AND migration_status = 'in_progress'",
    )
    .bind(wallet_id)
    .fetch_one(pool)
    .await?;
    Ok(count.unwrap_or(0) > 0)
}

pub async fn list_all_elements_wallets(pool: &PgPool) -> sqlx::Result<Vec<ElementsWalletRow>> {
    sqlx::query_as::<_, ElementsWalletRow>(
        "SELECT id, user_id, account_idx, descriptor, master_blinding_key, \
                daemon_wallet_name, chain_tip_height, created_at \
         FROM elements_wallets ORDER BY account_idx",
    )
    .fetch_all(pool)
    .await
}

pub async fn set_pending_migration_for_older_elements_versions(
    pool: &PgPool,
    elements_wallet_id: Uuid,
    current_version_index: i32,
) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE federation_versions \
         SET migration_status = 'pending' \
         WHERE elements_wallet_id = $1 AND version_index < $2 \
           AND migration_status = 'not_applicable'",
    )
    .bind(elements_wallet_id)
    .bind(current_version_index)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn has_in_progress_elements_migration(
    pool: &PgPool,
    elements_wallet_id: Uuid,
) -> sqlx::Result<bool> {
    let count: Option<i64> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM federation_versions \
         WHERE elements_wallet_id = $1 AND migration_status = 'in_progress'",
    )
    .bind(elements_wallet_id)
    .fetch_one(pool)
    .await?;
    Ok(count.unwrap_or(0) > 0)
}

#[cfg(test)]
mod account_idx_tests {
    use super::{next_account_idx, next_elements_account_idx};
    use sqlx::PgPool;
    use uuid::Uuid;

    /// Serialises the two allocator tests against each other.
    ///
    /// ▶ Both read a table-wide maximum, so a concurrent insert from the other
    /// one would change what they observe. This does **not** serialise them
    /// against `elements_sync::tests::pg_stores_honor_contracts`, which also
    /// inserts into `elements_wallets` (EMV-7). That interference can only make
    /// the Elements test pass for the wrong reason, never fail wrongly: the
    /// assertion is "the index was not reissued", and an unrelated higher index
    /// still satisfies it.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    async fn test_pool() -> Option<PgPool> {
        let url = std::env::var("TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .ok()?;
        let pool = PgPool::connect(&url).await.ok()?;
        // ▶ A failed migration is fatal here, NOT a reason to skip.
        //
        // The idiom this was copied from (`elements_sync::tests::test_pool`)
        // ends every fallible step with `.ok()?`, so a broken migration returns
        // `None`, the test prints "no DATABASE_URL" and reports **ok**. That
        // exact path produced a green run for these two tests while migration
        // 0010 was failing — a vacuous pass that looks identical to a real one.
        // Absent database: skip. Present but unmigratable: say so loudly.
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrations must apply; a failure here is not a skip condition");
        Some(pool)
    }

    async fn seed_user(pool: &PgPool) -> Uuid {
        sqlx::query_scalar("INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id")
            .bind(format!("acctidx-{}@test.local", Uuid::new_v4()))
            .fetch_one(pool)
            .await
            .expect("seed user")
    }

    /// An account index, once issued, must never be issued again — even after
    /// the wallet that held it is deleted.
    ///
    /// # ▶ Why this is the invariant that matters
    ///
    /// The index *is* the wallet: it selects the BIP-48 account in
    /// `m/48'/{coin}'/{account_idx}'/2'`, so reissuing it reproduces the same
    /// HSM keys, the same `wsh(sortedmulti(..))` descriptor and the same
    /// addresses. A second user handed a recycled index receives the first
    /// user's wallet — able to spend whatever is still sitting at those
    /// addresses, and to silently receive any later deposit meant for them.
    ///
    /// ▶ `UNIQUE (account_idx)` cannot express this. It constrains rows that
    /// *exist*; this constrains rows that **ever existed**. Deleting before
    /// re-inserting slips past it without the constraint ever firing, which is
    /// exactly how EMV-8 stayed invisible while the column was `UNIQUE` the
    /// whole time.
    #[tokio::test]
    async fn account_idx_is_never_reissued_after_wallet_deletion() {
        let Some(pool) = test_pool().await else {
            eprintln!("skipping: no TEST_DATABASE_URL/DATABASE_URL");
            return;
        };
        let _serial = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let user = seed_user(&pool).await;
        let issued = next_account_idx(&pool).await.expect("first allocation");
        // Distinct descriptor per row — see the Elements test for why.
        sqlx::query(
            "INSERT INTO wallets (user_id, account_idx, descriptor, bdk_changeset, \
                                  chain_tip_height) \
             VALUES ($1, $2, $3, '{}'::jsonb, 0)",
        )
        .bind(user)
        .bind(issued)
        .bind(format!("wsh(sortedmulti(2,acctidx-fixture-{user}))"))
        .execute(&pool)
        .await
        .expect("insert wallet at the issued index");

        // Delete the user; `wallets.user_id` is ON DELETE CASCADE, so the
        // wallet row goes with it — the exact sequence the reorg gates perform
        // in their cleanup, and the one the running app performs on offboarding.
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user)
            .execute(&pool)
            .await
            .expect("delete user (cascades to wallet)");

        let reissued = next_account_idx(&pool).await.expect("second allocation");
        assert_ne!(
            reissued, issued,
            "account index {issued} was handed out again after its wallet was deleted — \
             the next user would inherit the deleted user's keys, descriptor and addresses"
        );
    }

    /// The Elements chain has its own allocator and its own copy of the defect.
    ///
    /// ▶ It is slightly worse there: `daemon_wallet_name` is built as
    /// `format!("elements-user-{account_idx}")` and is `UNIQUE`, so a reused
    /// index also reuses a user-visible wallet label — and that constraint is
    /// defeated by the same delete-then-insert ordering, so it is not a guard
    /// either.
    #[tokio::test]
    async fn elements_account_idx_is_never_reissued_after_wallet_deletion() {
        let Some(pool) = test_pool().await else {
            eprintln!("skipping: no TEST_DATABASE_URL/DATABASE_URL");
            return;
        };
        let _serial = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let user = seed_user(&pool).await;
        let issued = next_elements_account_idx(&pool)
            .await
            .expect("first allocation");
        // ▶ A distinct descriptor per row, not the shared literal `'desc'` the
        // older fixtures use. Those duplicates are what currently blocks the
        // `UNIQUE (descriptor)` guard (EMV-11); new fixtures should not add to
        // the pile.
        sqlx::query(
            "INSERT INTO elements_wallets (user_id, account_idx, descriptor, \
                                           master_blinding_key, daemon_wallet_name) \
             VALUES ($1, $2, $4, 'mbk', $3)",
        )
        .bind(user)
        .bind(issued)
        .bind(format!("elements-user-{issued}"))
        .bind(format!("ct(slip77(mbk),elwsh(acctidx-fixture-{user})))"))
        .execute(&pool)
        .await
        .expect("insert elements wallet at the issued index");

        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user)
            .execute(&pool)
            .await
            .expect("delete user (cascades to elements wallet)");

        let reissued = next_elements_account_idx(&pool)
            .await
            .expect("second allocation");
        assert_ne!(
            reissued, issued,
            "Elements account index {issued} was handed out again after its wallet was \
             deleted — the next user would inherit the deleted user's CT descriptor, \
             blinding key and addresses"
        );
    }
}
