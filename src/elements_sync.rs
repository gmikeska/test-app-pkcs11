//! Postgres + Elements-RPC implementations of the `emvault-elements`
//! [`sync`](emvault::elements::sync) traits — the consuming application's half
//! of the shared block-scan pipeline.
//!
//! - [`PgBlockStore`] / [`PgWalletUtxoStore`] persist blocks and per-wallet
//!   UTXOs in Postgres (migration `0007`).
//! - [`RpcChainSource`] fetches blocks and broadcasts via the Elements node's
//!   JSON-RPC (the transport seam; `ElementsRpcClient` in spirit).
//!
//! The `sync` traits are synchronous (`&self`); the Postgres stores hold a
//! Tokio [`Handle`] captured at construction and `block_on` their async sqlx
//! queries. The engine is therefore meant to be driven from a `spawn_blocking`
//! context (see the ingestion service), where blocking is safe.

// Postgres stores heights/vouts/values as BIGINT (i64); the domain types are
// u32/u64. The casts at this boundary are safe given the column CHECK
// constraints (>= 0) and chain reality (heights/vouts fit in u32).
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::type_complexity,
    clippy::too_many_lines
)]

use std::str::FromStr;

use elements::AssetId;
use emvault::elements::sync::{
    BlockStore, CapturedUtxo, ElementsChainSource, KeychainKind, SyncedTip, WalletId,
    WalletUtxoStore,
};
use emvault::elements::{ElementsNetwork, SyncError};

use bitcoincore_rpc::{Auth, Client, RpcApi};
use elements::encode::{deserialize, serialize, serialize_hex};
use elements::hex::FromHex;
use elements::{Block, BlockHash, OutPoint, Transaction, TxOut, TxOutSecrets, Txid};
use serde_json::json;
use sqlx::PgPool;
use tokio::runtime::Handle;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// id / error helpers
// ---------------------------------------------------------------------------

fn wid_to_uuid(w: WalletId) -> Uuid {
    Uuid::from_bytes(*w.as_bytes())
}

fn uuid_to_wid(u: Uuid) -> WalletId {
    WalletId::from_bytes(*u.as_bytes())
}

fn store_err<E: std::fmt::Display>(e: E) -> SyncError {
    SyncError::Store(e.to_string())
}

fn enc_err<E: std::fmt::Display>(e: E) -> SyncError {
    SyncError::Encoding(e.to_string())
}

fn chain_to_i16(c: KeychainKind) -> i16 {
    match c {
        KeychainKind::External => 0,
        KeychainKind::Internal => 1,
    }
}

fn i16_to_chain(v: i16) -> KeychainKind {
    if v == 0 {
        KeychainKind::External
    } else {
        KeychainKind::Internal
    }
}

// ---------------------------------------------------------------------------
// PgBlockStore
// ---------------------------------------------------------------------------

/// Postgres-backed [`BlockStore`].
pub struct PgBlockStore {
    pool: PgPool,
    rt: Handle,
}

impl PgBlockStore {
    /// Construct from a pool. Must be called from within a Tokio runtime; the
    /// captured [`Handle`] is used to `block_on` queries from blocking threads.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            rt: Handle::current(),
        }
    }
}

impl BlockStore for PgBlockStore {
    fn store_block(&self, height: u32, hash: BlockHash, raw: &[u8]) -> Result<(), SyncError> {
        self.rt
            .block_on(async {
                sqlx::query(
                    "INSERT INTO elements_blocks (height, block_hash, raw_block) \
                 VALUES ($1, $2, $3) \
                 ON CONFLICT (height) DO UPDATE \
                   SET block_hash = EXCLUDED.block_hash, raw_block = EXCLUDED.raw_block",
                )
                .bind(i64::from(height))
                .bind(hash.to_string())
                .bind(raw)
                .execute(&self.pool)
                .await
            })
            .map_err(store_err)?;
        Ok(())
    }

    fn synced_tip(&self) -> Result<Option<SyncedTip>, SyncError> {
        let row: Option<(i64, String)> = self
            .rt
            .block_on(
                sqlx::query_as("SELECT tip_height, tip_hash FROM elements_sync_cursor WHERE id")
                    .fetch_optional(&self.pool),
            )
            .map_err(store_err)?;
        match row {
            None => Ok(None),
            Some((h, hash)) => Ok(Some(SyncedTip {
                height: h as u32,
                hash: BlockHash::from_str(&hash).map_err(enc_err)?,
            })),
        }
    }

    fn set_synced_tip(&self, tip: SyncedTip) -> Result<(), SyncError> {
        self.rt
            .block_on(
                sqlx::query(
                    "INSERT INTO elements_sync_cursor (id, tip_height, tip_hash) \
                     VALUES (true, $1, $2) \
                     ON CONFLICT (id) DO UPDATE \
                       SET tip_height = EXCLUDED.tip_height, \
                           tip_hash = EXCLUDED.tip_hash, updated_at = now()",
                )
                .bind(i64::from(tip.height))
                .bind(tip.hash.to_string())
                .execute(&self.pool),
            )
            .map_err(store_err)?;
        Ok(())
    }

    fn block_hash_at(&self, height: u32) -> Result<Option<BlockHash>, SyncError> {
        let row: Option<(String,)> = self
            .rt
            .block_on(
                sqlx::query_as("SELECT block_hash FROM elements_blocks WHERE height = $1")
                    .bind(i64::from(height))
                    .fetch_optional(&self.pool),
            )
            .map_err(store_err)?;
        row.map(|(h,)| BlockHash::from_str(&h).map_err(enc_err))
            .transpose()
    }

    fn rollback_above(&self, height: u32) -> Result<(), SyncError> {
        let h = i64::from(height);
        self.rt
            .block_on(async {
                sqlx::query("DELETE FROM elements_blocks WHERE height > $1")
                    .bind(h)
                    .execute(&self.pool)
                    .await?;

                // Mirror the in-memory store: if the cursor is above the
                // rollback height, reset it to the new max block (or clear it).
                let cur: Option<(i64,)> =
                    sqlx::query_as("SELECT tip_height FROM elements_sync_cursor WHERE id")
                        .fetch_optional(&self.pool)
                        .await?;
                if matches!(cur, Some((th,)) if th > h) {
                    let max: Option<(i64, String)> = sqlx::query_as(
                        "SELECT height, block_hash FROM elements_blocks ORDER BY height DESC LIMIT 1",
                    )
                    .fetch_optional(&self.pool)
                    .await?;
                    match max {
                        Some((mh, mhash)) => {
                            sqlx::query(
                                "UPDATE elements_sync_cursor \
                                 SET tip_height = $1, tip_hash = $2, updated_at = now() WHERE id",
                            )
                            .bind(mh)
                            .bind(mhash)
                            .execute(&self.pool)
                            .await?;
                        }
                        None => {
                            sqlx::query("DELETE FROM elements_sync_cursor WHERE id")
                                .execute(&self.pool)
                                .await?;
                        }
                    }
                }
                Ok::<_, sqlx::Error>(())
            })
            .map_err(store_err)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PgWalletUtxoStore
// ---------------------------------------------------------------------------

/// Postgres-backed [`WalletUtxoStore`].
pub struct PgWalletUtxoStore {
    pool: PgPool,
    rt: Handle,
}

impl PgWalletUtxoStore {
    /// Construct from a pool (see [`PgBlockStore::new`] for the `Handle` note).
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            rt: Handle::current(),
        }
    }

    /// All captured UTXOs for a wallet **including spent ones**, with their real
    /// `is_spent` flag. Used by the UI to show historical "total received" at an
    /// address even after the funds have been spent (e.g. post-migration).
    ///
    /// # Errors
    ///
    /// [`SyncError::Store`] on query failure or [`SyncError::Encoding`] if a row
    /// cannot be reconstructed.
    pub fn list_for_wallet(&self, wallet: WalletId) -> Result<Vec<CapturedUtxo>, SyncError> {
        let rows: Vec<(String, i64, Vec<u8>, String, i16, i64, i64, bool)> = self
            .rt
            .block_on(
                sqlx::query_as(
                    "SELECT txid, vout, raw_txout, secrets_json, chain, wildcard_index, \
                            height, is_spent \
                     FROM elements_utxos WHERE wallet_id = $1",
                )
                .bind(wid_to_uuid(wallet))
                .fetch_all(&self.pool),
            )
            .map_err(store_err)?;

        rows.into_iter()
            .map(
                |(txid, vout, raw_txout, secrets_json, chain, widx, height, is_spent)| {
                    let outpoint =
                        OutPoint::new(Txid::from_str(&txid).map_err(enc_err)?, vout as u32);
                    let txout: TxOut = deserialize(&raw_txout).map_err(enc_err)?;
                    let secrets: TxOutSecrets =
                        serde_json::from_str(&secrets_json).map_err(enc_err)?;
                    Ok(CapturedUtxo {
                        wallet_id: wallet,
                        outpoint,
                        txout,
                        secrets,
                        chain: i16_to_chain(chain),
                        wildcard_index: widx as u32,
                        height: height as u32,
                        is_spent,
                    })
                },
            )
            .collect()
    }
}

impl WalletUtxoStore for PgWalletUtxoStore {
    fn upsert_utxos(&self, utxos: &[CapturedUtxo]) -> Result<(), SyncError> {
        // Encode outside the async block so encoding errors surface cleanly.
        let mut rows = Vec::with_capacity(utxos.len());
        for u in utxos {
            let secrets_json = serde_json::to_string(&u.secrets).map_err(enc_err)?;
            rows.push((
                wid_to_uuid(u.wallet_id),
                u.outpoint.txid.to_string(),
                i64::from(u.outpoint.vout),
                serialize(&u.txout),
                secrets_json,
                u.secrets.asset.to_string(),
                u.value() as i64,
                chain_to_i16(u.chain),
                i64::from(u.wildcard_index),
                i64::from(u.height),
            ));
        }
        self.rt
            .block_on(async {
                for (wallet, txid, vout, raw_txout, secrets, asset, value, chain, widx, height) in
                    &rows
                {
                    sqlx::query(
                        "INSERT INTO elements_utxos \
                           (wallet_id, txid, vout, raw_txout, secrets_json, asset_id, \
                            value_sat, chain, wildcard_index, height) \
                         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) \
                         ON CONFLICT (wallet_id, txid, vout) DO UPDATE SET \
                           raw_txout = EXCLUDED.raw_txout, secrets_json = EXCLUDED.secrets_json, \
                           asset_id = EXCLUDED.asset_id, value_sat = EXCLUDED.value_sat, \
                           chain = EXCLUDED.chain, wildcard_index = EXCLUDED.wildcard_index, \
                           height = EXCLUDED.height",
                    )
                    .bind(wallet)
                    .bind(txid)
                    .bind(vout)
                    .bind(raw_txout)
                    .bind(secrets)
                    .bind(asset)
                    .bind(value)
                    .bind(chain)
                    .bind(widx)
                    .bind(height)
                    .execute(&self.pool)
                    .await?;
                }
                Ok::<_, sqlx::Error>(())
            })
            .map_err(store_err)?;
        Ok(())
    }

    fn mark_spent(&self, outpoints: &[OutPoint], spent_height: u32) -> Result<(), SyncError> {
        let h = i64::from(spent_height);
        self.rt
            .block_on(async {
                for op in outpoints {
                    sqlx::query(
                        "UPDATE elements_utxos SET is_spent = true, spent_height = $3 \
                         WHERE txid = $1 AND vout = $2",
                    )
                    .bind(op.txid.to_string())
                    .bind(i64::from(op.vout))
                    .bind(h)
                    .execute(&self.pool)
                    .await?;
                }
                Ok::<_, sqlx::Error>(())
            })
            .map_err(store_err)?;
        Ok(())
    }

    fn list_unspent(&self, wallet: WalletId) -> Result<Vec<CapturedUtxo>, SyncError> {
        let rows: Vec<(String, i64, Vec<u8>, String, i16, i64, i64)> = self
            .rt
            .block_on(
                sqlx::query_as(
                    "SELECT txid, vout, raw_txout, secrets_json, chain, wildcard_index, height \
                     FROM elements_utxos WHERE wallet_id = $1 AND NOT is_spent",
                )
                .bind(wid_to_uuid(wallet))
                .fetch_all(&self.pool),
            )
            .map_err(store_err)?;

        rows.into_iter()
            .map(
                |(txid, vout, raw_txout, secrets_json, chain, widx, height)| {
                    let outpoint =
                        OutPoint::new(Txid::from_str(&txid).map_err(enc_err)?, vout as u32);
                    let txout: TxOut = deserialize(&raw_txout).map_err(enc_err)?;
                    let secrets: TxOutSecrets =
                        serde_json::from_str(&secrets_json).map_err(enc_err)?;
                    Ok(CapturedUtxo {
                        wallet_id: wallet,
                        outpoint,
                        txout,
                        secrets,
                        chain: i16_to_chain(chain),
                        wildcard_index: widx as u32,
                        height: height as u32,
                        is_spent: false,
                    })
                },
            )
            .collect()
    }

    fn unspent_outpoints(&self) -> Result<Vec<(OutPoint, WalletId)>, SyncError> {
        let rows: Vec<(Uuid, String, i64)> = self
            .rt
            .block_on(
                sqlx::query_as(
                    "SELECT wallet_id, txid, vout FROM elements_utxos WHERE NOT is_spent",
                )
                .fetch_all(&self.pool),
            )
            .map_err(store_err)?;
        rows.into_iter()
            .map(|(wallet, txid, vout)| {
                let outpoint = OutPoint::new(Txid::from_str(&txid).map_err(enc_err)?, vout as u32);
                Ok((outpoint, uuid_to_wid(wallet)))
            })
            .collect()
    }

    fn rollback_above(&self, height: u32) -> Result<(), SyncError> {
        let h = i64::from(height);
        self.rt
            .block_on(async {
                sqlx::query("DELETE FROM elements_utxos WHERE height > $1")
                    .bind(h)
                    .execute(&self.pool)
                    .await?;
                sqlx::query(
                    "UPDATE elements_utxos SET is_spent = false, spent_height = NULL \
                     WHERE spent_height > $1",
                )
                .bind(h)
                .execute(&self.pool)
                .await?;
                Ok::<_, sqlx::Error>(())
            })
            .map_err(store_err)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RpcChainSource
// ---------------------------------------------------------------------------

/// Elements-node JSON-RPC implementation of [`ElementsChainSource`].
///
/// `bitcoincore-rpc`'s typed helpers assume Bitcoin block/tx encodings, so we
/// use raw `call` with Elements consensus (de)serialization.
pub struct RpcChainSource {
    client: Client,
}

impl RpcChainSource {
    /// Connect to the Elements node at `url` with the given credentials.
    ///
    /// # Errors
    ///
    /// [`SyncError::ChainSource`] if the client cannot be constructed.
    pub fn new(url: &str, user: &str, password: &str) -> Result<Self, SyncError> {
        let client = Client::new(url, Auth::UserPass(user.to_string(), password.to_string()))
            .map_err(|e| SyncError::ChainSource(e.to_string()))?;
        Ok(Self { client })
    }

    fn rpc_err<E: std::fmt::Display>(e: E) -> SyncError {
        SyncError::ChainSource(e.to_string())
    }

    /// The node's policy (L-BTC) asset, from `getsidechaininfo.pegged_asset`.
    ///
    /// # Errors
    ///
    /// [`SyncError::ChainSource`] on RPC failure or a malformed response.
    pub fn policy_asset(&self) -> Result<AssetId, SyncError> {
        let v: serde_json::Value = self
            .client
            .call("getsidechaininfo", &[])
            .map_err(Self::rpc_err)?;
        let s = v["pegged_asset"].as_str().ok_or_else(|| {
            SyncError::ChainSource("getsidechaininfo missing pegged_asset".into())
        })?;
        AssetId::from_str(s).map_err(enc_err)
    }
}

/// Resolve the concrete [`lwk_wollet::Network`] for a node. For
/// `ElementsRegtest` this sources the policy asset + genesis from the node
/// (which vary per deployment); Liquid/testnet use their fixed parameters.
///
/// # Errors
///
/// [`SyncError::ChainSource`] if node params can't be fetched.
pub fn node_lwk_network(
    chain: &RpcChainSource,
    network: ElementsNetwork,
) -> Result<emvault::elements::LwkNetwork, SyncError> {
    Ok(match network {
        ElementsNetwork::ElementsRegtest => {
            let policy = chain.policy_asset()?;
            let genesis = chain.block_hash(0)?;
            ElementsNetwork::custom_regtest(policy, genesis)
        }
        other => other.to_lwk(),
    })
}

impl ElementsChainSource for RpcChainSource {
    fn tip_height(&self) -> Result<u32, SyncError> {
        let h: u64 = self
            .client
            .call("getblockcount", &[])
            .map_err(Self::rpc_err)?;
        Ok(h as u32)
    }

    fn block_hash(&self, height: u32) -> Result<BlockHash, SyncError> {
        let hash: String = self
            .client
            .call("getblockhash", &[json!(height)])
            .map_err(Self::rpc_err)?;
        BlockHash::from_str(&hash).map_err(enc_err)
    }

    fn block(&self, hash: &BlockHash) -> Result<Block, SyncError> {
        // verbosity 0 → raw block hex
        let hex: String = self
            .client
            .call("getblock", &[json!(hash.to_string()), json!(0)])
            .map_err(Self::rpc_err)?;
        let bytes = Vec::<u8>::from_hex(&hex).map_err(enc_err)?;
        deserialize(&bytes).map_err(enc_err)
    }

    fn broadcast(&self, tx: &Transaction) -> Result<Txid, SyncError> {
        let hex = serialize_hex(tx);
        let txid: String = self
            .client
            .call("sendrawtransaction", &[json!(hex)])
            .map_err(Self::rpc_err)?;
        Txid::from_str(&txid).map_err(enc_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
    use elements::{AssetId, Script, TxOutWitness};

    /// Connect to the test database, or return `None` to skip when no DB is
    /// configured (keeps `cargo test` green in node-less/db-less envs).
    async fn test_pool() -> Option<PgPool> {
        let url = std::env::var("TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .ok()?;
        let pool = PgPool::connect(&url).await.ok()?;
        sqlx::migrate!("./migrations").run(&pool).await.ok()?;
        Some(pool)
    }

    /// Seed a throwaway user + `elements_wallet`, returning its id.
    async fn seed_wallet(pool: &PgPool) -> Uuid {
        let tag = Uuid::new_v4();
        let user_id: Uuid = sqlx::query_scalar(
            "INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id",
        )
        .bind(format!("{tag}@test.local"))
        .fetch_one(pool)
        .await
        .unwrap();
        // account_idx must be unique; derive from the random uuid.
        let acct = (u32::from_le_bytes(tag.as_bytes()[..4].try_into().unwrap()) % 1_000_000) as i32
            + 1_000_000;
        sqlx::query_scalar(
            "INSERT INTO elements_wallets \
               (user_id, account_idx, descriptor, master_blinding_key, daemon_wallet_name) \
             VALUES ($1, $2, 'desc', 'mbk', $3) RETURNING id",
        )
        .bind(user_id)
        .bind(acct)
        .bind(format!("w-{tag}"))
        .fetch_one(pool)
        .await
        .unwrap()
    }

    fn explicit_txout(value: u64) -> TxOut {
        TxOut {
            asset: Asset::Explicit(AssetId::from_slice(&[2u8; 32]).unwrap()),
            value: Value::Explicit(value),
            nonce: Nonce::Null,
            script_pubkey: Script::new(),
            witness: TxOutWitness::default(),
        }
    }

    fn captured(wallet: WalletId, height: u32, value: u64, vout: u32) -> CapturedUtxo {
        let mut op = OutPoint::null();
        op.vout = vout;
        CapturedUtxo {
            wallet_id: wallet,
            outpoint: op,
            txout: explicit_txout(value),
            secrets: TxOutSecrets::new(
                AssetId::from_slice(&[2u8; 32]).unwrap(),
                AssetBlindingFactor::zero(),
                value,
                ValueBlindingFactor::zero(),
            ),
            chain: KeychainKind::External,
            wildcard_index: 0,
            height,
            is_spent: false,
        }
    }

    /// The Postgres stores must satisfy the same contracts the in-memory fakes
    /// do (mirrors `emvault::elements::sync::tests`). Runs under a blocking
    /// task because the sync trait methods `block_on` internally.
    #[tokio::test]
    async fn pg_stores_honor_contracts() {
        let Some(pool) = test_pool().await else {
            eprintln!("skipping pg_stores_honor_contracts: no TEST_DATABASE_URL/DATABASE_URL");
            return;
        };
        let wallet_uuid = seed_wallet(&pool).await;
        let wallet = uuid_to_wid(wallet_uuid);

        let result = tokio::task::spawn_blocking(move || {
            let utxos = PgWalletUtxoStore::new(pool.clone());
            let blocks = PgBlockStore::new(pool.clone());

            // --- utxo: upsert + list (idempotent) ---
            utxos
                .upsert_utxos(&[captured(wallet, 1, 100, 0), captured(wallet, 1, 200, 1)])
                .unwrap();
            utxos.upsert_utxos(&[captured(wallet, 1, 100, 0)]).unwrap(); // re-upsert
            let mut vals: Vec<u64> = utxos
                .list_unspent(wallet)
                .unwrap()
                .iter()
                .map(CapturedUtxo::value)
                .collect();
            vals.sort_unstable();
            assert_eq!(vals, vec![100, 200], "idempotent upsert + list");

            // round-trip fidelity: txout + secrets reconstructed
            let one = &utxos.list_unspent(wallet).unwrap()[0];
            assert_eq!(one.value(), one.secrets.value);
            assert_eq!(one.script_pubkey(), &Script::new());

            // --- mark spent excludes ---
            let op0 = {
                let mut op = OutPoint::null();
                op.vout = 0;
                op
            };
            utxos.mark_spent(&[op0], 2).unwrap();
            let vals: Vec<u64> = utxos
                .list_unspent(wallet)
                .unwrap()
                .iter()
                .map(CapturedUtxo::value)
                .collect();
            assert_eq!(vals, vec![200], "spent excluded from list");

            // --- unspent_outpoints across wallets ---
            assert_eq!(
                utxos
                    .unspent_outpoints()
                    .unwrap()
                    .iter()
                    .filter(|(_, w)| *w == wallet)
                    .count(),
                1
            );

            // --- rollback drops captured-above + un-spends spent-above ---
            // State: op0(100,h1) spent at h2; op1(200,h1) unspent. Add op9(900,h9).
            utxos.upsert_utxos(&[captured(wallet, 9, 900, 9)]).unwrap();
            utxos.rollback_above(1).unwrap();
            let vals: Vec<u64> = {
                let mut v: Vec<u64> = utxos
                    .list_unspent(wallet)
                    .unwrap()
                    .iter()
                    .map(CapturedUtxo::value)
                    .collect();
                v.sort_unstable();
                v
            };
            // height-9 (900) dropped (captured > 1); op0 (100) un-spent (spent at h2 > 1)
            assert_eq!(
                vals,
                vec![100, 200],
                "rollback dropped above + un-spent above"
            );

            // --- block store: cursor + hash + rollback ---
            let h3 = BlockHash::from_str(
                "0000000000000000000000000000000000000000000000000000000000000003",
            )
            .unwrap();
            blocks.store_block(3, h3, b"rawbytes").unwrap();
            blocks
                .set_synced_tip(SyncedTip {
                    height: 3,
                    hash: h3,
                })
                .unwrap();
            assert_eq!(
                blocks.synced_tip().unwrap(),
                Some(SyncedTip {
                    height: 3,
                    hash: h3
                })
            );
            assert_eq!(blocks.block_hash_at(3).unwrap(), Some(h3));
            assert_eq!(blocks.block_hash_at(99).unwrap(), None);

            let h2 = BlockHash::from_str(
                "0000000000000000000000000000000000000000000000000000000000000002",
            )
            .unwrap();
            blocks.store_block(2, h2, b"x").unwrap();
            blocks.rollback_above(2).unwrap();
            assert!(
                blocks.block_hash_at(3).unwrap().is_none(),
                "block 3 dropped"
            );
            assert_eq!(
                blocks.synced_tip().unwrap().map(|t| t.height),
                Some(2),
                "cursor reset to max"
            );

            // cleanup
            Handle::current().block_on(async {
                sqlx::query("DELETE FROM users WHERE id = $1")
                    .bind(wallet_uuid)
                    .execute(&pool)
                    .await
                    .unwrap();
                sqlx::query("DELETE FROM elements_blocks")
                    .execute(&pool)
                    .await
                    .unwrap();
                sqlx::query("DELETE FROM elements_sync_cursor")
                    .execute(&pool)
                    .await
                    .unwrap();
            });
        })
        .await;
        result.unwrap();
    }
}
