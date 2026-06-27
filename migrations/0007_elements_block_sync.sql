-- Shared block-scan pipeline storage (Postgres implementation of the
-- emvault-elements `sync` traits). Replaces per-wallet daemon-wallet UTXO
-- capture, which does not scale past 1-2 wallets on the Elements node.
--
-- Each block is fetched from the node and stored exactly once; the scan engine
-- matches every block against the union of all wallets' watched scripts.
--
-- This migration is purely additive: it does NOT touch `elements_wallets` (the
-- `daemon_wallet_name` column is retired in a later migration, once the app
-- code no longer references it).

-- Raw blocks, fetched once and reused across all wallets.
CREATE TABLE IF NOT EXISTS elements_blocks (
    height       BIGINT      PRIMARY KEY CHECK (height >= 0),
    block_hash   TEXT        NOT NULL UNIQUE,
    raw_block    BYTEA       NOT NULL,
    ingested_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Singleton row: the last fully-scanned tip (for incremental sync + reorg
-- detection).
CREATE TABLE IF NOT EXISTS elements_sync_cursor (
    id          BOOLEAN     PRIMARY KEY DEFAULT true,
    tip_height  BIGINT      NOT NULL CHECK (tip_height >= 0),
    tip_hash    TEXT        NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT elements_sync_cursor_singleton CHECK (id)
);

-- Per-wallet captured UTXOs. `raw_txout` (consensus bytes) + `secrets_json`
-- (serde TxOutSecrets) fully reconstruct a `CapturedUtxo`; the remaining
-- columns are denormalized for querying and reorg rollback.
CREATE TABLE IF NOT EXISTS elements_utxos (
    wallet_id       UUID     NOT NULL REFERENCES elements_wallets(id) ON DELETE CASCADE,
    txid            TEXT     NOT NULL,
    vout            BIGINT   NOT NULL CHECK (vout >= 0),
    raw_txout       BYTEA    NOT NULL,
    secrets_json    TEXT     NOT NULL,
    asset_id        TEXT     NOT NULL,
    value_sat       BIGINT   NOT NULL CHECK (value_sat >= 0),
    chain           SMALLINT NOT NULL CHECK (chain IN (0, 1)), -- 0=external, 1=internal
    wildcard_index  BIGINT   NOT NULL CHECK (wildcard_index >= 0),
    height          BIGINT   NOT NULL CHECK (height >= 0),
    is_spent        BOOLEAN  NOT NULL DEFAULT false,
    spent_height    BIGINT   CHECK (spent_height IS NULL OR spent_height >= 0),
    PRIMARY KEY (wallet_id, txid, vout)
);

CREATE INDEX IF NOT EXISTS elements_utxos_unspent_idx
    ON elements_utxos (wallet_id) WHERE NOT is_spent;
CREATE INDEX IF NOT EXISTS elements_utxos_height_idx
    ON elements_utxos (height);
CREATE INDEX IF NOT EXISTS elements_utxos_spent_height_idx
    ON elements_utxos (spent_height) WHERE spent_height IS NOT NULL;
