-- Per-wallet reorg-detection checkpoints for the nodeless (Electrum/Esplora)
-- Elements chain backend (Postgres impl of emvault-elements `CheckpointStore`).
--
-- The block-scan (RPC) path uses `elements_sync_cursor` + `elements_blocks` for
-- reorg detection. The nodeless path has no blocks to store; instead it keeps a
-- thin sparse map of `(height, block_hash)` synced tips per wallet, and detects
-- a reorg by re-querying the backend header at each stored height. Keyed by
-- wallet so each wallet's reorg signal stays accurate when one client scans many
-- wallets in a pass.
CREATE TABLE IF NOT EXISTS elements_chain_checkpoints (
    wallet_id   UUID        NOT NULL REFERENCES elements_wallets(id) ON DELETE CASCADE,
    height      BIGINT      NOT NULL CHECK (height >= 0),
    block_hash  TEXT        NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (wallet_id, height)
);
