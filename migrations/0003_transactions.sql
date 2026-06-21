-- Append-only ledger of broadcast transactions per wallet.
--
-- There is no proposal lifecycle: POST /wallet/send builds, signs (3-of-3
-- HSMs), finalizes, and broadcasts in a single server call. This table
-- records what was actually shipped to the network so the Send tab can
-- render recent activity.

CREATE TABLE IF NOT EXISTS transactions (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id     UUID        NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    txid          TEXT        NOT NULL,
    recipient     TEXT        NOT NULL,
    amount_sat    BIGINT      NOT NULL CHECK (amount_sat > 0),
    fee_sat       BIGINT      NOT NULL CHECK (fee_sat   >= 0),
    -- Hex-encoded raw transaction bytes (consensus-serialized).
    raw_tx_hex    TEXT        NOT NULL,
    label         TEXT,
    broadcast_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (wallet_id, txid)
);

CREATE INDEX IF NOT EXISTS transactions_wallet_broadcast_idx
    ON transactions (wallet_id, broadcast_at DESC);
