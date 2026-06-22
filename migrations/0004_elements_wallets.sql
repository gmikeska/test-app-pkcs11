-- One Elements/Liquid wallet per user, parallel to the Bitcoin `wallets` table.
--
-- Uses the same 3-of-3 HSM federation but with a CT descriptor
-- (ct(slip77(<mbk>), elwsh(sortedmulti(...)))) and the Elements daemon
-- as the chain backend instead of BDK + Bitcoin Core.

CREATE TABLE IF NOT EXISTS elements_wallets (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID        NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    account_idx         INT         NOT NULL UNIQUE CHECK (account_idx >= 0),
    -- CT multipath descriptor: ct(slip77(<mbk>), elwsh(sortedmulti(...)))/<0;1>/*
    descriptor          TEXT        NOT NULL,
    -- 32-byte SLIP-77 master blinding key (hex-encoded for portability).
    master_blinding_key TEXT        NOT NULL,
    -- Elements daemon wallet name for RPC calls.
    daemon_wallet_name  TEXT        NOT NULL UNIQUE,
    chain_tip_height    INTEGER,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS elements_wallets_user_idx ON elements_wallets (user_id);

-- Append-only ledger of broadcast Elements transactions per wallet.

CREATE TABLE IF NOT EXISTS elements_transactions (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id     UUID        NOT NULL REFERENCES elements_wallets(id) ON DELETE CASCADE,
    txid          TEXT        NOT NULL,
    recipient     TEXT        NOT NULL,
    amount_sat    BIGINT      NOT NULL CHECK (amount_sat > 0),
    fee_sat       BIGINT      NOT NULL CHECK (fee_sat >= 0),
    raw_tx_hex    TEXT        NOT NULL,
    label         TEXT,
    broadcast_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (wallet_id, txid)
);

CREATE INDEX IF NOT EXISTS elements_transactions_wallet_broadcast_idx
    ON elements_transactions (wallet_id, broadcast_at DESC);
