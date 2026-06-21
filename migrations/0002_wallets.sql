-- One BDK-backed Bitcoin wallet per user.
--
-- The wallet is a 3-of-3 federation across the three SoftHSM tokens, with
-- each HSM contributing an xpub at m/48'/{coin}'/{account_idx}'/2'. Every
-- user has a unique `account_idx` so two wallets never share key material.
--
-- bdk_changeset is the JSON-encoded `bdk_wallet::ChangeSet` — the source
-- of truth for revealed addresses, UTXOs, and the local chain tip.

CREATE TABLE IF NOT EXISTS wallets (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID        NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    -- BIP-48 account index (the third hardened component of the path).
    account_idx      INT         NOT NULL UNIQUE CHECK (account_idx >= 0),
    -- Multipath wsh(sortedmulti(...)) descriptor with /<0;1>/* wildcards.
    descriptor       TEXT        NOT NULL,
    -- JSON-encoded `bdk_wallet::ChangeSet`. Never NULL after first
    -- creation — we persist the initial `take_staged()` immediately.
    bdk_changeset    JSONB,
    chain_tip_height INTEGER,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS wallets_user_idx ON wallets (user_id);
