-- Historical federation versions per wallet.
--
-- Each row corresponds to one FederationWallet entry in a FederatedWallet
-- stack. The version_index is 0-based (0 = oldest / initial federation).
-- The wallet_handle column stores the BDK database path (Bitcoin) or
-- Elements daemon wallet name needed to reconstruct the wallet instance
-- at startup.

CREATE TABLE IF NOT EXISTS federation_versions (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- FK to the Bitcoin wallets table. NULL for Elements wallets.
    wallet_id       UUID        REFERENCES wallets(id) ON DELETE CASCADE,
    -- FK to the Elements wallets table. NULL for Bitcoin wallets.
    elements_wallet_id UUID     REFERENCES elements_wallets(id) ON DELETE CASCADE,
    -- Position in the FederatedWallet stack (0 = oldest).
    version_index   INT         NOT NULL CHECK (version_index >= 0),
    -- The descriptor for this federation version.
    descriptor      TEXT        NOT NULL,
    -- Threshold at the time this federation was created.
    threshold       INT         NOT NULL CHECK (threshold > 0),
    -- Number of signers at the time this federation was created.
    signer_count    INT         NOT NULL CHECK (signer_count > 0),
    -- JSON-serialized FederationSnapshot for full reconstruction.
    federation_snapshot JSONB   NOT NULL,
    -- BDK changeset JSON (Bitcoin) or daemon wallet name (Elements).
    wallet_handle   TEXT        NOT NULL,
    -- SLIP-77 master blinding key hex (Elements only, NULL for Bitcoin).
    blinding_key    TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Exactly one of wallet_id or elements_wallet_id must be set.
    CHECK (
        (wallet_id IS NOT NULL AND elements_wallet_id IS NULL) OR
        (wallet_id IS NULL AND elements_wallet_id IS NOT NULL)
    ),
    -- Each wallet has at most one entry per version index.
    UNIQUE (wallet_id, version_index),
    UNIQUE (elements_wallet_id, version_index)
);

CREATE INDEX IF NOT EXISTS federation_versions_wallet_idx
    ON federation_versions (wallet_id) WHERE wallet_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS federation_versions_elements_wallet_idx
    ON federation_versions (elements_wallet_id) WHERE elements_wallet_id IS NOT NULL;
