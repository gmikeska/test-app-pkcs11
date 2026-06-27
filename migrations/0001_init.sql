-- test-app-pkcs11 schema (emvault_pkcs11 database).
--
-- Customer-facing app: users own no signers — they are isolated by their
-- own BIP-48 account index against a single global 3-of-3 HSM federation.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ----------------------------------------------------------------------------
-- users
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS users (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT        NOT NULL UNIQUE,
    password_hash TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS users_email_idx ON users (lower(email));
