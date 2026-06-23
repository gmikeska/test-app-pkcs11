#!/usr/bin/env bash
#
# Reset the test-app-pkcs11 dev environment to a clean state.
#
# What it does:
#   1. Drops and recreates the PostgreSQL database.
#   2. Wipes all SoftHSM token data so old key objects (e.g. from a
#      label-format change) don't accumulate.
#   3. Done — next `cargo run` re-initializes tokens and seeds users/wallets.
#
# Usage:
#   ./reset-dev.sh          # uses .env from the script's directory
#   ./reset-dev.sh --yes    # skip confirmation prompt

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "error: $ENV_FILE not found" >&2
    exit 1
fi

# Source .env (simple key=value lines only; skip comments and blanks).
while IFS='=' read -r key value; do
    [[ -z "$key" || "$key" == \#* ]] && continue
    value="${value%%#*}"          # strip inline comments
    value="${value%"${value##*[! ]}"}"  # trim trailing whitespace
    export "$key=$value" 2>/dev/null || true
done < "$ENV_FILE"

DB_URL="${DATABASE_URL:?DATABASE_URL not set in .env}"
DB_NAME="${DB_URL##*/}"
DB_BASE="${DB_URL%/*}"

# Resolve the SoftHSM token directory from SOFTHSM2_CONF.
SOFTHSM_CONF="${SOFTHSM2_CONF:-/etc/softhsm/softhsm2.conf}"
TOKEN_DIR=""
if [[ -f "$SOFTHSM_CONF" ]]; then
    TOKEN_DIR="$(grep -E '^\s*directories\.tokendir' "$SOFTHSM_CONF" | head -1 | sed 's/.*=\s*//' | xargs)"
fi

echo "=== test-app-pkcs11 dev reset ==="
echo "Database:   $DB_NAME (from DATABASE_URL)"
if [[ -n "$TOKEN_DIR" && -d "$TOKEN_DIR" ]]; then
    echo "Token dir:  $TOKEN_DIR (from $SOFTHSM_CONF)"
else
    echo "Token dir:  (not found or not a directory — skipping HSM wipe)"
fi
echo ""

if [[ "${1:-}" != "--yes" ]]; then
    read -rp "This will destroy all dev data. Continue? [y/N] " confirm
    if [[ "$confirm" != [yY] ]]; then
        echo "Aborted."
        exit 0
    fi
fi

echo ""

# 1. Drop and recreate the database.
echo "Dropping database $DB_NAME ..."
dropdb --if-exists "$DB_NAME" 2>/dev/null || psql "$DB_BASE/postgres" -c "DROP DATABASE IF EXISTS \"$DB_NAME\";"
echo "Creating database $DB_NAME ..."
createdb "$DB_NAME" 2>/dev/null || psql "$DB_BASE/postgres" -c "CREATE DATABASE \"$DB_NAME\";"
echo "Database reset complete."

# 2. Wipe SoftHSM token data.
if [[ -n "$TOKEN_DIR" && -d "$TOKEN_DIR" ]]; then
    echo "Clearing SoftHSM tokens in $TOKEN_DIR ..."
    # Remove all token slot directories (UUID-named) but keep the config file.
    find "$TOKEN_DIR" -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} +
    echo "SoftHSM tokens cleared."
else
    echo "Skipping SoftHSM wipe (token directory not found)."
fi

echo ""
echo "Done. Run 'cargo run' to re-initialize."
