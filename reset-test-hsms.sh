#!/usr/bin/env bash
#
# Reset SoftHSM tokens 5–15 (automated-testing pool).
#
# Leaves tokens 1–4 (manual testing) untouched.
# After deletion, the tokens are re-provisioned automatically the next time
# any example or the web app starts — HsmFleet::new() calls init_dev_token()
# for every APP_HSM_{N} entry, which creates missing tokens on free slots.
#
# Usage:
#   ./reset-test-hsms.sh          # interactive confirmation
#   ./reset-test-hsms.sh --yes    # skip confirmation

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "error: $ENV_FILE not found" >&2
    exit 1
fi

# Source .env for SOFTHSM2_CONF.
while IFS='=' read -r key value; do
    [[ -z "$key" || "$key" == \#* ]] && continue
    value="${value%%#*}"
    value="${value%"${value##*[! ]}"}"
    export "$key=$value" 2>/dev/null || true
done < "$ENV_FILE"

SOFTHSM_CONF="${SOFTHSM2_CONF:-/etc/softhsm/softhsm2.conf}"
export SOFTHSM2_CONF="$SOFTHSM_CONF"

if [[ ! -f "$SOFTHSM_CONF" ]]; then
    echo "error: SOFTHSM2_CONF not found at $SOFTHSM_CONF" >&2
    exit 1
fi

# Labels to reset — HSMs 5 through 15.
LABELS=()
for i in $(seq 5 15); do
    var="APP_HSM_${i}_LABEL"
    label="${!var:-}"
    if [[ -n "$label" ]]; then
        LABELS+=("$label")
    fi
done

if [[ ${#LABELS[@]} -eq 0 ]]; then
    echo "No test HSM labels found (APP_HSM_5_LABEL through APP_HSM_15_LABEL)."
    echo "Make sure they are defined in $ENV_FILE."
    exit 1
fi

echo "=== Reset test HSMs (5–15) ==="
echo "Tokens to delete:"
for label in "${LABELS[@]}"; do
    echo "  - $label"
done
echo ""
echo "Tokens 1–4 will NOT be touched."
echo ""

if [[ "${1:-}" != "--yes" ]]; then
    read -rp "Delete these tokens? They will be auto-recreated on next app start. [y/N] " confirm
    if [[ "$confirm" != [yY] ]]; then
        echo "Aborted."
        exit 0
    fi
fi

echo ""

deleted=0
skipped=0
for label in "${LABELS[@]}"; do
    # softhsm2-util --delete-token requires the token to exist.
    if softhsm2-util --show-slots 2>/dev/null | grep -q "Label:.*${label}"; then
        echo "Deleting token: $label"
        softhsm2-util --delete-token --token "$label" 2>/dev/null || true
        deleted=$((deleted + 1))
    else
        echo "Skipping (not found): $label"
        skipped=$((skipped + 1))
    fi
done

echo ""
echo "Done. Deleted: $deleted, Skipped (not found): $skipped"
echo "Tokens will be auto-provisioned on next cargo run."
