#!/usr/bin/env bash
# Taproot mixed-vendor e2e launcher for test-app-pkcs11.
#
# Boots the app configured for a 2-of-3 *taproot* federation whose signers are
# 2 dev SoftHSM tokens + 1 live Securosys CloudHSM (token #3). Uses a dedicated
# fresh DB and a clean SoftHSM store so the demo vault is a pristine taproot
# vault. Everything else (RPC creds, ports, session secret) comes from .env.
#
#   ./run-tap-e2e.sh          # boot the web app on :8095
#
# Log in at http://127.0.0.1:8095 as test1@test.com / test1234 to see the vault.
set -euo pipefail
cd "$(dirname "$0")"

CREDS="/shared/Emerald-Foundation_SBX01_YHRXBOTJLQWT-credentials_20260803.txt"
SEC_PIN="$(grep -oP 'PKCS#11 PIN:\s*\K\S+' "$CREDS")"
SEC_JWT="$(grep -oP 'JWT Token:\s*\K\S+' "$CREDS")"

# Securosys TSB (Schnorr) transport — enables the taproot signer on the
# Securosys backend (SecurosysBackend self-configures from these + `tsb` feature).
export SECUROSYS_TSB_URL="https://sbx-rest-api.cloudshsm.com/v1"
export SECUROSYS_TSB_JWT="$SEC_JWT"
# Deterministic 64-byte seed for the Securosys SLIP-10 master (demo only).
SEED64="2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"

# --- fresh DB (clean taproot vault); uses the base .env's working SoftHSM
#     token store so the dev-token seeds/mnemonics are already provisioned. ---
export DATABASE_URL="postgres://asterism:asterism@host.docker.internal:5544/asterism_pkcs11_tap"

# --- taproot federation: 2-of-3, tokens {0=dev,1=dev,2=securosys} ---
export APP_SCRIPT_TYPE="taproot"
export APP_FED_THRESHOLD="2"
export APP_FED_SIGNERS="1,2,3"
# Fast startup: provision each user's vault on their first request instead of
# eager-seeding all users across the whole token pool at boot.
export APP_SKIP_EAGER_SEED="1"

# Redefine token #3 (1-indexed) as the live Securosys partition.
export APP_HSM_3_VENDOR="securosys"
export APP_HSM_3_LABEL="YHRXBOTJLQWT"
export APP_HSM_3_LIB="/usr/lib/libprimusP11.so"
export APP_HSM_3_PIN="$SEC_PIN"
export APP_HSM_3_SEED="$SEED64"

# agent is already in the primus group, so libprimusP11 can read
# /etc/primus/.secrets.cfg without an sg wrapper.
exec ./target/debug/test-app-pkcs11 "$@"
