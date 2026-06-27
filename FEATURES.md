# test-app-pkcs11 — Feature Guide

> A complete, developer-oriented tour of every feature in `test-app-pkcs11`,
> the custodial reference app for
> [`asterism-pkcs11`](https://github.com/gmikeska/asterism-pkcs11).
>
> **Audience:** AI coding agents and human developers who need to understand —
> quickly and exactly — what this app can do, how each capability is wired, and
> which function/route to reach for. Every feature below is cross-linked to the
> source symbol that implements it (`src/file.rs::symbol`) so you can jump
> straight to the code. For the high-level pitch and run instructions, see
> [`README.md`](README.md); this document is the exhaustive companion to it.

---

## 1. The use case in one paragraph

`test-app-pkcs11` is a **custodial** wallet service. Users are *customers*, not
key-holders. A single global federation of emulated **HSMs** holds all signing
keys; customers are isolated from one another purely by **BIP-48 account index**
(`m/48'/{coin}'/{account_idx}'/2'`). Every spend is built, signed by the whole
m-of-n HSM federation **server-side**, and broadcast immediately — there is no
proposal/approval lifecycle (that is the job of its sibling,
[`test-app-xpub`](https://github.com/gmikeska/test-app-xpub)). The app speaks
**both Bitcoin and Elements/Liquid**, supports **federation migration** (rotating
the HSM set and sweeping funds to the new federation), and ships a suite of
**CLI example tools** for operating those migrations. It is the testbed that
exercises HSM-backed autonomous signing across two chains.

Mental model: *one vault, many numbered safe-deposit boxes.* The HSMs are the
vault; each customer owns a numbered box (account index) inside it.

---

## 2. Architecture at a glance

```
                          ┌──────────────────────────────────────────┐
   Browser (form posts)   │            Axum router (main.rs)          │
   ───────────────────▶   │  session layer · ServeDir · TraceLayer    │
                          └───────────┬───────────────┬──────────────┘
                                      │               │
                       Bitcoin handlers        Elements handlers
                    (handlers/wallet.rs,     (handlers/elements_*.rs)
                     handlers/transactions)            │
                          │                            │
                  WalletManager              ElementsWalletManager
                  (wallet.rs)                 (elements_wallet.rs)
                     │     │                       │        │
            BDK Wallet   HsmFleet  ◀──shared──▶  HsmFleet  lwk_wollet
            + Core RPC   (hsm.rs)                          + Elements RPC
                 │          │                       │          │
          bitcoind regtest  │                 PgWalletUtxoStore │
                            └──── PKCS#11 dev shim ─────┘  (elements_sync.rs)
                                 (libasterism_dev_hsm)          │
                                                       Block-scan ingestion
                                                       (elements_ingest.rs)
                                                                │
                                              ┌─────────────────┴───────────┐
                                              │   PostgreSQL (migrations/)   │
                                              │  users · wallets · txs ·     │
                                              │  elements_wallets · utxos ·  │
                                              │  federation_versions ·       │
                                              │  sessions                    │
                                              └──────────────────────────────┘
```

**Process boot order** (`src/main.rs::main`): load `.env` → init tracing → build
`AppConfig` → connect Postgres + run `db::migrate` → seed test users → init
`tower-sessions` store + expired-session GC task → build `HsmFleet` (init dev
tokens) → build `WalletManager` (Bitcoin) + `ElementsWalletManager` → eager-seed
the test users' wallets → spawn the Elements block-ingestion service → build the
router → serve on `APP_HOST:APP_PORT` (default `127.0.0.1:8095`).

---

## 3. Feature catalog

### 3.1 Authentication & sessions — `src/auth.rs`

| Capability | Where | Notes |
|---|---|---|
| Argon2id password hashing | `auth::hash_password` / `auth::verify_password` | PHC strings stored in `users.password_hash`. |
| Login / logout | `handlers::auth::{login_get,login_post,logout_post}` | Cookie-backed sessions via `tower-sessions`, Postgres-stored. |
| Login-required extractor | `auth::AuthUser` | Implements `FromRequestParts`: yields the `UserRow` or 303-redirects to `/login`. **Use this in any new authenticated handler.** |
| Optional auth extractor | `AuthUser` `OptionalFromRequestParts` | Yields `Option<AuthUser>` for pages that render differently for anonymous visitors. |
| Seeded test users | `auth::seed_test_users` | Idempotent. Seeds `test1/2/3@test.com` **and** `admin@test.com`, password `test1234`. `admin` is the conventional fee/house account (forced to account index 99). |

Sessions are signed (`with_signed(cookie_key)`), `SameSite::Lax`, 7-day inactivity
expiry, cookie name `asterism_session`. A background task
(`session_store.continuously_delete_expired`) prunes expired rows every minute and
is aborted on graceful shutdown.

### 3.2 Customer wallet model — account-index isolation

- Each user gets exactly one Bitcoin wallet row (`wallets`) and one Elements wallet
  row (`elements_wallets`), each at the next free **account index**
  (`db::next_account_idx` / `db::next_elements_account_idx`).
- The derivation path is `m/48'/{coin}'/{account_idx}'/2'` — built by
  `WalletManager::derivation_path_for` and `ElementsWalletManager::derivation_path_for`.
  `{coin}` is `0` on mainnet, `1` otherwise (`APP_BIP48_COIN_INDEX` overrides).
- Wallets are created lazily on first access (`load_or_init`) **and** eagerly at
  boot for the seeded users (`main::seed_test_wallets` /
  `seed_test_elements_wallets`) — the first cryptoki derivation across N tokens
  takes several seconds, so eager seeding keeps the first page load responsive.
- `ensure_wallet_for_user_at(user, 99)` is how the `admin` house account is pinned
  to index 99.

### 3.3 The HSM federation — `src/hsm.rs` (`HsmFleet`)

This is the heart of the app and the main thing it demonstrates about
`asterism-pkcs11`.

- **Token discovery & init.** `HsmFleet::new` verifies `PKCS11_LIB` exists, then
  calls `asterism::dev_signer::init_dev_token` for every discovered token
  (idempotent — the programmatic equivalent of `pkcs11-tool --init-token`).
- **Per-customer key namespace.** Every customer's federation lives on the *same*
  physical tokens but under a distinct Asterism label `signer-{user_uuid}`
  (`HsmFleet::signer_label`). On-token objects live at
  `asterism/v1/{label}/{priv,policy,sigrate}`.
- **Lazy derive-or-load with caching.** `HsmFleet::signers_for(signer_id, path)`
  opens authenticated sessions (one per token, on a `spawn_blocking` thread) and
  either `Pkcs11Signer::load`s existing keys or `derive_from_seed`s a fresh master
  (empty seed → the dev shim looks up the slot's preconfigured BIP-39 mnemonic).
  Results are cached per `signer_id` so the open-session count stays bounded.
- **Network correctness.** `setup_dev_federation` is deliberately **bypassed**
  because it hardcodes `Network::Testnet`; the fleet honours `BITCOIN_NETWORK`
  instead. Derived signers are wrapped in `NetworkPatchedSigner` (re-exported from
  `asterism-pkcs11`) so descriptors stamp the right network.
- **Key lifecycle helpers.** `HsmFleet::evict` drops a cached set (closing sessions);
  `HsmFleet::delete_keys` permanently deletes a signer's on-token objects (used by
  tests and future "reset wallet" flows).
- **The default federation vs. the full pool.** `APP_FED_SIGNERS` selects which
  tokens form *new* wallets (`fed_signer_indices`); `APP_FED_THRESHOLD` sets `m`.
  The full token pool remains available so migration tools can rotate signers in
  and out.

### 3.4 Bitcoin wallet features — `src/wallet.rs` + `src/handlers/wallet.rs`

Each `UserWallet` ties a `bdk_wallet::Wallet` to the customer's account, registers
all `Pkcs11Signer`s on both keychains, and tracks **every federation version**
(see §3.6). Concurrency: a per-user `AsyncMutex<Wallet>` serialises same-user
requests; different users sign in parallel.

| Feature | Function | Route |
|---|---|---|
| Chain sync (blocks + mempool) | `UserWallet::sync` (drives `bdk_bitcoind_rpc::Emitter` per version-wallet, persists merged `ChangeSet`) | implicit on every page |
| Balance (summed across versions) | `UserWallet::balance` → `BalanceView` | receive/send cards |
| Reveal receive addresses | `UserWallet::reveal_addresses` / `revealed_addresses_all_versions` (default `REVEAL_COUNT = 20`) | `GET /wallet/receive` |
| Change-address listing | `UserWallet::change_addresses` | receive tab |
| Address detail (QR + receipts) | `UserWallet::address_history` + `locate_address`; QR via `qrcode` crate | `GET /wallet/addresses/{address}` |
| **Send = build→sign(m-of-n)→finalize→broadcast→persist** | `UserWallet::build_sign_and_broadcast` | `POST /wallet/send` |
| Sweep (drain wallet to one address) | `UserWallet::sweep_to` | (library method; used by migration) |
| Recent broadcast history | `db::list_transactions_for_wallet` → `TransactionListView` | send tab |
| Federation status page | `handlers::wallet::federation` | `GET /wallet/federation` |

**Critical implementation detail to know before touching signing:**
`build_sign_and_broadcast` uses `SignOptions { try_finalize: false, .. }` when
running the `SigningCoordinator`. The default BDK options finalize immediately
after each signer, moving partial sigs into `final_script_witness` and emptying
`partial_sigs`; the coordinator would then count zero signatures and refuse to
finalize. Keep `try_finalize: false` for the sign pass, finalize separately.

### 3.5 Elements / Liquid wallet features — `src/elements_wallet.rs` + `src/handlers/elements_*.rs`

A **client-side** wallet model (no per-user daemon wallets — those don't scale):

- Each wallet is an `ElementsWollet` = CT descriptor + SLIP-77 master blinding key
  (`derive_master_blinding_key`, deterministic from `user_id` + `account_idx`).
- UTXOs are captured by the shared **block-scan pipeline** (§3.7) into Postgres,
  not by querying a node wallet. Balance/addresses read from `PgWalletUtxoStore`.
- Confidential-transaction aware: blinded PSETs, explicit fee output parsing, L-BTC
  amounts surfaced as `f64` BTC.

| Feature | Function | Route |
|---|---|---|
| Balance from captured UTXOs | `UserElementsWallet::balance` | `GET /elements/wallet/receive` |
| Reveal addresses (per federation version) | `reveal_addresses` / `reveal_addresses_all_versions` | receive tab |
| Change addresses | `change_addresses` / `change_addresses_for_version` | receive tab |
| Address history (incl. spent/historical) | `address_history` | `GET /elements/wallet/addresses/{address}` |
| **Send** (build PSET → HSM-sign → finalize P2WSH → broadcast) | `build_sign_and_broadcast` | `POST /elements/wallet/send` |
| Sweep all captured UTXOs | `sweep_to` | (library method) |
| Tip height | `tip_height` (via `RpcChainSource`) | header |
| Federation page | `handlers::elements_wallet::federation` | `GET /elements/wallet/federation` |
| Transaction detail | `handlers::elements_transactions::show` | `GET /elements/wallet/transactions/{txid}` |
| LWK network resolution | `ElementsWalletManager::lwk_network` (regtest sources policy asset + genesis from the node) | cached |

Signing uses `ElementsSigner::sign_pset` across the HSM set;
`finalize_p2wsh_pset` then assembles the witnesses. For migrations there are
index-scoped signing helpers (`sign_migration_pset_inputs`) that temporarily clear
`bip32_derivation` on inputs an account doesn't own — necessary because all
accounts share the same physical HSM fingerprints and differ only by path.

### 3.6 Federation versioning (multi-version wallets)

Both chains record **federation versions** in the `federation_versions` table
(`db::list_federation_versions_for_wallet` /
`..._for_elements_wallet`). A wallet is reconstructed from its stored versions, not
from the current `.env` — so loading stays correct even after `APP_FED_SIGNERS`
changes or a migration runs.

- Bitcoin: `WalletManager::build_federated_wallet` builds a
  `BtcFederatedWallet<NetworkPatchedSigner>` spanning all versions;
  `reconstruct_federation_from_version` matches signers from the HSM pool by
  fingerprint extracted from the stored descriptor.
- New deposits always derive from the **current** (newest) federation; balance and
  history aggregate across **all** versions, so funds at old addresses stay visible
  and spendable.
- The receive page renders one tab per version (`FederationAddressGroup`,
  `v1`, `v2`, … `vN (current)`).

### 3.7 Scalable Elements block-scan ingestion — `src/elements_sync.rs` + `src/elements_ingest.rs`

This is the consuming-app half of `asterism-elements`'s `sync` traits, and the
reason the Elements side scales to many customers:

- `PgBlockStore` / `PgWalletUtxoStore` — Postgres implementations of `BlockStore`
  and `WalletUtxoStore` (migration `0007`). They hold a captured Tokio `Handle` and
  `block_on` their sqlx queries, so the engine runs safely on a `spawn_blocking`
  thread.
- `RpcChainSource` — `ElementsChainSource` over the node's JSON-RPC (raw `call`
  with Elements consensus (de)serialisation; `bitcoincore-rpc`'s typed helpers
  assume Bitcoin encodings).
- `elements_ingest::spawn` — a single background task that, every 10s, loads
  **every** wallet's **every** federation version, builds one `BlockScanEngine`,
  fetches each new block **once**, and matches it against the union of all watched
  scripts. Reorg-aware (`rollback_above`), gap-limit `SCAN_GAP = 100`.

The in-memory fakes in `asterism-elements::sync::tests` and the Postgres stores
share the same contract; `elements_sync.rs`'s `pg_stores_honor_contracts` test
asserts that (skips gracefully without a DB).

### 3.8 Federation migration — `examples/federation_migration.rs`

A guided CLI that rotates the HSM federation and sweeps funds to the new one,
across **all** discovered accounts at once (federation change is infrastructure-
level, not per-user). Driven by a TOML file (see
`examples/federation_change.example.toml`).

- **Strategies:**
  - `account-for-account` — every account swept in a **single** transaction (max
    fee efficiency; discloses common ownership on-chain). Implemented for both
    Bitcoin and Elements.
  - `account-for-account-batched` — one tx per large account, small accounts
    (below `small_account_threshold`) bundled, fee account migrates last. Bitcoin
    today; the Elements batched path (chained confidential fee-change) is the
    documented next milestone.
- **Fee-account-pays.** `fee_account_idx` (e.g. the `admin`/99 house account) funds
  every sweep fee; the tool pre-flights that account's balance against the
  estimated total before touching anything.
- **Index-scoped signing.** Because all accounts share HSM fingerprints, the
  signer clears `bip32_derivation` on inputs an account doesn't own, signs, then
  restores (`sign_scoped` in the example / `sign_migration_inputs` in `wallet.rs`).
- **Blinding-key rotation (Elements).** `rotate_blinding_key = true` derives a
  fresh SLIP-77 key per new version so removed signers can't derive future blinding
  keys; `false` keeps accounting continuity.
- **Safety rails.** `--dry-run` (plan only), `--sweep-only` (skip the
  federation-record step and just sweep), `--elements` (run the Liquid side),
  step-by-step `[y/N]` confirmations, in-progress-migration guard
  (`db::has_in_progress_elements_migration`), and "restart the app to pick up the
  new federation" reminders.

Full operator loop (from the example doc-comments):

```text
./reset-dev.sh --yes
cargo run --example migration_bootstrap            # create accounts + funding addrs
#   …fund + mine…
cargo run --example migration_bootstrap -- --sync  # verify balances
cargo run --example federation_migration -- --config examples/federation_change.example.toml
cargo run --example migration_verify               # post-migration check
```

### 3.9 CLI example tools — `examples/`

| Tool | Purpose |
|---|---|
| `migration_bootstrap.rs` | Create users/wallets, derive receive addresses, print funding commands; `--sync` to verify balances. |
| `federation_migration.rs` | The migration engine described in §3.8 (Bitcoin + Elements). |
| `migration_verify.rs` | Sync all wallets, print per-account balances, check `federation_versions` migration status, report pass/fail. |

All three import the app's modules through the **library crate** (`src/lib.rs`
exposes every module publicly) and load the same `.env` as the web server.

### 3.10 Configuration surface — `src/config.rs`

`AppConfig::from_env` reads three groups (a sibling `.env` is auto-loaded):

- **Web/DB:** `APP_HOST`, `APP_PORT`, `APP_SESSION_SECRET` (≥64 bytes hex),
  `DATABASE_URL`.
- **Bitcoin Core RPC:** `BITCOIN_RPC_HOST/PORT/USER/PASSWORD`, `BITCOIN_NETWORK`,
  `BITCOIN_WALLET_NAME` (default `asterism-pkcs11`), `APP_BIP48_COIN_INDEX`
  (optional; defaults from network).
- **HSM federation:** `PKCS11_LIB`, sequential `APP_HSM_{N}_LABEL/_PIN/_SO_PIN`
  (scanned from N=1 until a gap), `APP_FED_THRESHOLD`, `APP_FED_SIGNERS`
  (1-based, comma-separated indices into the discovered tokens).
- **Elements:** `ELEMENTS_RPC_HOST/PORT/USER/PASSWORD`, `ELEMENTS_NETWORK`
  (`liquid` | `liquidtestnet` | `elementsregtest`).

The dev shim also reads `SOFTHSM2_LIB`, `SOFTHSM2_CONF`, and `DEV_HSM_CONFIG`
(`dev-hsm.toml`, the per-token BIP-39 mnemonics) — those are consumed by
`libasterism_dev_hsm`, not by this app directly.

### 3.11 Route map

**Bitcoin**

| Method | Path | Handler |
|---|---|---|
| GET | `/` | `home::root` → `/wallet/receive` |
| GET/POST | `/login` | `auth::login_get` / `login_post` |
| POST | `/logout` | `auth::logout_post` |
| GET | `/wallet` | `home::wallet_root` |
| GET | `/wallet/receive` | `wallet::receive` |
| GET/POST | `/wallet/send` | `wallet::send_get` / `send_post` |
| GET | `/wallet/federation` | `wallet::federation` |
| GET | `/wallet/addresses/{address}` | `wallet::address_show` |
| GET | `/wallet/transactions/{txid}` | `transactions::show` |

**Elements** (parity set under `/elements/wallet/...`): `home::elements_wallet_root`,
`elements_wallet::{receive,send_get,send_post,federation,address_show}`,
`elements_transactions::show`.

`/static/*` is served by `ServeDir`; all routes are wrapped in `TraceLayer` + the
session layer. Everything is form posts + Askama renders — **no JSON API, no
client-side JS, no `node_modules`.**

### 3.12 Dev & test infrastructure

- `reset-dev.sh` — wipe dev DB + HSM state for a clean migration run.
- `reset-test-hsms.sh` — wipe automated-testing tokens (HSMs 5–15) without touching
  the manual tokens (1–4).
- `migrations/0001..0007_*.sql` — schema: users, sessions, wallets, transactions,
  elements wallets, federation versions, migration status, elements block sync.
- `tests/` — HSM-signing tests (`*_hsm_signing`, hard-require SoftHSM2), e2e tests
  (`*_e2e`, skip gracefully without RPC/DB env), batched/offline migration tests.
  Running them needs SoftHSM2 + live regtest nodes + Postgres (see the repo's
  TOOLS notes; container restarts wipe SoftHSM2).

---

## 4. Developer entry points (where to start for common tasks)

| I want to… | Start here |
|---|---|
| Add an authenticated route | extractor `auth::AuthUser`, register in `main.rs`, follow `handlers::wallet::receive` as a template. |
| Change how spends are signed (Bitcoin) | `UserWallet::build_sign_and_broadcast` (mind the `try_finalize:false` note). |
| Change how spends are signed (Elements) | `UserElementsWallet::build_sign_and_broadcast`. |
| Touch HSM key derivation/caching | `HsmFleet::signers_for` + `derive_signers`. |
| Add a federation-version-aware view | `WalletManager::build_federated_wallet` + `reconstruct_federation_from_version`. |
| Extend the migration tool | `examples/federation_migration.rs` (`run_elements_migration`, `plan_elements_batched`). |
| Add captured-UTXO queries (Elements) | `PgWalletUtxoStore` in `src/elements_sync.rs`. |
| Add a config knob | `AppConfig` + `AppConfig::from_env` in `src/config.rs`. |

## 5. Relationship to the rest of Asterism

- Library crate: [`asterism-pkcs11`](https://github.com/gmikeska/asterism-pkcs11)
  (HSM signer), consumed through the [`asterism`](https://github.com/gmikeska/asterism)
  facade with features `pkcs11`, `elements`, `dev-signer`.
- Core descriptor/PSBT/federation machinery:
  [`asterism-core`](https://github.com/gmikeska/asterism-core).
- Elements wallet + sync traits:
  [`asterism-elements`](https://github.com/gmikeska/asterism-elements).
- Dev HSM shim: [`asterism-dev-signer`](https://github.com/gmikeska/asterism-dev-signer)
  / `libasterism_dev_hsm`.
- Sibling app (self-custody, hardware wallets, proposal-based signing):
  [`test-app-xpub`](https://github.com/gmikeska/test-app-xpub) — see its
  `FEATURES.md` for the contrasting model.
