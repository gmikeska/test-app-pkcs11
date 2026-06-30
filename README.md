# test-app-pkcs11

> Customer-facing test web app exercising
> [`emvault-pkcs11`](https://github.com/gmikeska/emvault-pkcs11): each user gets a 3-of-3
> HSM-backed Bitcoin wallet, every spend is signed by all 3 emulated HSMs
> server-side and broadcast immediately.

`test-app-pkcs11` mirrors the architecture, layout, and styling of
[`test-app-xpub`](https://github.com/gmikeska/test-app-xpub), but treats users as customers
rather than signer custodians:

- Users never bring an XPUB. There is no onboarding flow.
- Users are not federation members. The 3 HSMs comprise a global signer
  set; users are isolated by **BIP-48 account index**.
- Each user receives a fresh `bdk_wallet::Wallet` whose descriptor
  derives from `m/48'/{coin}'/{account_idx}'/2'` on every HSM.
- Sending collapses build → sign (3-of-3) → finalize → broadcast into a
  single `POST /wallet/send`. There is no proposal lifecycle.

Both Bitcoin **and** Elements/Liquid are wired up: each user gets a
parallel client-side Elements wallet, and the app supports federation
migration (HSM rotation + fund sweep) on both chains.

## Crate integration guide

For a developer-oriented walkthrough of **how this app consumes the EmVault
crates** — the HSM `Pkcs11Signer`, server-side m-of-n signing via
`SigningCoordinator`, federation construction + versioning, the
`core::migration` sweep engine, and the Elements wallet + the `sync` traits
this app **implements** — see **[`FEATURES.md`](FEATURES.md)**.

`FEATURES.md` is the **reference integration** for
[`emvault-pkcs11`](https://github.com/gmikeska/emvault-pkcs11) +
[`emvault-core`](https://github.com/gmikeska/emvault-core) +
[`emvault-elements`](https://github.com/gmikeska/emvault-elements): for each
library capability it shows the exact API the app calls and where
(`src/file.rs::symbol` ↔ `emvault::…::symbol`), so AI/human developers can learn
*how to integrate the crates* — including the key contrast with `test-app-xpub`
(autonomous HSM signing vs. browser-mediated external signing). It covers the
app↔crate boundary, not the UI, routes, or DB schema. This README is the
quick-start; `FEATURES.md` is the deep integration reference.

## Prerequisites

1. **Build the dev shim.** From the repo root:
   ```bash
   cargo build --release -p libemvault-dev-hsm
   ```
   Make sure `PKCS11_LIB` in `.env` points at the resulting `.so`.
2. **PostgreSQL.** Create the database (`createdb emvault_pkcs11`) and
   make sure `DATABASE_URL` in `.env` matches.
3. **Bitcoin Core regtest.** Same node `test-app-xpub` uses; configured
   via `BITCOIN_RPC_*` in `.env`.
4. **SoftHSM 2.** Installed at `SOFTHSM2_LIB`; the dev shim wraps it.

## Run

```bash
cd test-app-pkcs11
cargo run
# -> listens on http://127.0.0.1:8095
```

Three test users are seeded at startup
(`test1@test.com` / `test2@test.com` / `test3@test.com`, password
`test1234`). The first time each logs in, the app provisions their
3-of-3 federation across the three SoftHSM tokens at the next available
account index.

## Routes

| Method     | Path                                  | Behaviour                                  |
| ---------- | ------------------------------------- | ------------------------------------------ |
| GET        | `/`                                   | redirect to `/wallet/receive`              |
| GET / POST | `/login`                              | login form / submission                    |
| POST       | `/logout`                             | end session                                |
| GET        | `/wallet`                             | redirect to `/wallet/receive`              |
| GET        | `/wallet/receive`                     | balance card + 20 reveal addresses         |
| GET        | `/wallet/send`                        | send form + recent broadcast transactions  |
| POST       | `/wallet/send`                        | build, sign 3-of-3, broadcast              |
| GET        | `/wallet/addresses/{address}`         | QR + receipts for the user's address       |
| GET        | `/wallet/transactions/{txid}`         | broadcast transaction detail               |

No JSON endpoints, no client-side JS, no `node_modules`. Everything is
form posts and Askama renders.
