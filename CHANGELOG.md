# Changelog

All notable changes to `test-app-pkcs11` (the PKCS#11 / HSM reference app) are
documented here. This is the app's first CHANGELOG; the `0.2.0` entry summarizes
the current cycle (which tracks the emvault suite **0.8.0** / Bitcoin Taproot
release). Earlier history lives in git.

## [0.12.0] - 2026-11-24

Tracks emvault suite **0.12.0** (the `Pkcs11Signer::sign_sighash` seam; suite 0.11.0 is
yanked). Version aligned to the suite number rather than continuing the app's own 0.x line.

### Fixed
- **The emvault requirements were stale at `"0.10"` and the build was broken.** With the local
  tree at 0.12.0, `emvault-dev-signer = "^0.10.0"` could not resolve against its own path dep
  and `cargo check` failed outright. Requirements now read `"0.12"`.
- **The reorg e2e gates pointed their database at a different product**
  (`tests/reorg_mempool_requeue_e2e.rs`, `tests/reorg_reconciliation_e2e.rs`). Both overrode
  `DATABASE_URL` to `asterism:asterism@host.docker.internal:5546/asterism_pkcs11`, a workaround
  from when `.env` still named `127.0.0.1:5432`. `.env` now names the right endpoint
  (`:5544`, container `emv-asterism-pg-5544`), so the override had become the bug: `:5546` is
  `gv-dev-pg-5546`, a **GroupVault** database, which rejects the asterism credentials with
  `28P01`. ▶ And when that container is merely stopped it reads as `PoolTimedOut` instead —
  which looks like "no database anywhere" rather than "the wrong database". Both now inherit
  `DATABASE_URL` from `.env`.

- **The reorg gates were provisioning against the whole HSM pool, including an unreachable
  Securosys partition** (EMV-6; `tests/reorg_mempool_requeue_e2e.rs`,
  `tests/reorg_reconciliation_e2e.rs`). `HsmFleet::signers_for` derives a signer on **every** token
  in the pool, and `fed_signer_indices` only selects the federation's subset afterwards
  (`src/wallet.rs:462-467`). `.env` lists `APP_HSM_16` as securosys at `/usr/lib/libprimusP11.so`,
  which exists here with no HSM behind it, so the 16th `Pkcs11Session::open` returned
  `CKR_GENERAL_ERROR` from `C_Initialize` and provisioning died as
  `Hsm(Pkcs11(Initialize(Pkcs11(GeneralError, Initialize))))`.
  ▶ **The symptom accused the wrong component**: the dev shim's log was silent, because the shim is
  not the module that refused. The tell is the count — **exactly 15** successful `base-key`
  derivations (the 15 dev tokens) and then the error; **3** after the fix.
  Both gates now call `trim_hsm_pool_to_federation_tokens()`, which clears
  `APP_HSM_{4..=32}_LABEL` so discovery stops at token 4 and the pool is exactly the three the
  federation asks for. ▶ It must run **after** `dotenvy::from_path(".env")`, because dotenvy sets
  any variable that is not currently set — a shell `unset` of those vars is silently undone, which
  is why an earlier attempt to exclude this cause by unsetting them appeared to disprove it.
  `rpc_reorg_mempool_requeue_does_not_revert` now passes.
- **The reconciliation gate's RBF eviction was rejected by the fee-*rate* ceiling**
  (`tests/reorg_reconciliation_e2e.rs`). `EVICT_FEE_SATS` is a flat 0.01 BTC chosen to dwarf the
  deposit's fee so D' wins the replacement; on a 1-in-1-out transaction that is ~50 BTC/kvB, over
  `sendrawtransaction`'s **0.10 BTC/kvB** `maxfeerate` default. Now broadcast with `maxfeerate: 0`.
  ▶ The error text (`-25 Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)`)
  names `-maxtxfee` first and sends you to node configuration; the 0.01 BTC fee is well under that
  0.1 BTC default, and the binding limit is the per-call rate.

### Known issues
- **`rpc_reorg_reverts_completed_migration` still fails** (EMV-8), now much further along — through
  provisioning, signing and the RBF eviction — on `v0 must see the funding UTXO`: balance
  `1000000000` SAT against an expected `500000000`, exactly double the single 5 BTC deposit. Not
  address reuse: the observed runs revealed different v0 addresses and `db::next_account_idx` is
  `COALESCE(MAX(account_idx)+1, 0)`, so each run gets a fresh index and descriptor.
- **`elements_sync::tests::pg_stores_honor_contracts` is not hermetic** (EMV-7). It shares the
  `asterism_pkcs11` database rather than taking an isolated one, and fails intermittently on
  leftover rows — asserting `block_hash_at(99) == None` against a real stored hash. It has both
  passed and failed on this build; the deciding factor is database residue, not code.
- **One unreachable vendor token fails every *fresh* wallet provisioning, the server included**
  (EMV-9). EMV-6's fix is test-side; the pool-wide derivation above is unchanged, so on a box
  without the Securosys HSM any genuinely new user cannot be provisioned. ▶ The running server
  looks healthy only because `ensure_wallet_for_user` (`src/wallet.rs:430`) returns early for the
  seeded users, who already have wallets — a boot log with **zero** `base-key` lines is not
  evidence that provisioning works.

## [0.4.0] - 2026-08-28

Tracks emvault suite **0.10.0** (Taproot signing/verification + config-auth
security hardening — F1/F4/F2).

### Added
- **Dev-HSM Taproot `SigningCoordinator` gate** (`tests/taproot_hsm_signing_offline.rs`):
  a node-free 2-of-3 `tr(NUMS, multi_a)` federation signed by three real dev
  SoftHSM Schnorr signers, driven through the coordinator to prove the F1 fix at
  runtime — one signature credits exactly one signer and is not complete, two
  reach threshold, and the PSBT finalizes to a real Taproot script-path witness.

## [0.3.0] - 2026-08-21

Tracks emvault suite **0.9.0** (asset-aware Elements migration).

### Added
- **Liquid asset support in the Elements view** — per-asset display, an asset
  selector on the send page, and **Send-Max for assets** (drains the full asset
  balance; the network fee is paid separately in L-BTC).
- **Asset-aware Elements federation migration executor** — per-asset recipients plus
  fee-account assets, so a migration carries L-BTC and every issued asset forward.

### Fixed
- **L-BTC-only balance card + L-BTC-first holdings** — the balance card reflects only
  L-BTC; other assets are read from Holdings by asset.
- Show the correct (successor) federation after a migration.

### Changed
- Consume the full local emvault crate set via `[patch.crates-io]` (inter-crate deps
  are version-only now, so the facade patch no longer cascades). Bumped to
  **emvault 0.9**.

## [0.2.0] - 2026-08-16

Tracks emvault suite **0.8.0** (Bitcoin Taproot).

### Added
- **Taproot vaults.** Federations can be created as `tr(NUMS, multi_a(m, ...))`
  via `APP_SCRIPT_TYPE=taproot`, with a script-type eligibility gate, taproot-aware
  federation reconstruction on load, and a migration `script_type` override. Added
  the `run-tap-e2e.sh` launcher for the mixed-vendor 2-of-3 taproot demo and an
  `APP_SKIP_EAGER_SEED` knob.
- **Multi-vendor HSM fleet.** Vendor-aware HSM configuration with a live
  **Securosys** backend (`tsb` feature), consumed as a direct dependency
  (`emvault-dev-signer` / `emvault-securosys`) rather than through the umbrella,
  plus a multi-vendor federation-migration example.

### Changed
- Bumped the `emvault` suite dependency `0.7 → 0.8` and `emvault-dev-signer`
  `0.7.0 → 0.8.0`; `emvault-securosys` remains at `0.8`.
