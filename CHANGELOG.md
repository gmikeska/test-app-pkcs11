# Changelog

All notable changes to `test-app-pkcs11` (the PKCS#11 / HSM reference app) are
documented here. This is the app's first CHANGELOG; the `0.2.0` entry summarizes
the current cycle (which tracks the emvault suite **0.8.0** / Bitcoin Taproot
release). Earlier history lives in git.

## [0.12.0] - 2026-11-24

Tracks emvault suite **0.12.0** (the `Pkcs11Signer::sign_sighash` seam; suite 0.11.0 is
yanked). Version aligned to the suite number rather than continuing the app's own 0.x line.

### Fixed
- **Account indices were recycled after a wallet was deleted, so two users could share one
  on-chain wallet** (EMV-8; `src/db.rs`, migration `0010_monotonic_account_index.sql`).
  `next_account_idx` and `next_elements_account_idx` were
  `SELECT COALESCE(MAX(account_idx) + 1, 0)` over the live table — a high-water mark of
  **surviving** rows, not an allocator. Deleting a wallet freed its index, and the next user
  provisioned derived `m/48'/{coin}'/{account_idx}'/2'` to the *same* HSM keys, the same
  `wsh(sortedmulti(..))` descriptor and the same addresses: able to spend whatever was still
  sitting there, and to silently receive any later deposit meant for the previous holder.
  ▶ **`UNIQUE (account_idx)` never fired and never could** — it constrains rows that *exist*, and
  the violated invariant is over rows that **ever existed**; deleting before re-inserting slips
  past it without the constraint being consulted. Measured: two users, two wallet rows,
  `account_idx=110` both times, byte-identical descriptor and address, one shared wallet.
  Both allocators are now Postgres sequences — `nextval` is monotonic, survives deletes, and is
  not rolled back by a failed transaction, so reuse is unrepresentable rather than unlikely. The
  migration seeds each sequence above its table's maximum **plus a margin**, because indices held
  by already-deleted rows cannot be recovered from the surviving table. Two new tests pin the
  invariant per chain (allocate → delete via user CASCADE → allocate → assert differs); both
  failed before the change, at index 111 and 1462310.
  ▶ On Elements the consequence was slightly worse: `daemon_wallet_name` is
  `format!("elements-user-{account_idx}")` and `UNIQUE`, so a reused index also reused a
  user-visible label — and that constraint is defeated by the same ordering. Two guards, neither
  able to see the violation.
- **A failed migration made database tests report success** (`src/db.rs`). The copied `test_pool`
  idiom ended every fallible step with `.ok()?`, so a broken migration returned `None`, the test
  printed "no DATABASE_URL" and reported **ok**. That path produced a green run for the two new
  allocator tests while migration `0010` was in fact failing. Absent database still skips; present
  but unmigratable now panics with the migration error.
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
- **`elements_sync::tests::pg_stores_honor_contracts` is not hermetic** (EMV-7). It shares the
  `asterism_pkcs11` database rather than taking an isolated one, and has both passed and failed on
  this build — the deciding factor is database residue, not code. It passes in the run recorded
  above.
- **One unreachable vendor token fails every *fresh* wallet provisioning, the server included**
  (EMV-9). `HsmFleet::signers_for` derives across the whole token pool before
  `fed_signer_indices` narrows to the federation, so on a box without the Securosys HSM a
  genuinely new user cannot be provisioned. ▶ The running server looks healthy only because
  `ensure_wallet_for_user` (`src/wallet.rs:430`) returns early for the seeded users, who already
  have wallets — a boot log with **zero** `base-key` lines is not evidence that provisioning works.
- **`UNIQUE (descriptor)` is not yet enforced** (EMV-11). Drafted in migration `0010` and removed:
  it fails with `Key (descriptor)=(desc) is duplicated` because `elements_sync`'s `seed_wallet`
  fixture inserts the literal `descriptor = 'desc'` for every row and those accumulate in the
  shared database. ▶ It would not have caught EMV-8 — a live-rows guard cannot see
  delete-then-insert — but it does catch an identical signer set assembling one descriptor
  (GroupVault F13 proper). Blocked on the fixtures using distinct descriptors and the existing
  duplicates being resolved; the new allocator tests already use distinct ones.

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
