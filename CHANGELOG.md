# Changelog

All notable changes to `test-app-pkcs11` (the PKCS#11 / HSM reference app) are
documented here. This is the app's first CHANGELOG; the `0.2.0` entry summarizes
the current cycle (which tracks the emvault suite **0.8.0** / Bitcoin Taproot
release). Earlier history lives in git.

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
