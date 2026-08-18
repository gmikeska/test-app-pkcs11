# Changelog

All notable changes to `test-app-pkcs11` (the PKCS#11 / HSM reference app) are
documented here. This is the app's first CHANGELOG; the `0.2.0` entry summarizes
the current cycle (which tracks the emvault suite **0.8.0** / Bitcoin Taproot
release). Earlier history lives in git.

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
