# test-app-pkcs11 — Crate Integration Guide

> **How `test-app-pkcs11` consumes the EmVault crates** to build a *custodial,
> HSM-backed, two-chain* (Bitcoin + Liquid/Elements) wallet with **autonomous
> server-side signing**. This is the *reference integration* for
> [`emvault-pkcs11`](https://github.com/gmikeska/emvault-pkcs11) +
> [`emvault-core`](https://github.com/gmikeska/emvault-core) +
> [`emvault-elements`](https://github.com/gmikeska/emvault-elements) (via the
> [`emvault`](https://github.com/gmikeska/emvault) facade), with the dev HSM shim
> from [`emvault-dev-signer`](https://github.com/gmikeska/emvault-dev-signer).
> For each library capability it shows the exact API the app calls and where
> (`src/file.rs::symbol` ↔ `emvault::…::symbol`).
>
> **Scope:** the app↔crate boundary — *not* the UI, routes, templates, auth, or
> DB schema. (Those appear only where they touch a crate.) For run/quick-start
> see [`README.md`](README.md).

---

## 1. The integration contract (and the contrast with `test-app-xpub`)

`test-app-pkcs11` uses the **same** `emvault-core` federation / descriptor / PSBT
machinery as the self-custody [`test-app-xpub`](https://github.com/gmikeska/test-app-xpub),
but with a **different `Signer` backend** — and that contrast is the single most
important thing to understand:

| | `test-app-xpub` | **`test-app-pkcs11`** |
|---|---|---|
| `Signer` backend | `ExternalSigner` (identity only) | **`Pkcs11Signer` (signs in-process)** |
| Where signing happens | the trustee's **browser** | **server-side**, via the HSM |
| Flow | proposal lifecycle (multi round-trip) | one request: **build → sign(m-of-n) → finalize → broadcast** |
| Chains | Bitcoin | **Bitcoin + Liquid/Elements** |

**The lesson: the `Federation` / `SigningCoordinator` / `core::psbt` pipeline is
signer-backend-agnostic.** Because `Pkcs11Signer` implements `core::Signer` *and*
can sign, the same descriptor-building and PSBT-signing code drives an HSM
federation with no special-casing — you register the signers on the BDK wallet and
the coordinator dispatches to them (§5).

| The **crates** own | The **app** owns |
|---|---|
| HSM key derivation/loading/signing (`emvault::pkcs11`) | Token discovery, PIN/label config, the per-customer session cache |
| Descriptor / federation construction (`Federation`, `descriptor`) | Persisting descriptors + federation versions (Postgres) |
| The m-of-n PSBT pipeline (`SigningCoordinator`, `core::psbt`) | Building the spend, broadcasting, persisting txs |
| Chain-sync drivers (`core::chain_sync`) | Owning the `bdk_wallet::Wallet` + `ChangeSet` + RPC |
| The migration **engine** (`core::migration` sweep algorithms) | Discovering accounts, driving the CLI, signing the sweeps |
| Elements wallet + PSET builders + the `sync` **trait contracts + engine** | **Implementing** the storage/chain-source traits; running ingestion |
| Env-parsing helpers (`emvault::config`) | App config (HSM tokens, RPC, networks) |

---

## 2. The crate surface the app touches

| `emvault::…` API | Purpose | App call-site |
|---|---|---|
| `pkcs11::Pkcs11Signer::{load, derive_from_seed}` | Load/derive an HSM-resident BIP-32 master | `hsm.rs::derive_signers` |
| `pkcs11::Pkcs11Session::open`, `pkcs11::config::SlotIdentifier` | Open an authenticated token session by label | `hsm.rs` |
| `pkcs11::NetworkPatchedSigner` | Wrap a signer so descriptors stamp the right network | `hsm.rs`, `wallet.rs` |
| `pkcs11::key_ops::delete_key` | Wipe a signer's on-token objects | `hsm.rs::delete_key_objects` |
| `dev_signer::{init_dev_token, DevBackend}` | Dev-shim token init + HSM backend | `hsm.rs::HsmFleet::new` |
| `core::Federation::with_key_mode` | Build an m-of-n federation from signers | `wallet.rs`, `elements_wallet.rs` |
| `core::descriptor::{to_multipath_string, KeyMode}` | Federation → `wsh(sortedmulti(..))` multipath descriptor | `wallet.rs` |
| `core::psbt::{UnsignedPsbt, SigningCoordinator}` | Drive the m-of-n sign across registered signers | `wallet.rs::build_sign_and_broadcast` |
| `core::psbt::build_spend` | Build the unsigned spend PSBT | `wallet.rs` |
| `core::chain_sync::*` | Build/load + sync the BDK wallet | `wallet.rs` |
| `core::{FederatedWallet, BtcFederatedWallet}` | Track funds across federation versions | `wallet.rs` |
| `core::migration::{SweepAlgorithm, AccountForAccountSweep, AccountForAccountBatchedSweep, MigrationPlan, AccountUtxoSet, SweepOutput}` | The federation-migration sweep engine | `examples/federation_migration.rs` |
| `elements::ElementsWollet` + `CtDescriptorBuilder` | Client-side confidential wallet + CT descriptor | `elements_wallet.rs` |
| `elements::{build_spend_pset, build_sweep_pset, build_migration_pset, finalize_p2wsh_pset}` | PSET construction + P2WSH finalization | `elements_wallet.rs`, migration example |
| `elements::signer::ElementsSigner::sign_pset` | HSM signs a PSET | `elements_wallet.rs` |
| `elements::sync::{BlockStore, WalletUtxoStore, ElementsChainSource, BlockScanEngine}` | The scalable block-scan pipeline (traits + engine) | `elements_sync.rs`, `elements_ingest.rs` |
| `config::{require, optional, hex_encode, ConfigError}` | Env parsing | `config.rs` |

---

## 3. The HSM signer — `emvault::pkcs11` + `emvault::dev_signer`

This is the headline thing the app demonstrates about `emvault-pkcs11`.
`HsmFleet` (`src/hsm.rs`) manages the tokens and produces `Pkcs11Signer`s:

```rust
// dev-shim token init at startup (production: a vendor PKCS#11 .so instead)
dev_signer::init_dev_token(&dev_cfg, &token.label, &token.so_pin, &token.pin)?;

// per-signer: open a session, then load existing keys or derive a fresh master
let session = Pkcs11Session::open(&cfg, &SlotIdentifier::label(&token.label), &token.pin)?;
let signer = match Pkcs11Signer::load(session, label, path, network, Box::new(DevBackend)) {
    Ok(s) => s,                                            // keys already on-token
    Err(Pkcs11Error::ObjectNotFound(_)) =>                 // derive once
        Pkcs11Signer::derive_from_seed(session2, label, &path, network, Box::new(DevBackend), &[])?,
    Err(e) => return Err(e.into()),
};
```

Integration notes:
- **`Pkcs11Signer` is a `core::Signer` that also signs.** That dual nature is why
  it plugs directly into `Federation` + `SigningCoordinator` (§4, §5).
- **`DevBackend`** (`emvault-dev-signer`) is the only dev-vs-prod seam: it instructs
  `cryptoki` which mechanism IDs to send. Production swaps the `.so` + backend; the
  app code is identical (`HsmFleet::new` only varies `PKCS11_LIB`).
- **`NetworkPatchedSigner`** (re-exported from `emvault-pkcs11`) wraps each signer
  so descriptors stamp `BITCOIN_NETWORK` — the app deliberately **bypasses**
  `dev_signer::setup_dev_federation` because that helper hardcodes `Testnet`.
- On-token objects live under the `emvault/v1/{label}/…` namespace
  (`pkcs11::key_ops`); `key_ops::delete_key` wipes them.

---

## 4. Building a federation — `Federation::with_key_mode` + `descriptor`

The app builds the federation from the HSM signers with the lower-level core API
(`build_federation` is the convenience wrapper xpub uses; here we want
`KeyMode::Ranged`):

```rust
let fed = Federation::with_key_mode(
    threshold,
    patched_signers,                 // Vec<NetworkPatchedSigner>
    NetworkType::Bitcoin(network),
    KeyMode::Ranged,
)?;                                  // FederationError on bad inputs
let multipath = to_multipath_string(fed.try_descriptor()?);   // wsh(sortedmulti(..)) two-path
```

`multipath` is the same canonical `wsh(sortedmulti(m, …))` descriptor `test-app-xpub`
gets from `build_federation` — it's the source of truth for the BDK wallet and is
persisted per federation **version** (§6). Liquid uses the parallel
`CtDescriptorBuilder` (§8).

---

## 5. Autonomous m-of-n signing — `core::psbt::SigningCoordinator`

The custodial counterpart to xpub's browser round-trip: the HSM signers are
registered on the BDK wallet and the coordinator drives the whole m-of-n sign
**in one server request** (`UserWallet::build_sign_and_broadcast`):

```rust
let psbt = core_psbt::build_spend(&mut wallet, recipient_spk, amount, fee_rate)?;
let unsigned = UnsignedPsbt::new(psbt)?;
let mut coord = SigningCoordinator::new(&self.federation, unsigned);
coord.request_signatures(&wallet, SignOptions { try_finalize: false, ..SignOptions::default() })?; // ← critical
let finalized = coord.finalize(&wallet, SignOptions::default())?;
let raw = finalized.transaction();  // → sendrawtransaction
```

**Must-not-regress gotcha:** `request_signatures` runs with `try_finalize: false`.
The default BDK `SignOptions` finalize *immediately* after each signer, moving
partial sigs into `final_script_witness` and emptying `partial_sigs` — then
`SigningCoordinator`'s `signers_with_sigs` counts zero and refuses to finalize.
Sign with `try_finalize: false`, finalize as a separate step. (This is the
type-safe `UnsignedPsbt` → `FinalizedPsbt` pipeline doing its job.)

---

## 6. Wallet, chain sync & versioning — `core::chain_sync` + `FederatedWallet`

Same no-persistence model as xpub: the app owns the `bdk_wallet::Wallet` +
`ChangeSet`, the crate provides the drivers (`chain_sync::init_or_load_wallet` /
`emitter_sync`). What's *extra* here is **multi-version** tracking:

- A wallet is reconstructed from its **stored federation versions**, not the live
  `.env` — `WalletManager::build_federated_wallet` builds a
  `BtcFederatedWallet<NetworkPatchedSigner>` spanning every version, matching HSM
  signers to each version's descriptor by fingerprint
  (`reconstruct_federation_from_version`).
- New deposits derive from the **current** federation; balance/history aggregate
  across **all** versions via `core::FederatedWallet` (`find_by_signer`,
  `current`, …), so funds at old (pre-migration) addresses stay spendable.

---

## 7. Federation migration — the `core::migration` sweep engine

Where xpub uses `core::roster` for the arithmetic, the custodial app drives the
full **migration engine** in `emvault-core` (the `examples/federation_migration.rs`
CLI rotates the HSM set across **all** accounts at once):

```rust
let plan: MigrationPlan<_> = AccountForAccountSweep::new(fee_account_idx)
    .plan(&account_utxo_sets /* AccountUtxoSet */, fee_rate)?;     // or AccountForAccountBatchedSweep
for tx in &plan.sweep_transactions {
    for out in &tx.outputs { /* SweepOutput::{Customer, FeeChange} */ }
}
```

The crate computes the sweep transaction shape (`SweepAlgorithm::plan` →
`MigrationPlan` of `SweepOutput`s, `total_fees`, fee-account accounting); the app
provides the per-account UTXOs (`AccountUtxoSet`), signs each sweep with the
index-scoped HSM helper (`UserWallet::sign_migration_inputs` — clears
`bip32_derivation` on inputs an account doesn't own, since all accounts share the
same physical HSM fingerprints), and broadcasts. **Fee-account-pays**, `--dry-run`,
and the Elements parallel are app orchestration on top of the crate's plan.

---

## 8. The second chain — `emvault::elements`

The app's most involved integration: a **client-side** Liquid wallet plus the
**block-scan `sync` pipeline whose traits the app implements**.

**Wallet + signing** (`elements_wallet.rs`):
```rust
let ct_desc = CtDescriptorBuilder::new(threshold, &mbk)?.key_mode(CtKeyMode::Ranged) /* +signers */ .build()?;
let wollet  = ElementsWollet::from_descriptor_str(&desc, mbk, net, lwk)?;     // CT descriptor + SLIP-77 key
let blinded = build_spend_pset(&wollet, &utxos, &recipient, amount, fee_rate)?;
let mut pset = blinded.into_pset();
for signer in &self.signers { signer.sign_pset(&mut pset)?; }                 // ElementsSigner = HSM
finalize_p2wsh_pset(&mut pset)?;                                              // assemble P2WSH witnesses
```
`build_sweep_pset` / `build_migration_pset` are the sweep/migration variants;
`ElementsSigner::sign_pset` is the HSM signing the confidential tx.

**The `sync` traits — bring-your-own storage + chain source** (`elements_sync.rs`).
`emvault-elements` provides the *contracts* and the *engine*; the **app provides the
implementations**:
```rust
impl BlockStore        for PgBlockStore { … }        // Postgres block + cursor store
impl WalletUtxoStore   for PgWalletUtxoStore { … }   // Postgres captured-UTXO store
impl ElementsChainSource for RpcChainSource { … }    // Elements JSON-RPC transport
```
`elements_ingest::spawn` then drives the crate's `BlockScanEngine` over **all**
wallets/versions — fetch each new block once, match against the union of watched
scripts, persist `CapturedUtxo`s — the scalable replacement for per-user daemon
wallets. The crate ships in-memory fakes (`elements::sync::tests`) the app's
Postgres impls are contract-tested against (`pg_stores_honor_contracts`).

---

## 9. Config — `emvault::config`

`AppConfig::from_env` (`config.rs`) reuses the crate's `require` / `optional` /
`hex_encode` / `ConfigError` (deduped with the library crates), then adds the
HSM-specific surface: `PKCS11_LIB`, the discovered `APP_HSM_{N}_*` tokens,
`APP_FED_THRESHOLD` / `APP_FED_SIGNERS`, and the Bitcoin/Elements RPC + network
knobs.

---

## 10. Division of responsibility (cheat sheet)

| Concern | EmVault crate | This app |
|---|---|---|
| Derive/load/sign with HSM keys | `pkcs11::Pkcs11Signer` (+ `dev_signer::DevBackend`) | token config, session cache |
| Build the federation descriptor | `Federation` + `descriptor::to_multipath_string` | persist per version |
| Sign m-of-n in one pass | `core::psbt::SigningCoordinator` (mind `try_finalize:false`) | register signers, broadcast |
| Chain data | `chain_sync::*` | own the `Wallet` + `ChangeSet` + RPC |
| Track versions | `core::FederatedWallet` | reconstruct from stored versions |
| Plan a migration | `core::migration::SweepAlgorithm` | discover accounts, sign, broadcast |
| Liquid wallet + PSET | `elements::{ElementsWollet, build_*_pset, finalize_p2wsh_pset, ElementsSigner}` | orchestrate, persist txs |
| Liquid chain scan | `elements::sync` (traits + `BlockScanEngine`) | **implement** the stores + chain source, run ingestion |
| Persistence / moving funds | *(none — by design)* | Postgres + broadcast |

---

## 11. Integration entry points

| I want to… | App call-site → crate symbol |
|---|---|
| Add/parameterize HSM signers | `hsm.rs::derive_signers` → `Pkcs11Signer::{load, derive_from_seed}` |
| Build a federation | `wallet.rs` → `Federation::with_key_mode` + `to_multipath_string` |
| Change the signing pass | `UserWallet::build_sign_and_broadcast` → `SigningCoordinator` (keep `try_finalize:false`) |
| Touch chain sync / versions | `wallet.rs` → `chain_sync::*`, `BtcFederatedWallet` |
| Change migration strategy | `examples/federation_migration.rs` → `core::migration::SweepAlgorithm` |
| Add a Liquid feature | `elements_wallet.rs` → `elements::{build_*_pset, ElementsSigner, finalize_p2wsh_pset}` |
| Change Liquid storage/scan | `elements_sync.rs` impls → `elements::sync::{BlockStore, WalletUtxoStore, ElementsChainSource}` |
| Parse a new env var | `AppConfig::from_env` → `emvault::config::{require, optional}` |

---

## 12. Relationship to the rest of EmVault

- Library crates: [`emvault-pkcs11`](https://github.com/gmikeska/emvault-pkcs11)
  (`Pkcs11Signer`, `NetworkPatchedSigner`, `key_ops`),
  [`emvault-core`](https://github.com/gmikeska/emvault-core)
  (`Federation`, `SigningCoordinator`, `core::psbt`, `chain_sync`,
  `FederatedWallet`, `migration`),
  [`emvault-elements`](https://github.com/gmikeska/emvault-elements)
  (`ElementsWollet`, PSET builders, `sync`), and the dev shim
  [`emvault-dev-signer`](https://github.com/gmikeska/emvault-dev-signer)
  (`DevBackend`) + `libemvault_dev_hsm`. All via the
  [`emvault`](https://github.com/gmikeska/emvault) facade (features
  `pkcs11, elements, dev-signer`).
- Contrasting integration — **browser-mediated** signing with consumer hardware
  wallets (`ExternalSigner`, proposal lifecycle):
  [`test-app-xpub`](https://github.com/gmikeska/test-app-xpub) and its
  `FEATURES.md`. Same `emvault-core` descriptor/PSBT primitives, a different
  `Signer` backend — the whole point.
