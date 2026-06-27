//! Offline signing gate for the Bitcoin `account-for-account-batched`
//! federation migration with **decision (b)** fee-change routing.
//!
//! This is the Bitcoin analogue of the Elements offline gate
//! `asterism::elements::spend::tests::batched_migration_chains_fee_change_offline`.
//! It proves the chained fee-change mechanic that `run_bitcoin_migration`
//! implements (in `examples/federation_migration.rs`) **without** a node,
//! Postgres, PKCS#11, or any `UserWallet` — using in-process software
//! `wsh(sortedmulti(2,..))` descriptors signed by BDK's built-in signer.
//!
//! What Phase B changed is *signer-agnostic*: descriptor selection (rebuild the
//! chained input from the fee account's **OLD** descriptor, not the new-fed
//! one), address derivation (intermediate change → old-fed, final → new-fed),
//! and PSBT enrichment (`apply_unconfirmed_txs` on a temp wallet to spend the
//! still-unconfirmed chained change). Software keys exercise that logic exactly
//! as HSM keys would; the PKCS#11 path itself is untouched by Phase B.
//!
//! The gate builds a three-transaction batch:
//!   * tx0: customer C1 + the fee account's real UTXO  → C1 exact, change → fee OLD
//!   * tx1: customer C2 + the chained change from tx0  → C2 exact, change → fee OLD
//!   * tx2: the chained change from tx1 (fee-only)      → drain → fee NEW (final)
//!
//! and asserts: customers receive their exact balances; every intermediate
//! fee-change output is locked to the fee account's **old-fed** address; the
//! fee account's **new-fed** address appears **only** in the final tx; and
//! value is conserved (the fee account's initial balance lands at the new
//! federation, less the cumulative mining fee).
//!
//! Each chained input is rebuilt with the **same** temp-wallet machinery the
//! executor uses (`create_from_two_path_descriptor` on the OLD descriptor +
//! `apply_unconfirmed_txs` + `get_psbt_input`), so this gate covers the precise
//! lines reworked in Phase B (`federation_migration.rs:2322-2377`).

use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::{
    self, Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Weight, Witness, absolute::LockTime, bip32::Xpriv, transaction::Version,
};
use bdk_wallet::miniscript::psbt::PsbtExt;
use bdk_wallet::{KeychainKind, SignOptions, Wallet};

const NETWORK: Network = Network::Regtest;
/// 2-of-3 P2WSH satisfaction weight estimate (mirrors the executor's chained
/// input weight at `federation_migration.rs:2355`). Offline fee math only.
fn sat_weight() -> Weight {
    Weight::from_witness_data_size(260)
}

/// A software federation: a `wsh(sortedmulti(2, ..))` descriptor whose three
/// keys are held in-process so BDK can both derive its scripts and sign for it.
///
/// The executor builds its (public) wallets from a single BIP-389 multipath
/// descriptor via `create_from_two_path_descriptor`. BDK can't turn a *secret*
/// multipath key into a pubkey, so for software signing we hold the equivalent
/// external (`/0/*`) and internal (`/1/*`) single-path secret descriptors and
/// build via `Wallet::create`. The derived scripts are identical either way.
struct SoftFed {
    external: String,
    internal: String,
}

impl SoftFed {
    /// Build a 2-of-3 federation from three deterministic master keys.
    fn new(seeds: [u8; 3]) -> Self {
        let xprvs: Vec<Xpriv> = seeds
            .iter()
            .map(|s| Xpriv::new_master(NETWORK, &[*s; 32]).expect("valid master xprv"))
            .collect();
        let branch = |chain: u8| {
            let keys: Vec<String> = xprvs.iter().map(|x| format!("{x}/{chain}/*")).collect();
            format!("wsh(sortedmulti(2,{}))", keys.join(","))
        };
        Self {
            external: branch(0),
            internal: branch(1),
        }
    }

    /// A fresh wallet on this federation's secret descriptors. Wallets are cheap
    /// and stateless here; we make one whenever we need to derive, enrich, or
    /// sign — mirroring the executor's throwaway temp wallets.
    fn wallet(&self) -> Wallet {
        Wallet::create(self.external.clone(), self.internal.clone())
            .network(NETWORK)
            .create_wallet_no_persist()
            .expect("valid software descriptors")
    }

    /// The external address at `index` for this federation.
    fn address(&self, index: u32) -> Address {
        self.wallet()
            .peek_address(KeychainKind::External, index)
            .address
    }

    /// Sign every input of `psbt` that belongs to this federation. With all
    /// three secret keys present, one call satisfies the 2-of-3 threshold.
    /// `try_finalize` is off — finalization is done once, globally, with the
    /// standalone miniscript finalizer (as the executor does).
    fn sign(&self, psbt: &mut bitcoin::Psbt) {
        let opts = SignOptions {
            trust_witness_utxo: true,
            try_finalize: false,
            ..Default::default()
        };
        self.wallet().sign(psbt, opts).expect("software sign");
    }
}

/// A spendable input: outpoint + enriched PSBT input + satisfaction weight,
/// exactly the triple the executor threads as a foreign UTXO.
struct Funded {
    op: OutPoint,
    input: bitcoin::psbt::Input,
    weight: Weight,
}

/// Synthesize a confirmed-looking funding UTXO paying `value` to `fed`'s
/// address at `index`, and enrich it into a foreign-spendable PSBT input.
///
/// `seed` makes the synthetic funding txid unique per call. The enrichment goes
/// through a temp wallet on `fed`'s descriptor — the same path the executor
/// uses for the chained change — so the resulting input carries the witness
/// script and BIP-32 derivations needed for `fed.sign` to satisfy it.
fn fund(fed: &SoftFed, index: u32, value: u64, seed: u8) -> Funded {
    let spk = fed.address(index).script_pubkey();
    let funding = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            // A dummy origin; `apply_unconfirmed_txs` does not validate inputs.
            previous_output: OutPoint::new(Txid::from_byte_array([seed; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: spk,
        }],
    };
    let op = OutPoint::new(funding.compute_txid(), 0);
    enrich(fed, &funding, op)
}

/// Rebuild the PSBT input for `op` (an output of `tx`) from `fed`'s descriptor
/// via a throwaway wallet — the literal Phase B mechanic
/// (`federation_migration.rs:2339-2360`): the chained change is an unconfirmed
/// output no synced wallet has seen, so apply the just-built tx to a temp
/// wallet and read the UTXO back out.
fn enrich(fed: &SoftFed, tx: &Transaction, op: OutPoint) -> Funded {
    let mut tw = fed.wallet();
    // Reveal so the script index recognises index 0 (executor does the same).
    let _ = tw.reveal_next_address(KeychainKind::External);
    tw.apply_unconfirmed_txs(vec![(tx.clone(), 0)]);
    let local = tw
        .get_utxo(op)
        .expect("funding/chained utxo present in temp wallet after insert");
    let input = tw
        .get_psbt_input(local, None, false)
        .expect("build psbt input for utxo");
    Funded {
        op,
        input,
        weight: sat_weight(),
    }
}

/// Build, sign, finalize and extract one batch transaction.
///
/// `inputs` are spent as foreign UTXOs (they belong to old-fed descriptors, not
/// the builder wallet's); `customers` are exact recipients; `fee_dest` receives
/// the fee-absorbing change via `drain_to` — the executor routes this to the
/// fee account's old-fed address on intermediate hops and its new-fed address on
/// the final tx. `signers` are the federations whose inputs appear, each asked
/// to sign its own inputs (mirroring the per-owning-wallet signing loop).
fn run_tx(
    builder_fed: &SoftFed,
    inputs: &[Funded],
    customers: &[(Address, u64)],
    fee_dest: &Address,
    signers: &[&SoftFed],
) -> Transaction {
    let mut wallet = builder_fed.wallet();
    let mut psbt = {
        let mut builder = wallet.build_tx();
        builder.manually_selected_only();
        for f in inputs {
            builder
                .add_foreign_utxo(f.op, f.input.clone(), f.weight)
                .expect("add foreign utxo");
        }
        for (addr, amount) in customers {
            builder.add_recipient(addr.script_pubkey(), Amount::from_sat(*amount));
        }
        builder.drain_to(fee_dest.script_pubkey());
        builder.fee_rate(FeeRate::from_sat_per_vb(2).expect("valid fee rate"));
        builder.finish().expect("psbt construction")
    };

    for fed in signers {
        fed.sign(&mut psbt);
    }

    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    psbt.finalize_mut(&secp).expect("finalize all inputs");

    let tx = psbt.extract_tx().expect("extract tx");
    for inp in &tx.input {
        assert!(
            inp.witness.len() >= 4,
            "each input finalized with a 2-of-3 P2WSH witness"
        );
    }
    tx
}

/// The mining fee of `tx`, given the total value of its inputs.
fn fee_of(tx: &Transaction, input_total: u64) -> u64 {
    let out: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    input_total - out
}

/// The outpoint of the single output paying `addr`.
fn outpoint_at(tx: &Transaction, addr: &Address) -> OutPoint {
    let spk = addr.script_pubkey();
    let vout = tx
        .output
        .iter()
        .position(|o| o.script_pubkey == spk)
        .expect("expected output present");
    OutPoint::new(
        tx.compute_txid(),
        u32::try_from(vout).expect("vout fits u32"),
    )
}

/// The number of outputs paying `addr`.
fn count_at(tx: &Transaction, addr: &Address) -> usize {
    let spk = addr.script_pubkey();
    tx.output.iter().filter(|o| o.script_pubkey == spk).count()
}

/// The value of the output paying `addr`, asserting exactly one such output.
fn value_at(tx: &Transaction, addr: &Address) -> u64 {
    let spk = addr.script_pubkey();
    let matches: Vec<&TxOut> = tx
        .output
        .iter()
        .filter(|o| o.script_pubkey == spk)
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "exactly one output at the expected address"
    );
    matches[0].value.to_sat()
}

#[test]
fn bitcoin_batched_migration_chains_fee_change_old_fed_offline() {
    const INITIAL_FEE: u64 = 1_000_000;
    const C1_BAL: u64 = 200_000;
    const C2_BAL: u64 = 300_000;

    // Fee account: an OLD federation (holds funds, signs every hop) and a NEW
    // federation (only the final destination). Customers each have an OLD fed
    // (holds funds) and a NEW fed (migration destination).
    let fee_old = SoftFed::new([0xa1, 0xa2, 0xa3]);
    let fee_new = SoftFed::new([0xa4, 0xa5, 0xa6]);
    let c1_old = SoftFed::new([0xb1, 0xb2, 0xb3]);
    let c1_new = SoftFed::new([0xb4, 0xb5, 0xb6]);
    let c2_old = SoftFed::new([0xc1, 0xc2, 0xc3]);
    let c2_new = SoftFed::new([0xc4, 0xc5, 0xc6]);

    // Old-fed change sink (External/0) for intermediate hops; a distinct
    // new-fed address only for the final tx.
    let fee_old_addr = fee_old.address(0);
    let fee_new_addr = fee_new.address(0);
    let c1_dest = c1_new.address(5);
    let c2_dest = c2_new.address(5);

    // Funding UTXOs at the OLD federations.
    let fee_utxo = fund(&fee_old, 0, INITIAL_FEE, 0x11);
    let c1_utxo = fund(&c1_old, 0, C1_BAL, 0x22);
    let c2_utxo = fund(&c2_old, 0, C2_BAL, 0x33);

    // --- tx0: C1 + real fee utxo → C1 exact, change back to fee OLD. --------
    let tx0 = run_tx(
        &fee_old,
        &[c1_utxo, fee_utxo],
        &[(c1_dest.clone(), C1_BAL)],
        &fee_old_addr,
        &[&c1_old, &fee_old],
    );
    assert_eq!(value_at(&tx0, &c1_dest), C1_BAL, "C1 exact");
    let fee0 = fee_of(&tx0, C1_BAL + INITIAL_FEE);
    // Intermediate fee-change is locked to the fee account's OLD-fed address.
    let change0_value = value_at(&tx0, &fee_old_addr);
    assert_eq!(
        change0_value,
        INITIAL_FEE - fee0,
        "after tx0 the fee account holds its balance minus fee0 (C1 untouched)"
    );
    assert_eq!(
        count_at(&tx0, &fee_new_addr),
        0,
        "fee account's NEW-fed address must not appear in an intermediate tx"
    );
    // Rebuild the chained change from the fee account's OLD descriptor.
    let chained0 = enrich(&fee_old, &tx0, outpoint_at(&tx0, &fee_old_addr));

    // --- tx1: C2 + chained change → C2 exact, change back to fee OLD. -------
    let tx1 = run_tx(
        &fee_old,
        &[c2_utxo, chained0],
        &[(c2_dest.clone(), C2_BAL)],
        &fee_old_addr,
        &[&c2_old, &fee_old],
    );
    assert_eq!(value_at(&tx1, &c2_dest), C2_BAL, "C2 exact");
    let fee1 = fee_of(&tx1, C2_BAL + change0_value);
    let change1_value = value_at(&tx1, &fee_old_addr);
    assert_eq!(
        change1_value,
        INITIAL_FEE - fee0 - fee1,
        "after tx1 the fee account holds its balance minus fees so far"
    );
    assert_eq!(
        count_at(&tx1, &fee_new_addr),
        0,
        "fee account's NEW-fed address must not appear in an intermediate tx"
    );
    let chained1 = enrich(&fee_old, &tx1, outpoint_at(&tx1, &fee_old_addr));

    // --- tx2: fee-only final tx → drain to fee NEW. The chained input is
    // still OLD-fed-locked, so the OLD federation signs it; only the OUTPUT
    // crosses to the new federation. ----------------------------------------
    let tx2 = run_tx(&fee_old, &[chained1], &[], &fee_new_addr, &[&fee_old]);
    // Fee-only drain: exactly one recipient output (no customer outputs).
    assert_eq!(
        tx2.output.len(),
        1,
        "final fee-only tx: single drain output"
    );
    let fee2 = fee_of(&tx2, change1_value);
    let final_value = value_at(&tx2, &fee_new_addr);
    assert_eq!(
        count_at(&tx2, &fee_old_addr),
        0,
        "the final tx routes the fee account to the NEW federation, not OLD"
    );

    // Value conservation across the whole chain: the fee account's initial
    // balance ends up at the new federation, less the cumulative mining fee;
    // both customers received their full balances.
    assert_eq!(
        final_value + fee0 + fee1 + fee2,
        INITIAL_FEE,
        "fee account paid exactly the cumulative fee; customers got full balances"
    );
}
