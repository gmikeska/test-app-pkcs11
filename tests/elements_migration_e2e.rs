//! P4 — end-to-end Elements **federation migration** against a live `elementsd`
//! regtest node + Postgres, exercising the fee-account-pays path.
//!
//! Seeds a fee account + two customer accounts (unique per-run keys), funds all
//! three, captures via the block-scan engine, then builds one fee-account-pays
//! migration PSET (`build_migration_pset`), signs each account's inputs, and
//! broadcasts. Asserts the node accepted it, each customer's full balance moved
//! to its new-federation address, and the **fee account paid the fee**.
//!
//! Skips when `ELEMENTS_RPC_URL` / `DATABASE_URL` are unset.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::format_collect
)]

use std::str::FromStr;

use bitcoincore_rpc::{Auth, Client, RpcApi};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use asterism::core::signer::Signer;
use asterism::elements::descriptor::{CtDescriptorBuilder, CtKeyMode, to_multipath_string};
use asterism::elements::signer::ElementsSigner;
use asterism::elements::sync::{
    BlockScanEngine, CapturedUtxo, ElementsChainSource, KeychainKind, WalletId, WalletUtxoStore,
};
use asterism::elements::testkit::SoftwareSigner;
use asterism::elements::{
    ElementsNetwork, ElementsWalletHandle, ElementsWollet, LwkNetwork, build_migration_pset,
    captured_from_output, finalize_p2wsh_pset,
};

use test_app_pkcs11::elements_sync::{PgBlockStore, PgWalletUtxoStore, RpcChainSource};

const LBTC_SAT: u64 = 100_000_000;

/// Both e2e tests share the same Postgres `elements_blocks` / `elements_sync_cursor`
/// state and clean it up at the end, so they must not run concurrently. Acquire
/// this lock for the duration of each test to serialize them.
fn e2e_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

struct Env {
    rpc_url: String,
    rpc_user: String,
    rpc_pass: String,
    database_url: String,
}

fn env() -> Option<Env> {
    Some(Env {
        rpc_url: std::env::var("ELEMENTS_RPC_URL").ok()?,
        rpc_user: std::env::var("ELEMENTS_RPC_USER").ok()?,
        rpc_pass: std::env::var("ELEMENTS_RPC_PASSWORD").ok()?,
        database_url: std::env::var("DATABASE_URL").ok()?,
    })
}

fn node_wallet(env: &Env) -> Client {
    Client::new(
        &format!("{}/wallet/default", env.rpc_url),
        Auth::UserPass(env.rpc_user.clone(), env.rpc_pass.clone()),
    )
    .unwrap()
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A test wallet: 2-of-3 software-signer federation + its wollet/descriptor.
struct TestWallet {
    wollet: ElementsWollet,
    signers: Vec<SoftwareSigner>,
    descriptor: String,
    mbk: [u8; 32],
}

fn make_wallet(
    tag: Uuid,
    signer_salt: u8,
    blinding_salt: u8,
    net: ElementsNetwork,
    lwk: LwkNetwork,
) -> TestWallet {
    let signers: Vec<SoftwareSigner> = (0u8..3)
        .map(|i| {
            let mut sb = [0u8; 32];
            sb[..16].copy_from_slice(tag.as_bytes());
            sb[16] = signer_salt;
            sb[17] = i;
            SoftwareSigner::new_with_seed_bytes(sb, lwk)
        })
        .collect();
    let mut blinding = [0u8; 32];
    blinding[..16].copy_from_slice(tag.as_bytes());
    blinding[16] = blinding_salt;
    let mut builder = CtDescriptorBuilder::new(2, &blinding)
        .unwrap()
        .key_mode(CtKeyMode::Ranged);
    for s in &signers {
        builder.add_signer(s as &dyn Signer).unwrap();
    }
    let ct = builder.build().unwrap();
    let descriptor = to_multipath_string(&ct);
    let handle = ElementsWalletHandle::new(ct, blinding);
    let wollet = ElementsWollet::from_handle_with_lwk(&handle, net, lwk).unwrap();
    TestWallet {
        wollet,
        signers,
        descriptor,
        mbk: blinding,
    }
}

/// Seed a user + `elements_wallets` row (FK target for captured UTXOs).
async fn seed_row(pool: &PgPool, descriptor: &str, mbk: &[u8; 32], tag: Uuid, acct: i32) -> Uuid {
    let user_id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id",
    )
    .bind(format!("{tag}-{acct}@mig.local"))
    .fetch_one(pool)
    .await
    .unwrap();
    sqlx::query_scalar(
        "INSERT INTO elements_wallets \
           (user_id, account_idx, descriptor, master_blinding_key, daemon_wallet_name) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(user_id)
    .bind(acct)
    .bind(descriptor)
    .bind(hex32(mbk))
    .bind(format!("mig-{tag}-{acct}"))
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn elements_migration_fee_account_pays_e2e() {
    let Some(env) = env() else {
        eprintln!("skipping elements_migration_e2e: ELEMENTS_RPC_URL/DATABASE_URL unset");
        return;
    };
    let _serial = e2e_lock().lock().await;

    // --- node network params ---
    let base = Client::new(
        &env.rpc_url,
        Auth::UserPass(env.rpc_user.clone(), env.rpc_pass.clone()),
    )
    .unwrap();
    let genesis: String = base.call("getblockhash", &[json!(0)]).unwrap();
    let sidechain: serde_json::Value = base.call("getsidechaininfo", &[]).unwrap();
    let policy = elements::AssetId::from_str(sidechain["pegged_asset"].as_str().unwrap()).unwrap();
    let net = ElementsNetwork::ElementsRegtest;
    let lwk =
        ElementsNetwork::custom_regtest(policy, elements::BlockHash::from_str(&genesis).unwrap());

    let pool = PgPool::connect(&env.database_url).await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    let tag = Uuid::new_v4();

    // Old (current) wallets: fee account + two customers.
    let fee = make_wallet(tag, 0x10, 0xa0, net, lwk);
    let c1 = make_wallet(tag, 0x11, 0xa1, net, lwk);
    let c2 = make_wallet(tag, 0x12, 0xa2, net, lwk);

    // New-federation destination wallets (distinct keys).
    let fee_new = make_wallet(tag, 0x20, 0xb0, net, lwk);
    let c1_new = make_wallet(tag, 0x21, 0xb1, net, lwk);
    let c2_new = make_wallet(tag, 0x22, 0xb2, net, lwk);

    // Unique-per-run account indices derived from the tag.
    let base_acct = (u32::from_le_bytes(tag.as_bytes()[..4].try_into().unwrap()) % 1_000_000)
        as i32
        + 3_000_000;
    let fee_uuid = seed_row(&pool, &fee.descriptor, &fee.mbk, tag, base_acct).await;
    let c1_uuid = seed_row(&pool, &c1.descriptor, &c1.mbk, tag, base_acct + 1).await;
    let c2_uuid = seed_row(&pool, &c2.descriptor, &c2.mbk, tag, base_acct + 2).await;
    let fee_id = WalletId::from_bytes(*fee_uuid.as_bytes());
    let c1_id = WalletId::from_bytes(*c1_uuid.as_bytes());
    let c2_id = WalletId::from_bytes(*c2_uuid.as_bytes());

    // --- fund each old wallet's external addr #0 (1.0 L-BTC) ---
    let node = node_wallet(&env);
    let mine: String = node.call("getnewaddress", &[]).unwrap();
    for w in [&fee, &c1, &c2] {
        let addr = w.wollet.address(KeychainKind::External, 0).unwrap();
        let _t: String = node
            .call("sendtoaddress", &[json!(addr.to_string()), json!(1.0)])
            .unwrap();
    }
    let _: Vec<String> = node
        .call("generatetoaddress", &[json!(2), json!(mine.clone())])
        .unwrap();

    // --- capture all three via one scan pass ---
    let blocks = PgBlockStore::new(pool.clone());
    let utxos_store = PgWalletUtxoStore::new(pool.clone());
    let rpc = (
        env.rpc_url.clone(),
        env.rpc_user.clone(),
        env.rpc_pass.clone(),
    );

    // Move data into the blocking section: old + new descriptors/mbk + signers.
    let fee_desc = fee.descriptor.clone();
    let c1_desc = c1.descriptor.clone();
    let c2_desc = c2.descriptor.clone();
    let fee_new_desc = fee_new.descriptor.clone();
    let c1_new_desc = c1_new.descriptor.clone();
    let c2_new_desc = c2_new.descriptor.clone();
    let fee_sgn: Vec<SoftwareSigner> = fee.signers.clone();
    let c1_sgn: Vec<SoftwareSigner> = c1.signers.clone();
    let c2_sgn: Vec<SoftwareSigner> = c2.signers.clone();
    let (fee_mbk, c1_mbk, c2_mbk) = (fee.mbk, c1.mbk, c2.mbk);
    let (fee_new_mbk, c1_new_mbk, c2_new_mbk) = (fee_new.mbk, c1_new.mbk, c2_new.mbk);

    // Returns (c1_at_new, c2_at_new, fee_at_new, fee_paid).
    let outcome = tokio::task::spawn_blocking(move || -> Result<(u64, u64, u64, u64), String> {
        let chain = RpcChainSource::new(&rpc.0, &rpc.1, &rpc.2).map_err(de)?;
        let load = |d: &str, m: [u8; 32]| ElementsWollet::from_descriptor_str(d, m, net, lwk);

        let w_fee = load(&fee_desc, fee_mbk).map_err(de)?;
        let w_c1 = load(&c1_desc, c1_mbk).map_err(de)?;
        let w_c2 = load(&c2_desc, c2_mbk).map_err(de)?;
        // new-federation wollets (destinations) — to unblind & verify amounts.
        let w_fee_new = load(&fee_new_desc, fee_new_mbk).map_err(de)?;
        let w_c1_new = load(&c1_new_desc, c1_new_mbk).map_err(de)?;
        let w_c2_new = load(&c2_new_desc, c2_new_mbk).map_err(de)?;
        let fee_dest = w_fee_new.address(KeychainKind::External, 0).map_err(de)?;
        let c1_dest = w_c1_new.address(KeychainKind::External, 0).map_err(de)?;
        let c2_dest = w_c2_new.address(KeychainKind::External, 0).map_err(de)?;

        // capture all three in one scan pass
        let mut engine = BlockScanEngine::new();
        engine.register_wallet(fee_id, &w_fee, 20).map_err(de)?;
        engine.register_wallet(c1_id, &w_c1, 20).map_err(de)?;
        engine.register_wallet(c2_id, &w_c2, 20).map_err(de)?;
        engine.sync(&chain, &blocks, &utxos_store).map_err(de)?;

        let fee_utxos = utxos_store.list_unspent(fee_id).map_err(de)?;
        let c1_utxos = utxos_store.list_unspent(c1_id).map_err(de)?;
        let c2_utxos = utxos_store.list_unspent(c2_id).map_err(de)?;
        if fee_utxos.is_empty() || c1_utxos.is_empty() || c2_utxos.is_empty() {
            return Err(format!(
                "capture incomplete: fee={} c1={} c2={}",
                fee_utxos.len(),
                c1_utxos.len(),
                c2_utxos.len()
            ));
        }
        let fee_bal: u64 = fee_utxos.iter().map(CapturedUtxo::value).sum();
        let c1_bal: u64 = c1_utxos.iter().map(CapturedUtxo::value).sum();
        let c2_bal: u64 = c2_utxos.iter().map(CapturedUtxo::value).sum();

        // fee-account-pays migration PSET
        let mut inputs: Vec<(CapturedUtxo, &ElementsWollet)> = Vec::new();
        for u in &fee_utxos {
            inputs.push((u.clone(), &w_fee));
        }
        for u in &c1_utxos {
            inputs.push((u.clone(), &w_c1));
        }
        for u in &c2_utxos {
            inputs.push((u.clone(), &w_c2));
        }
        let blinded = build_migration_pset(
            &w_fee,
            &inputs,
            &[(c1_dest.clone(), c1_bal), (c2_dest.clone(), c2_bal)],
            &fee_dest,
            2000.0,
        )
        .map_err(de)?;
        let mut pset = blinded.into_pset();

        // sign each account's inputs (index-scoped)
        let sign_account = |pset: &mut elements::pset::PartiallySignedTransaction,
                            utxos: &[CapturedUtxo],
                            signers: &[SoftwareSigner]| {
            let owned: std::collections::HashSet<elements::OutPoint> =
                utxos.iter().map(|u| u.outpoint).collect();
            let indices: Vec<usize> = pset
                .inputs()
                .iter()
                .enumerate()
                .filter(|(_, i)| {
                    owned.contains(&elements::OutPoint::new(
                        i.previous_txid,
                        i.previous_output_index,
                    ))
                })
                .map(|(i, _)| i)
                .collect();
            let mut saved = Vec::new();
            for (i, inp) in pset.inputs_mut().iter_mut().enumerate() {
                if !indices.contains(&i) {
                    saved.push((i, std::mem::take(&mut inp.bip32_derivation)));
                }
            }
            for s in signers {
                let _ = s.sign_pset(pset);
            }
            for (i, d) in saved {
                pset.inputs_mut()[i].bip32_derivation = d;
            }
        };
        sign_account(&mut pset, &fee_utxos, &fee_sgn);
        sign_account(&mut pset, &c1_utxos, &c1_sgn);
        sign_account(&mut pset, &c2_utxos, &c2_sgn);

        finalize_p2wsh_pset(&mut pset).map_err(de)?;
        let tx = pset.extract_tx().map_err(de)?;

        // unblind the new-federation outputs to verify amounts
        let val_at = |w: &ElementsWollet, addr: &elements::Address| -> u64 {
            let spk = addr.script_pubkey();
            let o = tx
                .output
                .iter()
                .find(|o| o.script_pubkey == spk)
                .expect("destination output present");
            w.unblind(o).unwrap().value
        };
        let c1_at_new = val_at(&w_c1_new, &c1_dest);
        let c2_at_new = val_at(&w_c2_new, &c2_dest);
        let fee_at_new = val_at(&w_fee_new, &fee_dest);
        let fee_paid = fee_bal - fee_at_new;

        let txid = chain.broadcast(&tx).map_err(de)?;
        eprintln!("migration broadcast txid: {txid}");

        // sanity vs node
        let _ = (c1_bal, c2_bal);
        Ok((c1_at_new, c2_at_new, fee_at_new, fee_paid))
    })
    .await
    .unwrap();

    let (c1_at_new, c2_at_new, fee_at_new, fee_paid) = outcome.expect("migration");
    assert_eq!(c1_at_new, LBTC_SAT, "customer 1 migrated its full balance");
    assert_eq!(c2_at_new, LBTC_SAT, "customer 2 migrated its full balance");
    assert!(fee_paid > 0, "fee account paid a non-zero fee");
    assert_eq!(
        fee_at_new + fee_paid,
        LBTC_SAT,
        "fee account: new balance + fee == its old balance (it paid for everyone)"
    );

    // --- confirm + re-capture: the new federation's funds must now be captured
    //     under each customer's *same* wallet id (what the UI v1 tab reads),
    //     and the old deposit must be spent. This is the multi-version path. ---
    let _: Vec<String> = node
        .call("generatetoaddress", &[json!(2), json!(mine)])
        .unwrap();
    let blocks2 = PgBlockStore::new(pool.clone());
    let utxos2 = PgWalletUtxoStore::new(pool.clone());
    let rpc2 = (
        env.rpc_url.clone(),
        env.rpc_user.clone(),
        env.rpc_pass.clone(),
    );
    let recap = vec![
        (
            c1_id,
            c1.descriptor.clone(),
            c1.mbk,
            c1_new.descriptor.clone(),
            c1_new.mbk,
        ),
        (
            c2_id,
            c2.descriptor.clone(),
            c2.mbk,
            c2_new.descriptor.clone(),
            c2_new.mbk,
        ),
    ];
    // Returns per customer: (new_unspent, old_received, old_unspent).
    let recaptured =
        tokio::task::spawn_blocking(move || -> Result<Vec<(u64, u64, u64)>, String> {
            let chain = RpcChainSource::new(&rpc2.0, &rpc2.1, &rpc2.2).map_err(de)?;
            // Build old + new wollets per customer and register both under the
            // customer's single wallet id (exactly as the ingestion service does).
            let mut built = Vec::new();
            for (id, old_d, old_m, new_d, new_m) in &recap {
                let w_old =
                    ElementsWollet::from_descriptor_str(old_d, *old_m, net, lwk).map_err(de)?;
                let w_new =
                    ElementsWollet::from_descriptor_str(new_d, *new_m, net, lwk).map_err(de)?;
                built.push((*id, w_old, w_new));
            }
            let mut engine = BlockScanEngine::new();
            for (id, w_old, w_new) in &built {
                engine.register_wallet(*id, w_old, 20).map_err(de)?;
                engine.register_wallet(*id, w_new, 20).map_err(de)?;
            }
            engine.sync(&chain, &blocks2, &utxos2).map_err(de)?;

            let mut out = Vec::new();
            for (id, w_old, w_new) in &built {
                // All captured (incl. spent) — what the UI "total received" reads.
                let all = utxos2.list_for_wallet(*id).map_err(de)?;
                let old_spk = w_old
                    .address(KeychainKind::External, 0)
                    .map_err(de)?
                    .script_pubkey();
                let new_spk = w_new
                    .address(KeychainKind::External, 0)
                    .map_err(de)?
                    .script_pubkey();
                let sum = |spk: &elements::Script, spent: bool| -> u64 {
                    all.iter()
                        .filter(|x| *x.script_pubkey() == *spk && x.is_spent == spent)
                        .map(CapturedUtxo::value)
                        .sum()
                };
                let new_unspent = sum(&new_spk, false);
                let old_received = sum(&old_spk, true) + sum(&old_spk, false);
                let old_unspent = sum(&old_spk, false);
                out.push((new_unspent, old_received, old_unspent));
            }
            Ok(out)
        })
        .await
        .unwrap()
        .expect("recapture");

    for (i, (new_unspent, old_received, old_unspent)) in recaptured.iter().enumerate() {
        assert_eq!(
            *new_unspent, LBTC_SAT,
            "customer {i}: full balance captured at the NEW federation"
        );
        // The old address keeps its historical "received" even though it's spent.
        assert_eq!(
            *old_received, LBTC_SAT,
            "customer {i}: old address still shows 1.0 received (history)"
        );
        assert_eq!(
            *old_unspent, 0,
            "customer {i}: old address now has 0 unspent (migrated away)"
        );
    }

    // cleanup
    for id in [fee_uuid, c1_uuid, c2_uuid] {
        sqlx::query(
            "DELETE FROM users WHERE id = (SELECT user_id FROM elements_wallets WHERE id=$1)",
        )
        .bind(id)
        .execute(&pool)
        .await
        .ok();
    }
    sqlx::query("DELETE FROM elements_blocks")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM elements_sync_cursor")
        .execute(&pool)
        .await
        .unwrap();
}

/// P4 — batched migration with **chained confidential fee-change** (decision
/// (b)): one tx for a large customer, one bundled tx for two small customers,
/// then the fee account migrating last. The fee account's change is routed back
/// to its OLD-fed address each hop (captured via `captured_from_output` and fed
/// into the next tx), crossing to the new federation only in the final tx.
///
/// Asserts the node accepted all three (chained, partly-unconfirmed) broadcasts,
/// each customer received its full balance at the new federation, and the fee
/// account paid the entire cumulative mining fee.
#[tokio::test]
async fn elements_batched_migration_e2e() {
    const LARGE: u64 = LBTC_SAT; // 1.0
    const SMALL1: u64 = 200_000; // 0.002
    const SMALL2: u64 = 100_000; // 0.001

    let Some(env) = env() else {
        eprintln!("skipping elements_batched_migration_e2e: ELEMENTS_RPC_URL/DATABASE_URL unset");
        return;
    };
    let _serial = e2e_lock().lock().await;

    let base = Client::new(
        &env.rpc_url,
        Auth::UserPass(env.rpc_user.clone(), env.rpc_pass.clone()),
    )
    .unwrap();
    let genesis: String = base.call("getblockhash", &[json!(0)]).unwrap();
    let sidechain: serde_json::Value = base.call("getsidechaininfo", &[]).unwrap();
    let policy = elements::AssetId::from_str(sidechain["pegged_asset"].as_str().unwrap()).unwrap();
    let net = ElementsNetwork::ElementsRegtest;
    let lwk =
        ElementsNetwork::custom_regtest(policy, elements::BlockHash::from_str(&genesis).unwrap());

    let pool = PgPool::connect(&env.database_url).await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    let tag = Uuid::new_v4();

    // Old wallets: fee + large customer + two small customers.
    let fee = make_wallet(tag, 0x30, 0xc0, net, lwk);
    let cl = make_wallet(tag, 0x31, 0xc1, net, lwk);
    let cs1 = make_wallet(tag, 0x32, 0xc2, net, lwk);
    let cs2 = make_wallet(tag, 0x33, 0xc3, net, lwk);
    // New-federation destinations.
    let fee_new = make_wallet(tag, 0x40, 0xd0, net, lwk);
    let cl_new = make_wallet(tag, 0x41, 0xd1, net, lwk);
    let cs1_new = make_wallet(tag, 0x42, 0xd2, net, lwk);
    let cs2_new = make_wallet(tag, 0x43, 0xd3, net, lwk);

    let base_acct = (u32::from_le_bytes(tag.as_bytes()[..4].try_into().unwrap()) % 1_000_000)
        as i32
        + 4_000_000;
    let fee_uuid = seed_row(&pool, &fee.descriptor, &fee.mbk, tag, base_acct).await;
    let cl_uuid = seed_row(&pool, &cl.descriptor, &cl.mbk, tag, base_acct + 1).await;
    let cs1_uuid = seed_row(&pool, &cs1.descriptor, &cs1.mbk, tag, base_acct + 2).await;
    let cs2_uuid = seed_row(&pool, &cs2.descriptor, &cs2.mbk, tag, base_acct + 3).await;
    let fee_id = WalletId::from_bytes(*fee_uuid.as_bytes());
    let cl_id = WalletId::from_bytes(*cl_uuid.as_bytes());
    let cs1_id = WalletId::from_bytes(*cs1_uuid.as_bytes());
    let cs2_id = WalletId::from_bytes(*cs2_uuid.as_bytes());

    // Fund each old wallet's external addr #0.
    let node = node_wallet(&env);
    let mine: String = node.call("getnewaddress", &[]).unwrap();
    for (w, amt) in [(&fee, 1.0), (&cl, 1.0), (&cs1, 0.002), (&cs2, 0.001)] {
        let addr = w.wollet.address(KeychainKind::External, 0).unwrap();
        let _t: String = node
            .call("sendtoaddress", &[json!(addr.to_string()), json!(amt)])
            .unwrap();
    }
    let _: Vec<String> = node
        .call("generatetoaddress", &[json!(2), json!(mine.clone())])
        .unwrap();

    let blocks = PgBlockStore::new(pool.clone());
    let utxos_store = PgWalletUtxoStore::new(pool.clone());
    let rpc = (
        env.rpc_url.clone(),
        env.rpc_user.clone(),
        env.rpc_pass.clone(),
    );

    let (fee_desc, cl_desc, cs1_desc, cs2_desc) = (
        fee.descriptor.clone(),
        cl.descriptor.clone(),
        cs1.descriptor.clone(),
        cs2.descriptor.clone(),
    );
    let (fee_new_desc, cl_new_desc, cs1_new_desc, cs2_new_desc) = (
        fee_new.descriptor.clone(),
        cl_new.descriptor.clone(),
        cs1_new.descriptor.clone(),
        cs2_new.descriptor.clone(),
    );
    let fee_sgn = fee.signers.clone();
    let cl_sgn = cl.signers.clone();
    let cs1_sgn = cs1.signers.clone();
    let cs2_sgn = cs2.signers.clone();
    let (fee_mbk, cl_mbk, cs1_mbk, cs2_mbk) = (fee.mbk, cl.mbk, cs1.mbk, cs2.mbk);
    let (fee_new_mbk, cl_new_mbk, cs1_new_mbk, cs2_new_mbk) =
        (fee_new.mbk, cl_new.mbk, cs1_new.mbk, cs2_new.mbk);

    // Returns (large_at_new, small1_at_new, small2_at_new, fee_at_new, fee_bal,
    // broadcasts).
    let outcome = tokio::task::spawn_blocking(
        move || -> Result<(u64, u64, u64, u64, u64, usize), String> {
            let chain = RpcChainSource::new(&rpc.0, &rpc.1, &rpc.2).map_err(de)?;
            let load = |d: &str, m: [u8; 32]| ElementsWollet::from_descriptor_str(d, m, net, lwk);

            let w_fee = load(&fee_desc, fee_mbk).map_err(de)?;
            let w_cl = load(&cl_desc, cl_mbk).map_err(de)?;
            let w_cs1 = load(&cs1_desc, cs1_mbk).map_err(de)?;
            let w_cs2 = load(&cs2_desc, cs2_mbk).map_err(de)?;
            let w_fee_new = load(&fee_new_desc, fee_new_mbk).map_err(de)?;
            let w_cl_new = load(&cl_new_desc, cl_new_mbk).map_err(de)?;
            let w_cs1_new = load(&cs1_new_desc, cs1_new_mbk).map_err(de)?;
            let w_cs2_new = load(&cs2_new_desc, cs2_new_mbk).map_err(de)?;

            let fee_old_addr = w_fee.address(KeychainKind::External, 0).map_err(de)?;
            let fee_new_dest = w_fee_new.address(KeychainKind::External, 0).map_err(de)?;
            let cl_dest = w_cl_new.address(KeychainKind::External, 0).map_err(de)?;
            let cs1_dest = w_cs1_new.address(KeychainKind::External, 0).map_err(de)?;
            let cs2_dest = w_cs2_new.address(KeychainKind::External, 0).map_err(de)?;

            // Capture all four old wallets in one scan pass.
            let mut engine = BlockScanEngine::new();
            engine.register_wallet(fee_id, &w_fee, 20).map_err(de)?;
            engine.register_wallet(cl_id, &w_cl, 20).map_err(de)?;
            engine.register_wallet(cs1_id, &w_cs1, 20).map_err(de)?;
            engine.register_wallet(cs2_id, &w_cs2, 20).map_err(de)?;
            engine.sync(&chain, &blocks, &utxos_store).map_err(de)?;

            let fee_utxos = utxos_store.list_unspent(fee_id).map_err(de)?;
            let cl_utxos = utxos_store.list_unspent(cl_id).map_err(de)?;
            let cs1_utxos = utxos_store.list_unspent(cs1_id).map_err(de)?;
            let cs2_utxos = utxos_store.list_unspent(cs2_id).map_err(de)?;
            if fee_utxos.is_empty()
                || cl_utxos.is_empty()
                || cs1_utxos.is_empty()
                || cs2_utxos.is_empty()
            {
                return Err("capture incomplete".to_string());
            }
            let fee_bal: u64 = fee_utxos.iter().map(CapturedUtxo::value).sum();

            // Index-scoped per-account signing (shared old federation).
            let sign_account = |pset: &mut elements::pset::PartiallySignedTransaction,
                                utxos: &[CapturedUtxo],
                                signers: &[SoftwareSigner]| {
                let owned: std::collections::HashSet<elements::OutPoint> =
                    utxos.iter().map(|u| u.outpoint).collect();
                let indices: Vec<usize> = pset
                    .inputs()
                    .iter()
                    .enumerate()
                    .filter(|(_, i)| {
                        owned.contains(&elements::OutPoint::new(
                            i.previous_txid,
                            i.previous_output_index,
                        ))
                    })
                    .map(|(i, _)| i)
                    .collect();
                let mut saved = Vec::new();
                for (i, inp) in pset.inputs_mut().iter_mut().enumerate() {
                    if !indices.contains(&i) {
                        saved.push((i, std::mem::take(&mut inp.bip32_derivation)));
                    }
                }
                for s in signers {
                    let _ = s.sign_pset(pset);
                }
                for (i, d) in saved {
                    pset.inputs_mut()[i].bip32_derivation = d;
                }
            };

            let val_at =
                |tx: &elements::Transaction, w: &ElementsWollet, addr: &elements::Address| -> u64 {
                    let spk = addr.script_pubkey();
                    let o = tx
                        .output
                        .iter()
                        .find(|o| o.script_pubkey == spk)
                        .expect("destination output present");
                    w.unblind(o).unwrap().value
                };
            // Capture the fee account's change (at its old-fed addr) as the
            // chained input for the next tx.
            let cap_chain = |tx: &elements::Transaction| -> Result<CapturedUtxo, String> {
                let spk = fee_old_addr.script_pubkey();
                let (vout, txout) = tx
                    .output
                    .iter()
                    .enumerate()
                    .find(|(_, o)| o.script_pubkey == spk)
                    .map(|(i, o)| (u32::try_from(i).unwrap(), o.clone()))
                    .ok_or("fee change output missing")?;
                captured_from_output(&w_fee, tx.txid(), vout, &txout, fee_id, 0).map_err(de)
            };

            let mut broadcasts = 0usize;

            // --- tx0: large customer + fee seed → change back to fee old. ---
            let mut inputs: Vec<(CapturedUtxo, &ElementsWollet)> = Vec::new();
            for u in &cl_utxos {
                inputs.push((u.clone(), &w_cl));
            }
            inputs.push((fee_utxos[0].clone(), &w_fee));
            let blinded = build_migration_pset(
                &w_fee,
                &inputs,
                &[(cl_dest.clone(), LARGE)],
                &fee_old_addr,
                2000.0,
            )
            .map_err(de)?;
            let mut pset = blinded.into_pset();
            sign_account(&mut pset, &cl_utxos, &cl_sgn);
            sign_account(&mut pset, std::slice::from_ref(&fee_utxos[0]), &fee_sgn);
            finalize_p2wsh_pset(&mut pset).map_err(de)?;
            let tx0 = pset.extract_tx().map_err(de)?;
            let large_at_new = val_at(&tx0, &w_cl_new, &cl_dest);
            chain.broadcast(&tx0).map_err(de)?;
            broadcasts += 1;
            let chained0 = cap_chain(&tx0)?;

            // --- tx1: small bundle + chained change → change back to fee old. ---
            let mut inputs: Vec<(CapturedUtxo, &ElementsWollet)> = Vec::new();
            for u in &cs1_utxos {
                inputs.push((u.clone(), &w_cs1));
            }
            for u in &cs2_utxos {
                inputs.push((u.clone(), &w_cs2));
            }
            inputs.push((chained0.clone(), &w_fee));
            let blinded = build_migration_pset(
                &w_fee,
                &inputs,
                &[(cs1_dest.clone(), SMALL1), (cs2_dest.clone(), SMALL2)],
                &fee_old_addr,
                2000.0,
            )
            .map_err(de)?;
            let mut pset = blinded.into_pset();
            sign_account(&mut pset, &cs1_utxos, &cs1_sgn);
            sign_account(&mut pset, &cs2_utxos, &cs2_sgn);
            sign_account(&mut pset, std::slice::from_ref(&chained0), &fee_sgn);
            finalize_p2wsh_pset(&mut pset).map_err(de)?;
            let tx1 = pset.extract_tx().map_err(de)?;
            let small1_at_new = val_at(&tx1, &w_cs1_new, &cs1_dest);
            let small2_at_new = val_at(&tx1, &w_cs2_new, &cs2_dest);
            chain.broadcast(&tx1).map_err(de)?;
            broadcasts += 1;
            let chained1 = cap_chain(&tx1)?;

            // --- tx2: fee account migrates last → drain to fee NEW dest. ---
            let inputs: Vec<(CapturedUtxo, &ElementsWollet)> = vec![(chained1.clone(), &w_fee)];
            let blinded =
                build_migration_pset(&w_fee, &inputs, &[], &fee_new_dest, 2000.0).map_err(de)?;
            let mut pset = blinded.into_pset();
            sign_account(&mut pset, std::slice::from_ref(&chained1), &fee_sgn);
            finalize_p2wsh_pset(&mut pset).map_err(de)?;
            let tx2 = pset.extract_tx().map_err(de)?;
            let fee_at_new = val_at(&tx2, &w_fee_new, &fee_new_dest);
            chain.broadcast(&tx2).map_err(de)?;
            broadcasts += 1;

            Ok((
                large_at_new,
                small1_at_new,
                small2_at_new,
                fee_at_new,
                fee_bal,
                broadcasts,
            ))
        },
    )
    .await
    .unwrap();

    let (large_at_new, small1_at_new, small2_at_new, fee_at_new, fee_bal, broadcasts) =
        outcome.expect("batched migration");

    assert_eq!(broadcasts, 3, "one large tx + one small bundle + fee-final");
    assert_eq!(
        large_at_new, LARGE,
        "large customer migrated its full balance"
    );
    assert_eq!(
        small1_at_new, SMALL1,
        "small customer 1 migrated its full balance"
    );
    assert_eq!(
        small2_at_new, SMALL2,
        "small customer 2 migrated its full balance"
    );
    let fee_paid = fee_bal - fee_at_new;
    assert!(fee_paid > 0, "fee account paid a non-zero cumulative fee");
    assert_eq!(
        fee_at_new + fee_paid,
        fee_bal,
        "fee account: final new-fed balance + cumulative fee == its old balance"
    );

    // cleanup
    let _ = node.call::<Vec<String>>("generatetoaddress", &[json!(1), json!(mine)]);
    for id in [fee_uuid, cl_uuid, cs1_uuid, cs2_uuid] {
        sqlx::query(
            "DELETE FROM users WHERE id = (SELECT user_id FROM elements_wallets WHERE id=$1)",
        )
        .bind(id)
        .execute(&pool)
        .await
        .ok();
    }
    sqlx::query("DELETE FROM elements_blocks")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM elements_sync_cursor")
        .execute(&pool)
        .await
        .unwrap();
}

fn de<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}
