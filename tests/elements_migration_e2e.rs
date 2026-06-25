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

use asterism_core::signer::Signer;
use asterism_elements::descriptor::{to_multipath_string, CtDescriptorBuilder, CtKeyMode};
use asterism_elements::signer::ElementsSigner;
use asterism_elements::sync::{
    BlockScanEngine, CapturedUtxo, ElementsChainSource, KeychainKind, WalletId, WalletUtxoStore,
};
use asterism_elements::testkit::SoftwareSigner;
use asterism_elements::{
    build_migration_pset, finalize_p2wsh_pset, ElementsNetwork, ElementsWollet,
    ElementsWalletHandle, LwkNetwork,
};

use test_app_pkcs11::elements_sync::{PgBlockStore, PgWalletUtxoStore, RpcChainSource};

const LBTC_SAT: u64 = 100_000_000;

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

fn make_wallet(tag: Uuid, signer_salt: u8, blinding_salt: u8, net: ElementsNetwork, lwk: LwkNetwork) -> TestWallet {
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
    let mut builder = CtDescriptorBuilder::new(2, &blinding).unwrap().key_mode(CtKeyMode::Ranged);
    for s in &signers {
        builder.add_signer(s as &dyn Signer).unwrap();
    }
    let ct = builder.build().unwrap();
    let descriptor = to_multipath_string(&ct);
    let handle = ElementsWalletHandle::new(ct, blinding);
    let wollet = ElementsWollet::from_handle_with_lwk(&handle, net, lwk).unwrap();
    TestWallet { wollet, signers, descriptor, mbk: blinding }
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
    let lwk = ElementsNetwork::custom_regtest(policy, elements::BlockHash::from_str(&genesis).unwrap());

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
    let base_acct =
        (u32::from_le_bytes(tag.as_bytes()[..4].try_into().unwrap()) % 1_000_000) as i32 + 3_000_000;
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
        let _t: String = node.call("sendtoaddress", &[json!(addr.to_string()), json!(1.0)]).unwrap();
    }
    let _: Vec<String> = node.call("generatetoaddress", &[json!(2), json!(mine.clone())]).unwrap();

    // --- capture all three via one scan pass ---
    let blocks = PgBlockStore::new(pool.clone());
    let utxos_store = PgWalletUtxoStore::new(pool.clone());
    let rpc = (env.rpc_url.clone(), env.rpc_user.clone(), env.rpc_pass.clone());

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
                    owned.contains(&elements::OutPoint::new(i.previous_txid, i.previous_output_index))
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

    // cleanup
    for id in [fee_uuid, c1_uuid, c2_uuid] {
        sqlx::query("DELETE FROM users WHERE id = (SELECT user_id FROM elements_wallets WHERE id=$1)")
            .bind(id).execute(&pool).await.ok();
    }
    sqlx::query("DELETE FROM elements_blocks").execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM elements_sync_cursor").execute(&pool).await.unwrap();
}

fn de<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}
