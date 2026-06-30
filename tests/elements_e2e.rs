//! P7 — end-to-end Elements receive + send against a live `elementsd` regtest
//! node and Postgres.
//!
//! Proves the whole pipeline on real confidential transactions:
//!   1. derive a confidential address from an `ElementsWollet`,
//!   2. fund it from the node's `default` wallet, confirm with a block,
//!   3. `BlockScanEngine::sync` over the live chain → UTXO captured + unblinded,
//!   4. `build_spend_pset` → sign 2-of-3 with `SoftwareSigner`s → broadcast,
//!   5. confirm, re-sync → deposit shows spent, change captured.
//!
//! Skips cleanly when `ELEMENTS_RPC_URL` / `DATABASE_URL` are not set, so the
//! normal `cargo test` stays green in environments without the node.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::format_collect,
    clippy::cast_lossless
)]

use std::str::FromStr;
use emvault::elements::elements;

use emvault::core::bitcoincore_rpc::{Auth, Client, RpcApi};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use emvault::core::federation::Federation;
use emvault::core::network::{ElementsNetworkId, NetworkType};
use emvault::core::signer::Signer;

use emvault::elements::descriptor::{CtDescriptorBuilder, CtKeyMode, to_multipath_string};
use emvault::elements::pset::ElementsSigningCoordinator;
use emvault::elements::sync::{BlockScanEngine, ElementsChainSource, WalletId, WalletUtxoStore};
use emvault::elements::testkit::SoftwareSigner;
use emvault::elements::{ElementsNetwork, ElementsWalletHandle, ElementsWollet, build_spend_pset};

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

/// A node wallet client (`/wallet/default`) for funding + mining.
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

#[tokio::test]
async fn elements_receive_and_send_e2e() {
    let Some(env) = env() else {
        eprintln!("skipping elements_receive_and_send_e2e: ELEMENTS_RPC_URL/DATABASE_URL unset");
        return;
    };

    // --- source the node's actual regtest params (policy asset + genesis) ---
    let base = Client::new(
        &env.rpc_url,
        Auth::UserPass(env.rpc_user.clone(), env.rpc_pass.clone()),
    )
    .unwrap();
    let genesis_str: String = base.call("getblockhash", &[json!(0)]).unwrap();
    let sidechain: serde_json::Value = base.call("getsidechaininfo", &[]).unwrap();
    let policy_str = sidechain["pegged_asset"].as_str().unwrap().to_string();
    let policy_asset = elements::AssetId::from_str(&policy_str).unwrap();
    let genesis_hash = elements::BlockHash::from_str(&genesis_str).unwrap();
    let lwk_net = ElementsNetwork::custom_regtest(policy_asset, genesis_hash);

    // --- build a 2-of-3 software-signer federation + wollet -----------------
    // Unique-per-run keys (and thus a fresh multisig script + addresses) so the
    // wallet never collides with UTXOs left on-chain by previous runs.
    let tag = Uuid::new_v4();
    let net = ElementsNetwork::ElementsRegtest;
    let signers: Vec<SoftwareSigner> = (0u8..3)
        .map(|i| {
            let mut sb = [0u8; 32];
            sb[..16].copy_from_slice(tag.as_bytes());
            sb[16] = i;
            SoftwareSigner::new_with_seed_bytes(sb, lwk_net)
        })
        .collect();
    let mut blinding = [0u8; 32];
    blinding[..16].copy_from_slice(tag.as_bytes());
    blinding[16] = 0xab;
    let mut builder = CtDescriptorBuilder::new(2, &blinding)
        .unwrap()
        .key_mode(CtKeyMode::Ranged);
    for s in &signers {
        builder.add_signer(s as &dyn Signer).unwrap();
    }
    let ct_desc = builder.build().unwrap();
    let handle = ElementsWalletHandle::new(ct_desc.clone(), blinding);
    let wollet = ElementsWollet::from_handle_with_lwk(&handle, net, lwk_net).unwrap();
    let federation = Federation::new(
        2,
        signers.clone(),
        NetworkType::Elements(ElementsNetworkId::ElementsRegtest),
    )
    .unwrap();

    // --- seed a throwaway user + elements_wallet (FK target) ----------------
    let pool = PgPool::connect(&env.database_url).await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    let user_id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id",
    )
    .bind(format!("{tag}@e2e.local"))
    .fetch_one(&pool)
    .await
    .unwrap();
    let acct = (u32::from_le_bytes(tag.as_bytes()[..4].try_into().unwrap()) % 1_000_000) as i32
        + 2_000_000;
    let wallet_uuid: Uuid = sqlx::query_scalar(
        "INSERT INTO elements_wallets \
           (user_id, account_idx, descriptor, master_blinding_key, daemon_wallet_name) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(user_id)
    .bind(acct)
    .bind(to_multipath_string(&ct_desc))
    .bind(hex32(&blinding))
    .bind(format!("e2e-{tag}"))
    .fetch_one(&pool)
    .await
    .unwrap();
    let wallet_id = WalletId::from_bytes(*wallet_uuid.as_bytes());

    // --- fund the wollet's external address #0 from the node ----------------
    let node = node_wallet(&env);
    let deposit_addr = wollet
        .address(emvault::elements::sync::KeychainKind::External, 0)
        .unwrap();
    let mine_addr: String = node.call("getnewaddress", &[]).unwrap();
    let _txid: String = node
        .call(
            "sendtoaddress",
            &[json!(deposit_addr.to_string()), json!(1.0)],
        )
        .unwrap();
    let _: Vec<String> = node
        .call("generatetoaddress", &[json!(2), json!(mine_addr.clone())])
        .unwrap();

    // Stores must be built in async context (capture the runtime Handle), then
    // moved into the blocking task that drives the engine.
    let blocks = PgBlockStore::new(pool.clone());
    let utxos = PgWalletUtxoStore::new(pool.clone());

    let env_rpc = (
        env.rpc_url.clone(),
        env.rpc_user.clone(),
        env.rpc_pass.clone(),
    );
    let recipient_str: String = node.call("getnewaddress", &[]).unwrap();

    let outcome = tokio::task::spawn_blocking(move || -> Result<(u64, u64), String> {
        let chain = RpcChainSource::new(&env_rpc.0, &env_rpc.1, &env_rpc.2).map_err(de)?;

        // 1) capture the deposit
        let mut engine = BlockScanEngine::new();
        engine.register_wallet(wallet_id, &wollet, 20).map_err(de)?;
        engine.sync(&chain, &blocks, &utxos).map_err(de)?;

        let captured = utxos.list_unspent(wallet_id).map_err(de)?;
        if captured.len() != 1 {
            return Err(format!("expected 1 captured utxo, got {}", captured.len()));
        }
        let deposit_value = captured[0].value();

        // 2) spend 0.5 LBTC to a fresh node address
        let recipient = elements::Address::from_str(&recipient_str).map_err(de)?;
        // 2000 sat/kvb (2 sat/vb) clears the node's min relay fee.
        let blinded =
            build_spend_pset(&wollet, &captured, &recipient, LBTC_SAT / 2, 2000.0).map_err(de)?;
        let mut coord = ElementsSigningCoordinator::new(&federation, blinded).map_err(de)?;
        coord.sign_with(&signers[0], &signers[0].id()).map_err(de)?;
        coord.sign_with(&signers[1], &signers[1].id()).map_err(de)?;
        let finalized = coord.finalize().map_err(de)?;
        let txid = chain.broadcast(finalized.transaction()).map_err(de)?;
        eprintln!("e2e broadcast txid: {txid}");

        Ok((deposit_value, captured[0].height as u64))
    })
    .await
    .unwrap();

    let (deposit_value, _h) = outcome.expect("capture + spend + broadcast");
    assert_eq!(deposit_value, LBTC_SAT, "captured 1.0 L-BTC, unblinded");

    // 3) confirm the spend, re-sync, assert deposit spent + change captured
    let _: Vec<String> = node
        .call("generatetoaddress", &[json!(2), json!(mine_addr)])
        .unwrap();

    let wollet2 = ElementsWollet::from_handle_with_lwk(&handle, net, lwk_net).unwrap();
    let blocks2 = PgBlockStore::new(pool.clone());
    let utxos2 = PgWalletUtxoStore::new(pool.clone());
    let env_rpc2 = (
        env.rpc_url.clone(),
        env.rpc_user.clone(),
        env.rpc_pass.clone(),
    );
    let resync = tokio::task::spawn_blocking(move || -> Result<Vec<u64>, String> {
        let chain = RpcChainSource::new(&env_rpc2.0, &env_rpc2.1, &env_rpc2.2).map_err(de)?;
        let mut engine = BlockScanEngine::new();
        engine
            .register_wallet(wallet_id, &wollet2, 20)
            .map_err(de)?;
        engine.sync(&chain, &blocks2, &utxos2).map_err(de)?;
        Ok(utxos2
            .list_unspent(wallet_id)
            .map_err(de)?
            .iter()
            .map(emvault::elements::CapturedUtxo::value)
            .collect())
    })
    .await
    .unwrap()
    .expect("resync");

    // The 1.0 deposit is now spent; only the change (≈0.5 minus fee) remains.
    assert!(
        !resync.contains(&LBTC_SAT),
        "deposit must be spent after broadcast+confirm, unspent set = {resync:?}"
    );
    assert_eq!(
        resync.len(),
        1,
        "exactly the change output remains: {resync:?}"
    );
    let change = resync[0];
    assert!(
        change > 0 && change < LBTC_SAT / 2 + 1_000_000,
        "change ≈ 0.5 L-BTC minus fee, got {change}"
    );

    // --- cleanup -----------------------------------------------------------
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
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
