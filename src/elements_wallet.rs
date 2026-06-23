//! Per-user Elements/Liquid wallet manager.
//!
//! Mirrors the Bitcoin [`WalletManager`](crate::wallet::WalletManager) but
//! delegates chain operations to the Elements daemon (watch-only descriptor
//! wallet) instead of BDK + Bitcoin Core. The HSMs sign PSET inputs
//! identically to the Bitcoin PSBT path.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use asterism_elements::ElementsNetwork;
use asterism_elements::descriptor::{CtDescriptorBuilder, CtKeyMode, to_multipath_string};
use asterism_elements::signer::ElementsSigner;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use elements::encode::{deserialize as consensus_deserialize, serialize as consensus_serialize};
use elements::pset::PartiallySignedTransaction as Pset;
use sqlx::PgPool;
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

use asterism_elements::elements_miniscript::slip77::MasterBlindingKey;

use crate::config::AppConfig;
use crate::db;
use crate::elements_rpc::{
    ElementsBalances, ElementsRpc, ElementsRpcError, ElementsUtxo, ImportDescriptorRequest,
};
use crate::hsm::{HsmError, HsmFleet};
use crate::models::ElementsWalletRow;
use crate::wallet::NetworkPatchedSigner;

#[allow(dead_code)]
pub const REVEAL_COUNT: u32 = 20;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub enum ElementsWalletError {
    #[error("Elements wallet for user `{0}` not found")]
    NotFound(Uuid),
    #[error("address `{addr}` is not valid: {reason}")]
    BadAddress { addr: String, reason: String },
    #[error("invalid fee rate `{sat_per_vb}` sat/vB")]
    BadFeeRate { sat_per_vb: u64 },
    #[error("invalid amount `{amount}`: {reason}")]
    BadAmount { amount: String, reason: String },
    #[error("PSET construction failed: {0}")]
    BuildPset(String),
    #[error("PSET signing error: {0}")]
    Sign(String),
    #[error("PSET finalization failed: {0}")]
    Finalize(String),
    #[error("Elements daemon rejected broadcast: {0}")]
    BroadcastRejected(String),
    #[error("Elements RPC error: {0}")]
    Rpc(#[from] ElementsRpcError),
    #[error("descriptor builder error: {0}")]
    Descriptor(String),
    #[error("HSM error: {0}")]
    Hsm(#[from] HsmError),
    #[error("PSET decode error: {0}")]
    PsetDecode(String),
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("config error: {0}")]
    Config(#[from] crate::config::ConfigError),
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

pub struct ElementsWalletManager {
    pool: PgPool,
    rpc: Arc<ElementsRpc>,
    network: ElementsNetwork,
    bip48_coin_index: u32,
    fed_threshold: u32,
    hsm: Arc<HsmFleet>,
    cache: AsyncMutex<HashMap<Uuid, Arc<UserElementsWallet>>>,
}

#[allow(dead_code)]
impl ElementsWalletManager {
    pub fn new(pool: PgPool, config: &AppConfig, hsm: Arc<HsmFleet>) -> Self {
        let rpc = Arc::new(ElementsRpc::new(
            &config.elements_rpc_url,
            &config.elements_rpc_user,
            &config.elements_rpc_password,
        ));
        Self {
            pool,
            rpc,
            network: config.elements_network,
            bip48_coin_index: config.bip48_coin_index,
            fed_threshold: config.fed_threshold,
            hsm,
            cache: AsyncMutex::new(HashMap::new()),
        }
    }

    pub fn network(&self) -> ElementsNetwork {
        self.network
    }

    fn derivation_path_for(
        &self,
        account_idx: u32,
    ) -> Result<bitcoin::bip32::DerivationPath, ElementsWalletError> {
        let parts = [
            bitcoin::bip32::ChildNumber::from_hardened_idx(48)
                .map_err(|e| ElementsWalletError::Sign(format!("48': {e}")))?,
            bitcoin::bip32::ChildNumber::from_hardened_idx(self.bip48_coin_index)
                .map_err(|e| ElementsWalletError::Sign(format!("coin: {e}")))?,
            bitcoin::bip32::ChildNumber::from_hardened_idx(account_idx)
                .map_err(|e| ElementsWalletError::Sign(format!("account: {e}")))?,
            bitcoin::bip32::ChildNumber::from_hardened_idx(2)
                .map_err(|e| ElementsWalletError::Sign(format!("script-type: {e}")))?,
        ];
        Ok(bitcoin::bip32::DerivationPath::from(parts.to_vec()))
    }

    pub async fn load_or_init(
        &self,
        user_id: Uuid,
    ) -> Result<Arc<UserElementsWallet>, ElementsWalletError> {
        if let Some(uw) = self.cache.lock().await.get(&user_id).cloned() {
            return Ok(uw);
        }
        let row = match db::find_elements_wallet_for_user(&self.pool, user_id).await? {
            Some(r) => r,
            None => self.create_wallet_for_user(user_id).await?,
        };
        let uw = Arc::new(self.build_user_wallet(user_id, row).await?);
        let mut cache = self.cache.lock().await;
        Ok(cache.entry(user_id).or_insert(uw).clone())
    }

    pub async fn ensure_wallet_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<ElementsWalletRow, ElementsWalletError> {
        if let Some(row) = db::find_elements_wallet_for_user(&self.pool, user_id).await? {
            return Ok(row);
        }
        self.create_wallet_for_user(user_id).await
    }

    async fn create_wallet_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<ElementsWalletRow, ElementsWalletError> {
        let account_idx = db::next_elements_account_idx(&self.pool).await?;
        let account_idx_u32 = u32::try_from(account_idx).unwrap_or(0);
        let path = self.derivation_path_for(account_idx_u32)?;

        let signers_arc = self.hsm.signers_for(user_id, &path).await?;
        let patched: Vec<NetworkPatchedSigner> = signers_arc
            .iter()
            .cloned()
            .map(|s| NetworkPatchedSigner::new(s, self.hsm.network()))
            .collect();

        // Generate a deterministic MBK from user_id + account_idx.
        let mbk = derive_master_blinding_key(user_id, account_idx);
        let mbk_hex = hex_encode(&mbk);

        let mut builder = CtDescriptorBuilder::new(self.fed_threshold, &mbk)
            .map_err(|e| ElementsWalletError::Descriptor(e.to_string()))?
            .key_mode(CtKeyMode::Ranged);
        for signer in &patched {
            builder
                .add_signer(signer)
                .map_err(|e| ElementsWalletError::Descriptor(e.to_string()))?;
        }
        let ct_desc = builder
            .build()
            .map_err(|e| ElementsWalletError::Descriptor(e.to_string()))?;
        let multipath = to_multipath_string(&ct_desc);

        // Elements Core RPC doesn't support ct()/elwsh() descriptors or
        // BIP-389 multipath syntax (/<0;1>/*). Extract the inner
        // wsh(sortedmulti(...)) and import receive (/0/*) and change (/1/*)
        // as separate descriptors with checksums.
        let inner_multipath = extract_inner_wsh(&multipath).ok_or_else(|| {
            ElementsWalletError::Descriptor(
                "could not extract inner wsh() from CT descriptor".into(),
            )
        })?;
        let inner_receive = inner_multipath.replace("/<0;1>/*", "/0/*");
        let inner_change = inner_multipath.replace("/<0;1>/*", "/1/*");

        let daemon_wallet_name = format!("asterism-elements-user-{account_idx}");

        let rpc = self.rpc.clone();
        let wallet_name = daemon_wallet_name.clone();
        let mbk_for_blinding = mbk;
        let network = self.network;
        let ct_desc_clone = ct_desc.clone();
        tokio::task::spawn_blocking(move || -> Result<(), ElementsWalletError> {
            type CtDesc = asterism_elements::elements_miniscript::confidential::Descriptor<
                asterism_elements::elements_miniscript::descriptor::DescriptorPublicKey,
            >;

            rpc.ensure_wallet_loaded(&wallet_name)?;

            // Import receive and change descriptors separately.
            for (desc, is_internal) in [(&inner_receive, false), (&inner_change, true)] {
                let info = rpc.get_descriptor_info(desc)?;
                let desc_with_checksum = format!("{desc}#{}", info.checksum);

                let results = rpc.import_descriptors(
                    &wallet_name,
                    &[ImportDescriptorRequest {
                        descriptor: desc_with_checksum,
                        active: true,
                        internal: is_internal,
                    }],
                )?;
                for r in &results {
                    if let (false, Some(err)) = (r.success, &r.error) {
                        tracing::warn!(
                            code = err.code,
                            msg = %err.message,
                            internal = is_internal,
                            "import_descriptors warning (may be already imported)"
                        );
                    }
                }
            }

            // Import blinding keys for both receive (/0/*) and change (/1/*).
            let slip77_mbk = MasterBlindingKey::from(mbk_for_blinding);
            let secp =
                asterism_elements::elements_miniscript::elements::secp256k1_zkp::Secp256k1::new();

            let multipath_str = ct_desc_clone.to_string();
            let receive_str = multipath_str.replace("/<0;1>/*", "/0/*");
            let change_str = multipath_str.replace("/<0;1>/*", "/1/*");

            let descs: Vec<CtDesc> = [&receive_str, &change_str]
                .iter()
                .filter_map(|s| CtDesc::from_str(s).ok())
                .collect();

            for desc in &descs {
                for idx in 0..REVEAL_COUNT {
                    if let Ok(definite) = desc.at_derivation_index(idx) {
                        let Ok(addr) = definite.address(&secp, network.address_params()) else {
                            continue;
                        };
                        let spk = definite.descriptor.script_pubkey();
                        let bk = slip77_mbk.blinding_private_key(&spk);
                        let bk_hex = hex_encode(&bk.secret_bytes());
                        if let Err(e) =
                            rpc.import_blinding_key(&wallet_name, &addr.to_string(), &bk_hex)
                        {
                            tracing::warn!(idx, error = %e, "importblindingkey failed");
                        }
                    }
                }
            }

            Ok(())
        })
        .await
        .expect("spawn_blocking join")?;

        let row = db::insert_elements_wallet(
            &self.pool,
            &db::NewElementsWallet {
                user_id,
                account_idx,
                descriptor: &multipath,
                master_blinding_key: &mbk_hex,
                daemon_wallet_name: &daemon_wallet_name,
            },
        )
        .await?;

        tracing::info!(
            %user_id,
            account_idx = row.account_idx,
            daemon_wallet = %daemon_wallet_name,
            "created Elements user wallet"
        );
        Ok(row)
    }

    async fn build_user_wallet(
        &self,
        user_id: Uuid,
        row: ElementsWalletRow,
    ) -> Result<UserElementsWallet, ElementsWalletError> {
        let account_idx_u32 = u32::try_from(row.account_idx).unwrap_or(0);
        let path = self.derivation_path_for(account_idx_u32)?;
        let signers_arc = self.hsm.signers_for(user_id, &path).await?;

        // Ensure daemon wallet is loaded.
        let rpc = self.rpc.clone();
        let wallet_name = row.daemon_wallet_name.clone();
        tokio::task::spawn_blocking(move || rpc.ensure_wallet_loaded(&wallet_name))
            .await
            .expect("spawn_blocking join")?;

        // Record the initial federation version if not already stored.
        let version_count = db::federation_version_count_for_elements_wallet(
            &self.pool, row.id,
        )
        .await
        .unwrap_or(0);
        let signer_count = i32::try_from(signers_arc.len()).unwrap_or(0);
        let threshold = i32::try_from(self.fed_threshold).unwrap_or(0);
        if version_count == 0 {
            let snapshot = serde_json::json!({
                "descriptor": row.descriptor,
                "daemon_wallet_name": row.daemon_wallet_name,
            });
            let _ = db::insert_federation_version(
                &self.pool,
                &db::NewFederationVersion {
                    wallet_id: None,
                    elements_wallet_id: Some(row.id),
                    version_index: 0,
                    descriptor: &row.descriptor,
                    threshold,
                    signer_count,
                    federation_snapshot: &snapshot,
                    wallet_handle: &row.daemon_wallet_name,
                    blinding_key: Some(&row.master_blinding_key),
                },
            )
            .await
            .ok();
        }

        Ok(UserElementsWallet {
            user_id,
            wallet_id: row.id,
            account_idx: row.account_idx,
            network: self.network,
            descriptor: row.descriptor,
            daemon_wallet_name: row.daemon_wallet_name,
            signers: signers_arc,
            federation_version_count: usize::try_from(version_count.max(1)).unwrap_or(1),
            rpc: self.rpc.clone(),
            pool: self.pool.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// UserElementsWallet
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ElementsRevealedAddress {
    pub index: u32,
    pub address: String,
    pub received: f64,
    pub unspent: f64,
}

#[derive(Debug, Clone)]
pub struct ElementsAddressReceipt {
    pub txid: String,
    pub vout: u32,
    pub amount: f64,
    pub confirmations: u32,
    pub is_spent: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ElementsAddressActivity {
    pub tip_height: u64,
    pub total_received: f64,
    pub unspent: f64,
    pub receipts: Vec<ElementsAddressReceipt>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ElementsBroadcastTransaction {
    pub txid: String,
    pub recipient: String,
    pub amount_sat: i64,
    pub fee_sat: i64,
}

pub struct UserElementsWallet {
    user_id: Uuid,
    wallet_id: Uuid,
    account_idx: i32,
    network: ElementsNetwork,
    descriptor: String,
    daemon_wallet_name: String,
    signers: crate::hsm::SignerSet,
    /// Number of historical federation versions for this wallet.
    federation_version_count: usize,
    rpc: Arc<ElementsRpc>,
    pool: PgPool,
}

#[allow(dead_code)]
impl UserElementsWallet {
    pub fn user_id(&self) -> Uuid {
        self.user_id
    }

    pub fn wallet_id(&self) -> Uuid {
        self.wallet_id
    }

    pub fn network(&self) -> ElementsNetwork {
        self.network
    }

    pub fn account_idx(&self) -> i32 {
        self.account_idx
    }

    pub fn descriptor(&self) -> &str {
        &self.descriptor
    }

    pub fn federation_version_count(&self) -> usize {
        self.federation_version_count
    }

    pub async fn tip_height(&self) -> Result<u64, ElementsWalletError> {
        let rpc = self.rpc.clone();
        let height = tokio::task::spawn_blocking(move || rpc.get_block_count())
            .await
            .expect("spawn_blocking join")?;
        Ok(height)
    }

    pub async fn balance(&self) -> Result<ElementsBalances, ElementsWalletError> {
        let rpc = self.rpc.clone();
        let wallet = self.daemon_wallet_name.clone();
        let balances = tokio::task::spawn_blocking(move || rpc.get_balances(&wallet))
            .await
            .expect("spawn_blocking join")?;
        Ok(balances)
    }

    pub async fn reveal_addresses(
        &self,
        count: u32,
    ) -> Result<Vec<ElementsRevealedAddress>, ElementsWalletError> {
        self.derive_addresses(count, "/0/*").await
    }

    pub async fn change_addresses(
        &self,
        count: u32,
    ) -> Result<Vec<ElementsRevealedAddress>, ElementsWalletError> {
        self.derive_addresses(count, "/1/*").await
    }

    async fn derive_addresses(
        &self,
        count: u32,
        keychain_suffix: &str,
    ) -> Result<Vec<ElementsRevealedAddress>, ElementsWalletError> {
        type CtDesc = asterism_elements::elements_miniscript::confidential::Descriptor<
            asterism_elements::elements_miniscript::descriptor::DescriptorPublicKey,
        >;

        if count == 0 {
            return Ok(Vec::new());
        }

        let desc_str = self.descriptor.replace("/<0;1>/*", keychain_suffix);
        let ct_desc = CtDesc::from_str(&desc_str)
            .map_err(|e| ElementsWalletError::Descriptor(e.to_string()))?;

        let secp =
            asterism_elements::elements_miniscript::elements::secp256k1_zkp::Secp256k1::new();
        let network = self.network;

        // Derive addresses and their script pubkeys for matching.
        let mut addr_info: Vec<(String, elements::Script)> = Vec::with_capacity(count as usize);
        for idx in 0..count {
            let definite = ct_desc
                .at_derivation_index(idx)
                .map_err(|e| ElementsWalletError::Descriptor(e.to_string()))?;
            let conf_addr = definite
                .address(&secp, network.address_params())
                .map_err(|e| ElementsWalletError::Descriptor(e.to_string()))?;
            let spk = definite.descriptor.script_pubkey();
            addr_info.push((conf_addr.to_string(), spk));
        }

        let rpc = self.rpc.clone();
        let wallet = self.daemon_wallet_name.clone();
        let (utxos, txs) = tokio::task::spawn_blocking(move || -> Result<_, ElementsWalletError> {
            let utxos = rpc.list_unspent(&wallet)?;
            let txs = rpc.list_transactions(&wallet)?;
            Ok((utxos, txs))
        })
        .await
        .expect("spawn_blocking join")?;

        // Build script-pubkey maps for unspent and total received.
        let spk_unspent = build_spk_utxo_map(&utxos);
        let spk_received = build_spk_received_map(&txs);

        let results = addr_info
            .into_iter()
            .enumerate()
            .map(|(i, (conf_addr, spk))| {
                let unspent = spk_unspent.get(&spk).copied().unwrap_or(0.0);
                let received = spk_received.get(&spk).copied().unwrap_or(0.0);
                ElementsRevealedAddress {
                    index: u32::try_from(i).unwrap_or(0),
                    address: conf_addr,
                    received,
                    unspent,
                }
            })
            .collect();
        Ok(results)
    }

    pub async fn address_history(
        &self,
        address: &str,
    ) -> Result<ElementsAddressActivity, ElementsWalletError> {
        let target_spk = elements::Address::from_str(address)
            .map(|a| a.script_pubkey())
            .map_err(|e| ElementsWalletError::Descriptor(format!("invalid address: {e}")))?;

        let rpc = self.rpc.clone();
        let wallet = self.daemon_wallet_name.clone();
        let spk = target_spk.clone();

        let (txs, unspent_utxos, tip) =
            tokio::task::spawn_blocking(move || -> Result<_, ElementsWalletError> {
                let txs = rpc.list_transactions(&wallet)?;
                let utxos = rpc.list_unspent(&wallet)?;
                let tip = rpc.get_block_count()?;

                let addr_matches = |addr_str: &str| -> bool {
                    elements::Address::from_str(addr_str)
                        .ok()
                        .is_some_and(|a| a.script_pubkey() == spk)
                };

                let matched_txs: Vec<_> = txs
                    .into_iter()
                    .filter(|t| {
                        t.address.as_deref().is_some_and(addr_matches)
                    })
                    .collect();

                let matched_utxos: Vec<_> = utxos
                    .into_iter()
                    .filter(|u| {
                        u.address.as_deref().is_some_and(addr_matches)
                    })
                    .collect();

                Ok((matched_txs, matched_utxos, tip))
            })
            .await
            .expect("spawn_blocking join")?;

        // Total received = sum of positive-amount "receive" transactions.
        let total_received: f64 = txs
            .iter()
            .filter(|t| t.category == "receive")
            .filter_map(|t| t.amount)
            .filter(|a| *a > 0.0)
            .sum();

        // Unspent = sum of current UTXOs at this address (clamped to zero).
        let unspent: f64 = unspent_utxos
            .iter()
            .filter_map(|u| u.amount)
            .filter(|a| *a > 0.0)
            .sum();

        // Build receipts from transaction history (shows both spent and unspent).
        let unspent_set: std::collections::HashSet<(String, u32)> = unspent_utxos
            .iter()
            .map(|u| (u.txid.clone(), u.vout))
            .collect();

        let receipts: Vec<_> = txs
            .iter()
            .filter(|t| t.category == "receive")
            .map(|t| {
                let vout = t.vout.unwrap_or(0);
                let is_spent = !unspent_set.contains(&(t.txid.clone(), vout));
                ElementsAddressReceipt {
                    txid: t.txid.clone(),
                    vout,
                    amount: t.amount.unwrap_or(0.0),
                    confirmations: u32::try_from(t.confirmations.unwrap_or(0).max(0))
                        .unwrap_or(0),
                    is_spent,
                }
            })
            .collect();

        Ok(ElementsAddressActivity {
            tip_height: tip,
            total_received,
            unspent,
            receipts,
        })
    }

    pub async fn build_sign_and_broadcast(
        &self,
        recipient: &str,
        amount_btc: f64,
        fee_rate_sat_vb: u64,
        label: Option<String>,
    ) -> Result<ElementsBroadcastTransaction, ElementsWalletError> {
        // sat/vB → BTC/kB for Elements RPC.
        #[allow(clippy::cast_precision_loss)]
        let fee_rate_btc_kb = (fee_rate_sat_vb as f64) * 1000.0 / 100_000_000.0;

        let rpc = self.rpc.clone();
        let wallet = self.daemon_wallet_name.clone();
        let recipient_owned = recipient.to_string();
        let signers: Vec<_> = self.signers.iter().cloned().collect();
        let mbk_bytes = derive_master_blinding_key(self.user_id, self.account_idx);

        let result = tokio::task::spawn_blocking(move || -> Result<_, ElementsWalletError> {
            // Step 1: Build unsigned PSET via Elements daemon (UTXO selection).
            let outputs = vec![serde_json::json!({ recipient_owned.clone(): amount_btc })];
            let funded = rpc.wallet_create_funded_psbt(&wallet, &outputs, fee_rate_btc_kb)?;

            // Step 2: Decode and wrap as UnsignedPset.
            let pset_bytes = BASE64
                .decode(funded.psbt.as_bytes())
                .map_err(|e| ElementsWalletError::PsetDecode(e.to_string()))?;
            let pset: Pset = consensus_deserialize(&pset_bytes)
                .map_err(|e| ElementsWalletError::PsetDecode(e.to_string()))?;
            let unsigned = asterism_elements::UnsignedPset::new(pset)
                .map_err(|e| ElementsWalletError::PsetDecode(e.to_string()))?;

            // Step 3: Blind using the library (replaces walletprocesspsbt RPC).
            // The PSET's witness_utxo may lack range proofs for confidential
            // inputs (Elements Core strips them in walletcreatefundedpsbt).
            // For those inputs, fetch the full previous transaction to get
            // the complete output with range proof for unblinding.
            let mbk = MasterBlindingKey::from(mbk_bytes);
            let inp_secrets = derive_input_secrets_with_rpc(
                unsigned.as_pset(), &mbk, &rpc, &wallet,
            )?;
            let blinded = asterism_elements::blind_pset(unsigned, &inp_secrets)
                .map_err(|e| ElementsWalletError::Sign(e.to_string()))?;

            // Step 4: Sign with all HSMs.
            let mut pset = blinded.into_pset();
            let mut total_signed = 0usize;
            for signer in &signers {
                let n = signer
                    .sign_pset(&mut pset)
                    .map_err(|e| ElementsWalletError::Sign(e.to_string()))?;
                total_signed += n;
            }
            tracing::debug!(total_signed, "PSET signed by HSM federation");

            // Step 5: Finalize using the library (replaces finalizepsbt RPC).
            asterism_elements::finalize_p2wsh_pset(&mut pset)
                .map_err(|e| ElementsWalletError::Finalize(e.to_string()))?;
            let tx = pset
                .extract_tx()
                .map_err(|e| ElementsWalletError::Finalize(e.to_string()))?;
            let raw_hex = {
                let bytes = consensus_serialize(&tx);
                let mut hex = String::with_capacity(bytes.len() * 2);
                for b in &bytes {
                    use std::fmt::Write;
                    let _ = write!(hex, "{b:02x}");
                }
                hex
            };

            // Step 6: Broadcast.
            let txid = rpc.send_raw_transaction(&raw_hex)?;
            #[allow(clippy::cast_possible_truncation)]
            let fee_sat = (funded.fee * 100_000_000.0).round() as i64;
            #[allow(clippy::cast_possible_truncation)]
            let amount_sat = (amount_btc * 100_000_000.0).round() as i64;

            Ok((txid, recipient_owned, amount_sat, fee_sat, raw_hex))
        })
        .await
        .expect("spawn_blocking join")?;

        let (txid, recipient_str, amount_sat, fee_sat, raw_hex) = result;

        db::insert_elements_transaction(
            &self.pool,
            &db::NewElementsTransaction {
                wallet_id: self.wallet_id,
                txid: &txid,
                recipient: &recipient_str,
                amount_sat,
                fee_sat,
                raw_tx_hex: &raw_hex,
                label: label.as_deref(),
            },
        )
        .await?;

        Ok(ElementsBroadcastTransaction {
            txid,
            recipient: recipient_str,
            amount_sat,
            fee_sat,
        })
    }
}

fn derive_input_secrets_with_rpc(
    pset: &Pset,
    master_blinding_key: &MasterBlindingKey,
    rpc: &ElementsRpc,
    wallet: &str,
) -> Result<HashMap<usize, elements::TxOutSecrets>, ElementsWalletError> {
    use elements::confidential;

    let mut secrets = HashMap::new();
    for (i, input) in pset.inputs().iter().enumerate() {
        let utxo = input.witness_utxo.as_ref().ok_or_else(|| {
            ElementsWalletError::Sign(format!("input {i} missing witness_utxo"))
        })?;

        if let (confidential::Value::Explicit(value), confidential::Asset::Explicit(asset)) =
            (utxo.value, utxo.asset)
        {
            secrets.insert(i, asterism_elements::explicit_txout_secrets(asset, value));
        } else {
            let prev_txid = &input.previous_txid;
            let prev_vout = input.previous_output_index;
            let raw_hex = rpc.get_wallet_transaction_hex(wallet, &prev_txid.to_string())
                .map_err(|e| ElementsWalletError::Sign(format!(
                    "failed to fetch prev tx {prev_txid}: {e}"
                )))?;
            let tx_bytes = hex_decode(&raw_hex)
                .map_err(|e| ElementsWalletError::Sign(format!(
                    "bad hex from getrawtransaction: {e}"
                )))?;
            let prev_tx: elements::Transaction = consensus_deserialize(&tx_bytes)
                .map_err(|e| ElementsWalletError::Sign(format!(
                    "failed to decode prev tx: {e}"
                )))?;
            let full_output = &prev_tx.output[prev_vout as usize];
            let slip77_key = asterism_elements::slip77_blinding_key(
                master_blinding_key,
                &full_output.script_pubkey,
            );
            // Try SLIP-77 key first; fall back to the daemon's blinding
            // key for legacy change outputs blinded before we imported
            // our own keys.
            let txout_secrets = if let Ok(s) =
                asterism_elements::unblind_input(full_output, slip77_key)
            {
                s
            } else {
                let addr = elements::Address::from_script(
                    &full_output.script_pubkey,
                    None,
                    &elements::AddressParams::ELEMENTS,
                )
                .ok_or_else(|| ElementsWalletError::Sign(format!(
                    "input {i}: cannot derive address from script_pubkey"
                )))?;
                let key_hex = rpc.dump_blinding_key(wallet, &addr.to_string())
                    .map_err(|e| ElementsWalletError::Sign(format!(
                        "input {i}: dumpblindingkey failed: {e}"
                    )))?;
                let key_bytes = hex_decode(&key_hex)
                    .map_err(|e| ElementsWalletError::Sign(format!(
                        "input {i}: bad blinding key hex: {e}"
                    )))?;
                let daemon_key = elements::secp256k1_zkp::SecretKey::from_slice(&key_bytes)
                    .map_err(|e| ElementsWalletError::Sign(format!(
                        "input {i}: invalid blinding key: {e}"
                    )))?;
                asterism_elements::unblind_input(full_output, daemon_key)
                    .map_err(|e| ElementsWalletError::Sign(e.to_string()))?
            };
            secrets.insert(i, txout_secrets);
        }
    }
    Ok(secrets)
}

fn build_spk_utxo_map(utxos: &[ElementsUtxo]) -> HashMap<elements::Script, f64> {
    let mut map: HashMap<elements::Script, f64> = HashMap::new();
    for utxo in utxos {
        if let Some(addr_str) = utxo.address.as_deref() {
            let amount = utxo.amount.unwrap_or(0.0);
            if let Ok(addr) = elements::Address::from_str(addr_str) {
                let spk = addr.script_pubkey();
                *map.entry(spk).or_insert(0.0) += amount;
            }
        }
    }
    map
}

fn build_spk_received_map(
    txs: &[crate::elements_rpc::WalletTransaction],
) -> HashMap<elements::Script, f64> {
    let mut map: HashMap<elements::Script, f64> = HashMap::new();
    for tx in txs {
        if tx.category != "receive" {
            continue;
        }
        if let Some(addr_str) = tx.address.as_deref() {
            let amount = tx.amount.unwrap_or(0.0);
            if let Ok(addr) = elements::Address::from_str(addr_str) {
                let spk = addr.script_pubkey();
                *map.entry(spk).or_insert(0.0) += amount;
            }
        }
    }
    map
}

fn derive_master_blinding_key(user_id: Uuid, account_idx: i32) -> [u8; 32] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    user_id.hash(&mut hasher);
    account_idx.hash(&mut hasher);
    let h1 = hasher.finish();
    let mut hasher2 = DefaultHasher::new();
    h1.hash(&mut hasher2);
    "asterism-elements-mbk-v1".hash(&mut hasher2);
    let h2 = hasher2.finish();

    let mut key = [0u8; 32];
    key[..8].copy_from_slice(&h1.to_le_bytes());
    key[8..16].copy_from_slice(&h2.to_le_bytes());
    key[16..24].copy_from_slice(&h1.to_be_bytes());
    key[24..32].copy_from_slice(&h2.to_be_bytes());
    key
}

/// Extract the inner `wsh(sortedmulti(...))` descriptor from a
/// `ct(slip77(...), elwsh(sortedmulti(...)))` string.
///
/// Elements Core RPC only understands standard Bitcoin descriptor types
/// (`wsh`, `wpkh`, etc.), not the `ct()`/`elwsh()` extensions from
/// `elements-miniscript`. We strip the CT wrapper and replace `elwsh`
/// with `wsh` so the descriptor can be imported via `importdescriptors`.
fn extract_inner_wsh(ct_desc: &str) -> Option<String> {
    // Strip any trailing #checksum
    let body = ct_desc.split_once('#').map_or(ct_desc, |(b, _)| b);

    // Find the inner "elwsh(" or "wsh(" after "ct(slip77(...),"
    let inner_start = body.find("elwsh(").or_else(|| body.find("wsh("))?;
    // The inner descriptor runs to the matching close of the ct() wrapper,
    // which is the last ')' minus one (the ct close paren).
    let inner = &body[inner_start..body.len() - 1]; // strip trailing ')'
    // Replace elwsh → wsh for Elements Core compatibility.
    Some(inner.replace("elwsh(", "wsh("))
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd-length hex string".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
