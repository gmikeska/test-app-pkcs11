//! Per-user Elements/Liquid wallet manager.
//!
//! Mirrors the Bitcoin [`WalletManager`](crate::wallet::WalletManager) but
//! delegates chain operations to the Elements daemon (watch-only descriptor
//! wallet) instead of BDK + Bitcoin Core. The HSMs sign PSET inputs
//! identically to the Bitcoin PSBT path.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use asterism_elements::descriptor::{CtDescriptorBuilder, CtKeyMode, to_multipath_string};
use asterism_elements::signer::ElementsSigner;
use asterism_elements::ElementsNetwork;
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
use crate::elements_rpc::{ElementsBalances, ElementsRpc, ElementsRpcError, ElementsUtxo, ImportDescriptorRequest};
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
    hsm: Arc<HsmFleet>,
    cache: AsyncMutex<HashMap<Uuid, Arc<UserElementsWallet>>>,
}

#[allow(dead_code)]
impl ElementsWalletManager {
    pub fn new(
        pool: PgPool,
        config: &AppConfig,
        hsm: Arc<HsmFleet>,
    ) -> Self {
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
            hsm,
            cache: AsyncMutex::new(HashMap::new()),
        }
    }

    pub fn network(&self) -> ElementsNetwork {
        self.network
    }

    fn derivation_path_for(&self, account_idx: u32) -> Result<bitcoin::bip32::DerivationPath, ElementsWalletError> {
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

    pub async fn load_or_init(&self, user_id: Uuid) -> Result<Arc<UserElementsWallet>, ElementsWalletError> {
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

    pub async fn ensure_wallet_for_user(&self, user_id: Uuid) -> Result<ElementsWalletRow, ElementsWalletError> {
        if let Some(row) = db::find_elements_wallet_for_user(&self.pool, user_id).await? {
            return Ok(row);
        }
        self.create_wallet_for_user(user_id).await
    }

    async fn create_wallet_for_user(&self, user_id: Uuid) -> Result<ElementsWalletRow, ElementsWalletError> {
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

        let mut builder = CtDescriptorBuilder::new(3, &mbk)
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
        let inner_multipath = extract_inner_wsh(&multipath)
            .ok_or_else(|| ElementsWalletError::Descriptor(
                "could not extract inner wsh() from CT descriptor".into(),
            ))?;
        let inner_receive = inner_multipath.replace("/<0;1>/*", "/0/*");
        let inner_change = inner_multipath.replace("/<0;1>/*", "/1/*");

        let daemon_wallet_name = format!("asterism-elements-user-{account_idx}");

        let rpc = self.rpc.clone();
        let wallet_name = daemon_wallet_name.clone();
        let mbk_for_blinding = mbk;
        let network = self.network;
        let ct_desc_clone = ct_desc.clone();
        tokio::task::spawn_blocking(move || -> Result<(), ElementsWalletError> {
            rpc.ensure_wallet_loaded(&wallet_name)?;

            // Import receive and change descriptors separately.
            for (desc, is_internal) in [(&inner_receive, false), (&inner_change, true)] {
                let info = rpc.get_descriptor_info(desc)?;
                let desc_with_checksum = format!("{desc}#{}", info.checksum);

                let results = rpc.import_descriptors(&wallet_name, &[
                    ImportDescriptorRequest {
                        descriptor: desc_with_checksum,
                        active: true,
                        internal: is_internal,
                    },
                ])?;
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

            // Import blinding keys for the first batch of receive addresses.
            let slip77_mbk = MasterBlindingKey::from(mbk_for_blinding);
            let secp = asterism_elements::elements_miniscript::elements::secp256k1_zkp::Secp256k1::new();
            for idx in 0..REVEAL_COUNT {
                if let Ok(definite) = ct_desc_clone.at_derivation_index(idx) {
                    let addr = match definite.address(&secp, network.address_params()) {
                        Ok(a) => a,
                        Err(e) => {
                            tracing::warn!(idx, error = %e, "skipping blinding key import");
                            continue;
                        }
                    };
                    let spk = definite.descriptor.script_pubkey();
                    let bk = slip77_mbk.blinding_private_key(&spk);
                    let bk_hex = hex_encode(&bk.secret_bytes());
                    if let Err(e) = rpc.import_blinding_key(&wallet_name, &addr.to_string(), &bk_hex) {
                        tracing::warn!(idx, error = %e, "importblindingkey failed");
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

        Ok(UserElementsWallet {
            user_id,
            wallet_id: row.id,
            account_idx: row.account_idx,
            network: self.network,
            descriptor: row.descriptor,
            daemon_wallet_name: row.daemon_wallet_name,
            signers: signers_arc,
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
    signers: crate::hsm::UserSigners,
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
        if count == 0 {
            return Ok(Vec::new());
        }

        // Derive confidential addresses locally from the CT descriptor
        // (Elements Core RPC doesn't understand ct()/elwsh() descriptors).
        let desc_str = self.descriptor.replace("/<0;1>/*", "/0/*");
        let ct_desc = asterism_elements::elements_miniscript::confidential::Descriptor::<
            asterism_elements::elements_miniscript::descriptor::DescriptorPublicKey,
        >::from_str(&desc_str)
            .map_err(|e| ElementsWalletError::Descriptor(e.to_string()))?;

        let secp = asterism_elements::elements_miniscript::elements::secp256k1_zkp::Secp256k1::new();
        let network = self.network;
        // Derive both confidential and unconfidential addresses.
        // Elements Core returns unconfidential addresses in listunspent
        // (since we import wsh() not ct()), so we need both forms for matching.
        let mut addr_pairs: Vec<(String, String)> = Vec::with_capacity(count as usize);
        for idx in 0..count {
            let definite = ct_desc
                .at_derivation_index(idx)
                .map_err(|e| ElementsWalletError::Descriptor(e.to_string()))?;
            let conf_addr = definite
                .address(&secp, network.address_params())
                .map_err(|e| ElementsWalletError::Descriptor(e.to_string()))?;
            let unconf_addr = elements::Address::from_script(
                &definite.descriptor.script_pubkey(),
                None,
                network.address_params(),
            );
            let unconf_str = unconf_addr
                .map(|a| a.to_string())
                .unwrap_or_default();
            addr_pairs.push((conf_addr.to_string(), unconf_str));
        }

        let rpc = self.rpc.clone();
        let wallet = self.daemon_wallet_name.clone();
        let utxos = tokio::task::spawn_blocking(move || rpc.list_unspent(&wallet))
            .await
            .expect("spawn_blocking join")?;

        let utxo_map = build_utxo_map(&utxos);

        let results = addr_pairs
            .into_iter()
            .enumerate()
            .map(|(i, (conf_addr, unconf_addr))| {
                let (received, unspent) = utxo_map
                    .get(conf_addr.as_str())
                    .or_else(|| utxo_map.get(unconf_addr.as_str()))
                    .copied()
                    .unwrap_or((0.0, 0.0));
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
        // Derive the unconfidential address to also match against, since
        // Elements Core returns unconfidential addresses in listunspent.
        let unconf = confidential_to_unconfidential(address, self.network);

        let rpc = self.rpc.clone();
        let wallet = self.daemon_wallet_name.clone();
        let addr = address.to_string();

        let (utxos, tip) = tokio::task::spawn_blocking(move || -> Result<_, ElementsWalletError> {
            let mut utxos = rpc.list_received_by_address(&wallet, &addr)?;
            if utxos.is_empty() {
                if let Some(ref uc) = unconf {
                    utxos = rpc.list_received_by_address(&wallet, uc)?;
                }
            }
            let tip = rpc.get_block_count()?;
            Ok((utxos, tip))
        })
        .await
        .expect("spawn_blocking join")?;

        let mut total_received = 0.0;
        let mut unspent = 0.0;
        let mut receipts = Vec::new();

        for utxo in &utxos {
            let amount = utxo.amount.unwrap_or(0.0);
            total_received += amount;
            let is_spent = !utxo.spendable;
            if !is_spent {
                unspent += amount;
            }
            receipts.push(ElementsAddressReceipt {
                txid: utxo.txid.clone(),
                vout: utxo.vout,
                amount,
                confirmations: utxo.confirmations,
                is_spent,
            });
        }

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

        let result = tokio::task::spawn_blocking(move || -> Result<_, ElementsWalletError> {
            // Step 1: Build unsigned PSET via Elements daemon.
            let outputs = vec![serde_json::json!({ recipient_owned.clone(): amount_btc })];
            let funded = rpc.wallet_create_funded_psbt(&wallet, &outputs, fee_rate_btc_kb)?;

            // Step 2: Decode PSET.
            let pset_bytes = BASE64.decode(funded.psbt.as_bytes())
                .map_err(|e| ElementsWalletError::PsetDecode(e.to_string()))?;
            let mut pset: Pset = consensus_deserialize(&pset_bytes)
                .map_err(|e| ElementsWalletError::PsetDecode(e.to_string()))?;

            // Step 3: Sign with all 3 HSMs.
            let mut total_signed = 0usize;
            for signer in &signers {
                let n = signer.sign_pset(&mut pset)
                    .map_err(|e| ElementsWalletError::Sign(e.to_string()))?;
                total_signed += n;
            }
            tracing::debug!(total_signed, "PSET signed by HSM federation");

            // Step 4: Serialize signed PSET back to base64.
            let signed_bytes = consensus_serialize(&pset);
            let signed_b64 = BASE64.encode(&signed_bytes);

            // Step 5: Finalize via Elements daemon.
            let finalized = rpc.finalize_psbt(&wallet, &signed_b64)?;
            if !finalized.complete {
                return Err(ElementsWalletError::Finalize(
                    "finalizepsbt returned complete=false".into(),
                ));
            }
            let raw_hex = finalized.hex.ok_or_else(|| {
                ElementsWalletError::Finalize("finalizepsbt returned no hex".into())
            })?;

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

fn build_utxo_map(utxos: &[ElementsUtxo]) -> HashMap<&str, (f64, f64)> {
    let mut map: HashMap<&str, (f64, f64)> = HashMap::new();
    for utxo in utxos {
        if let Some(addr) = utxo.address.as_deref() {
            let amount = utxo.amount.unwrap_or(0.0);
            let entry = map.entry(addr).or_insert((0.0, 0.0));
            entry.0 += amount;
            if utxo.spendable {
                entry.1 += amount;
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

fn confidential_to_unconfidential(address: &str, network: ElementsNetwork) -> Option<String> {
    let parsed = elements::Address::from_str(address).ok()?;
    let spk = parsed.script_pubkey();
    elements::Address::from_script(&spk, None, network.address_params())
        .map(|a| a.to_string())
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
