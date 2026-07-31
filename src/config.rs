//! Process-wide configuration loaded from environment variables (a sibling
//! `.env` file is loaded by `dotenvy` at startup if present).
//!
//! Three groups of variables are required:
//!
//! - **Web/server.** `APP_HOST`, `APP_PORT`, `APP_SESSION_SECRET`,
//!   `DATABASE_URL`.
//! - **Bitcoin Core RPC.** `BITCOIN_RPC_*`, `BITCOIN_NETWORK`,
//!   `BITCOIN_WALLET_NAME`.
//! - **HSM federation.** `PKCS11_LIB`, `APP_HSM_{N}_LABEL`/`_PIN`/`_SO_PIN`
//!   (scanned sequentially from N=1), and `APP_FED_THRESHOLD`.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use emvault::config::{hex_decode, optional, require};
use emvault::core::bitcoin::Network;
use emvault::core::bitcoin::bip32::{ChildNumber, DerivationPath};
use emvault::elements::ElementsNetwork;

// Re-exported so `crate::config::ConfigError` keeps resolving across the app
// (used via `#[from]` in `WalletError` and `ElementsWalletError`).
pub use emvault::config::ConfigError;

/// Configuration for a single federation HSM token.
#[derive(Clone, Debug)]
pub struct HsmTokenConfig {
    /// Human-readable token label. Doubles as the `SlotIdentifier::Label`
    /// resolved against `SoftHSM` at session-open time.
    pub label: String,
    /// User PIN.
    pub pin: String,
    /// Security-officer PIN (used by `init_dev_token`).
    pub so_pin: String,
}

/// Which chain backend the app syncs and broadcasts through.
///
/// Selected by `APP_CHAIN_BACKEND` (default `rpc`). The two Esplora modes share
/// one `APP_ESPLORA_URL`; they differ only in scan strategy (`Waterfalls` needs
/// an enterprise/QuickSync endpoint).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ChainBackend {
    /// Bitcoin Core JSON-RPC (`bdk_bitcoind_rpc::Emitter`).
    #[default]
    Rpc,
    /// Nodeless Esplora, address-based scan.
    Esplora,
    /// Nodeless Esplora, Waterfalls/QuickSync descriptor scan.
    Waterfalls,
}

impl FromStr for ChainBackend {
    type Err = ConfigError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "rpc" => Ok(Self::Rpc),
            "esplora" => Ok(Self::Esplora),
            "waterfalls" => Ok(Self::Waterfalls),
            other => Err(ConfigError::Parse {
                var: "APP_CHAIN_BACKEND",
                reason: format!("expected rpc|esplora|waterfalls, got `{other}`"),
            }),
        }
    }
}

/// Which backend the **Elements/Liquid** wallet syncs and broadcasts through.
///
/// Selected by `ELEMENTS_CHAIN_BACKEND` (default `rpc`). This app is the
/// full-coverage nodeless proving ground: all of Electrum, plain Esplora, and
/// the Esplora Waterfalls descriptor endpoint, plus the elementsd block-scan.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ElementsChainBackend {
    /// elementsd JSON-RPC block-scan (`emvault::elements::sync::BlockScanEngine`).
    #[default]
    Rpc,
    /// Descriptor-private Electrum backend (`emvault::elements::nodeless`),
    /// via `ELEMENTS_ELECTRUM_URL`.
    Electrum,
    /// Nodeless Esplora address-scan (`emvault::elements::nodeless`), via
    /// `ELEMENTS_ESPLORA_URL`.
    Esplora,
    /// Nodeless Esplora Waterfalls descriptor scan, via `ELEMENTS_ESPLORA_URL`.
    Waterfalls,
}

impl FromStr for ElementsChainBackend {
    type Err = ConfigError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "rpc" => Ok(Self::Rpc),
            "electrum" => Ok(Self::Electrum),
            "esplora" => Ok(Self::Esplora),
            "waterfalls" => Ok(Self::Waterfalls),
            other => Err(ConfigError::Parse {
                var: "ELEMENTS_CHAIN_BACKEND",
                reason: format!("expected rpc|electrum|esplora|waterfalls, got `{other}`"),
            }),
        }
    }
}

/// Top-level configuration.
#[derive(Clone, Debug)]
pub struct AppConfig {
    /// HTTP listen address.
    pub bind: SocketAddr,
    /// Session-cookie signing key (hex, decoded at startup).
    pub session_secret: Vec<u8>,
    /// Postgres connection string.
    pub database_url: String,
    /// Network the wallet operates on.
    pub network: Network,
    /// BIP-48 coin-type field — `0` for mainnet, `1` for testnet/signet/
    /// regtest, computed from `network` unless `APP_BIP48_COIN_INDEX`
    /// overrides it.
    pub bip48_coin_index: u32,
    /// Bitcoin Core JSON-RPC base URL, e.g. `http://127.0.0.1:18443`.
    pub bitcoin_rpc_url: String,
    /// Bitcoin Core RPC username.
    pub bitcoin_rpc_user: String,
    /// Bitcoin Core RPC password.
    pub bitcoin_rpc_password: String,
    /// Name passed to Bitcoin Core's `loadwallet` when needed.
    pub bitcoin_wallet_name: String,
    /// Which chain backend to sync/broadcast through (`APP_CHAIN_BACKEND`).
    pub chain_backend: ChainBackend,
    /// Esplora base URL (`APP_ESPLORA_URL`), required when `chain_backend` is an
    /// Esplora mode; ignored for `Rpc`.
    pub esplora_url: Option<String>,
    /// Path to `libemvault_dev_hsm.so` (or, in production, the vendor
    /// PKCS#11 library).
    pub pkcs11_library_path: PathBuf,
    /// Token configs, discovered sequentially from `APP_HSM_{1,2,...}_*`
    /// env vars at startup.
    pub hsm_tokens: Vec<HsmTokenConfig>,
    /// Federation threshold (m in m-of-n). Must satisfy `1 ≤ t ≤ n`.
    pub fed_threshold: u32,
    /// Zero-based indices into `hsm_tokens` for the default federation.
    /// When set, only these tokens participate in new wallet federations.
    /// The full HSM pool remains available for migration tools.
    pub fed_signer_indices: Vec<usize>,

    // -- Elements chain config --
    /// Elements daemon JSON-RPC base URL.
    pub elements_rpc_url: String,
    /// Elements daemon RPC username.
    pub elements_rpc_user: String,
    /// Elements daemon RPC password.
    pub elements_rpc_password: String,
    /// Elements network (liquid / liquidtestnet / elementsregtest).
    pub elements_network: ElementsNetwork,
    /// Which backend the Elements wallet syncs/broadcasts through
    /// (`ELEMENTS_CHAIN_BACKEND`, default `rpc`).
    pub elements_chain_backend: ElementsChainBackend,
    /// Electrum server URL for the Elements backend (`ELEMENTS_ELECTRUM_URL`,
    /// e.g. `tcp://10.44.0.1:60101`), required when `elements_chain_backend` is
    /// `Electrum`.
    pub elements_electrum_url: Option<String>,
    /// Esplora base URL for the Elements backend (`ELEMENTS_ESPLORA_URL`,
    /// e.g. `http://10.44.0.1:3102`), required when `elements_chain_backend` is
    /// `Esplora` or `Waterfalls`.
    pub elements_esplora_url: Option<String>,
}

impl AppConfig {
    /// Read configuration from process environment.
    ///
    /// # Errors
    /// Returns [`ConfigError`] if any required variable is missing or any
    /// value fails to parse.
    #[allow(clippy::too_many_lines)]
    pub fn from_env() -> Result<Self, ConfigError> {
        let host = require("APP_HOST")?;
        let port: u16 = require("APP_PORT")?
            .parse()
            .map_err(|e: std::num::ParseIntError| ConfigError::Parse {
                var: "APP_PORT",
                reason: e.to_string(),
            })?;
        let host_ip: IpAddr =
            host.parse()
                .map_err(|e: std::net::AddrParseError| ConfigError::Parse {
                    var: "APP_HOST",
                    reason: e.to_string(),
                })?;

        let secret_hex = require("APP_SESSION_SECRET")?;
        let session_secret = hex_decode(&secret_hex).map_err(|reason| ConfigError::Parse {
            var: "APP_SESSION_SECRET",
            reason,
        })?;
        if session_secret.len() < 64 {
            return Err(ConfigError::Parse {
                var: "APP_SESSION_SECRET",
                reason: format!(
                    "session secret must be at least 64 bytes (got {})",
                    session_secret.len()
                ),
            });
        }

        let database_url = require("DATABASE_URL")?;

        let network_str = require("BITCOIN_NETWORK")?;
        let network = Network::from_str(&network_str).map_err(|e| ConfigError::Parse {
            var: "BITCOIN_NETWORK",
            reason: e.to_string(),
        })?;

        let bip48_coin_index = match optional("APP_BIP48_COIN_INDEX") {
            Some(s) => s
                .parse()
                .map_err(|e: std::num::ParseIntError| ConfigError::Parse {
                    var: "APP_BIP48_COIN_INDEX",
                    reason: e.to_string(),
                })?,
            None => default_bip48_coin_index(network),
        };

        let rpc_host = require("BITCOIN_RPC_HOST")?;
        let rpc_port: u16 =
            require("BITCOIN_RPC_PORT")?
                .parse()
                .map_err(|e: std::num::ParseIntError| ConfigError::Parse {
                    var: "BITCOIN_RPC_PORT",
                    reason: e.to_string(),
                })?;
        let bitcoin_rpc_url = format!("http://{rpc_host}:{rpc_port}");
        let bitcoin_rpc_user = require("BITCOIN_RPC_USER")?;
        let bitcoin_rpc_password = require("BITCOIN_RPC_PASSWORD")?;
        let bitcoin_wallet_name =
            optional("BITCOIN_WALLET_NAME").unwrap_or_else(|| "emvault-pkcs11".to_string());

        let chain_backend = match optional("APP_CHAIN_BACKEND") {
            Some(s) => ChainBackend::from_str(&s)?,
            None => ChainBackend::default(),
        };
        let esplora_url = optional("APP_ESPLORA_URL");
        if matches!(
            chain_backend,
            ChainBackend::Esplora | ChainBackend::Waterfalls
        ) && esplora_url.as_deref().unwrap_or("").trim().is_empty()
        {
            return Err(ConfigError::Missing {
                var: "APP_ESPLORA_URL",
            });
        }

        let pkcs11_library_path = PathBuf::from(require("PKCS11_LIB")?);

        let hsm_tokens = discover_hsm_tokens()?;
        if hsm_tokens.is_empty() {
            return Err(ConfigError::Missing {
                var: "APP_HSM_1_LABEL",
            });
        }

        let n = u32::try_from(hsm_tokens.len()).unwrap_or(u32::MAX);
        let fed_threshold: u32 = match optional("APP_FED_THRESHOLD") {
            Some(s) => s
                .parse()
                .map_err(|e: std::num::ParseIntError| ConfigError::Parse {
                    var: "APP_FED_THRESHOLD",
                    reason: e.to_string(),
                })?,
            None => n,
        };
        let fed_signer_indices: Vec<usize> = match optional("APP_FED_SIGNERS") {
            Some(s) => {
                let mut indices = Vec::new();
                for part in s.split(',') {
                    let idx: usize =
                        part.trim().parse().map_err(|e: std::num::ParseIntError| {
                            ConfigError::Parse {
                                var: "APP_FED_SIGNERS",
                                reason: format!("invalid index \"{}\": {e}", part.trim()),
                            }
                        })?;
                    if idx == 0 || idx > hsm_tokens.len() {
                        return Err(ConfigError::Parse {
                            var: "APP_FED_SIGNERS",
                            reason: format!(
                                "signer index {idx} out of range (must be 1..={})",
                                hsm_tokens.len()
                            ),
                        });
                    }
                    indices.push(idx - 1);
                }
                if indices.is_empty() {
                    return Err(ConfigError::Parse {
                        var: "APP_FED_SIGNERS",
                        reason: "empty signer list".into(),
                    });
                }
                indices
            }
            None => (0..hsm_tokens.len()).collect(),
        };

        let fed_signer_count = u32::try_from(fed_signer_indices.len()).unwrap_or(u32::MAX);
        if fed_threshold < 1 || fed_threshold > fed_signer_count {
            return Err(ConfigError::Parse {
                var: "APP_FED_THRESHOLD",
                reason: format!(
                    "threshold must satisfy 1 ≤ t ≤ {fed_signer_count} (got {fed_threshold})"
                ),
            });
        }

        let elements_rpc_host = require("ELEMENTS_RPC_HOST")?;
        let elements_rpc_port: u16 =
            require("ELEMENTS_RPC_PORT")?
                .parse()
                .map_err(|e: std::num::ParseIntError| ConfigError::Parse {
                    var: "ELEMENTS_RPC_PORT",
                    reason: e.to_string(),
                })?;
        let elements_rpc_url = format!("http://{elements_rpc_host}:{elements_rpc_port}");
        let elements_rpc_user = require("ELEMENTS_RPC_USER")?;
        let elements_rpc_password = require("ELEMENTS_RPC_PASSWORD")?;
        let elements_network_str = require("ELEMENTS_NETWORK")?;
        let elements_network = match elements_network_str.as_str() {
            "liquid" => ElementsNetwork::Liquid,
            "liquidtestnet" => ElementsNetwork::LiquidTestnet,
            "elementsregtest" => ElementsNetwork::ElementsRegtest,
            other => {
                return Err(ConfigError::Parse {
                    var: "ELEMENTS_NETWORK",
                    reason: format!("expected liquid|liquidtestnet|elementsregtest, got `{other}`"),
                });
            }
        };

        let elements_chain_backend = match optional("ELEMENTS_CHAIN_BACKEND") {
            Some(s) => ElementsChainBackend::from_str(&s)?,
            None => ElementsChainBackend::default(),
        };
        let elements_electrum_url = optional("ELEMENTS_ELECTRUM_URL");
        if elements_chain_backend == ElementsChainBackend::Electrum
            && elements_electrum_url
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
        {
            return Err(ConfigError::Missing {
                var: "ELEMENTS_ELECTRUM_URL",
            });
        }
        let elements_esplora_url = optional("ELEMENTS_ESPLORA_URL");
        if matches!(
            elements_chain_backend,
            ElementsChainBackend::Esplora | ElementsChainBackend::Waterfalls
        ) && elements_esplora_url
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
        {
            return Err(ConfigError::Missing {
                var: "ELEMENTS_ESPLORA_URL",
            });
        }

        Ok(Self {
            bind: SocketAddr::new(host_ip, port),
            session_secret,
            database_url,
            network,
            bip48_coin_index,
            bitcoin_rpc_url,
            bitcoin_rpc_user,
            bitcoin_rpc_password,
            bitcoin_wallet_name,
            chain_backend,
            esplora_url,
            pkcs11_library_path,
            hsm_tokens,
            fed_threshold,
            fed_signer_indices,
            elements_rpc_url,
            elements_rpc_user,
            elements_rpc_password,
            elements_network,
            elements_chain_backend,
            elements_electrum_url,
            elements_esplora_url,
        })
    }

    /// Build the BIP-48 derivation path for `account_idx`:
    /// `m/48'/{coin}'/{account_idx}'/2'`.
    ///
    /// `wallet.rs` uses its own equivalent helper (it has the same
    /// arithmetic but maps errors into `WalletError` directly); this
    /// method is the canonical path-builder kept on `AppConfig` for
    /// future call-sites.
    ///
    /// # Errors
    /// Returns [`ConfigError::Parse`] if any `ChildNumber` rejects the
    /// supplied index (i.e. the index has the high bit set, which would
    /// overflow a hardened child number).
    #[allow(dead_code)]
    pub fn derivation_path_for(&self, account_idx: u32) -> Result<DerivationPath, ConfigError> {
        let parts = [
            hardened(48, "BIP-48 purpose")?,
            hardened(self.bip48_coin_index, "APP_BIP48_COIN_INDEX")?,
            hardened(account_idx, "account_idx")?,
            hardened(2, "BIP-48 script-type")?,
        ];
        Ok(DerivationPath::from(parts.to_vec()))
    }
}

fn default_bip48_coin_index(network: Network) -> u32 {
    u32::from(network != Network::Bitcoin)
}

#[allow(dead_code)] // used by AppConfig::derivation_path_for
fn hardened(index: u32, label: &'static str) -> Result<ChildNumber, ConfigError> {
    ChildNumber::from_hardened_idx(index).map_err(|e| ConfigError::Parse {
        var: label,
        reason: e.to_string(),
    })
}

fn discover_hsm_tokens() -> Result<Vec<HsmTokenConfig>, ConfigError> {
    let mut tokens = Vec::new();
    for idx in 1u32.. {
        let label_var: &'static str = Box::leak(format!("APP_HSM_{idx}_LABEL").into_boxed_str());
        let Some(label) = optional(label_var) else {
            break;
        };
        let pin_var: &'static str = Box::leak(format!("APP_HSM_{idx}_PIN").into_boxed_str());
        let so_pin_var: &'static str = Box::leak(format!("APP_HSM_{idx}_SO_PIN").into_boxed_str());
        tokens.push(HsmTokenConfig {
            label,
            pin: require(pin_var)?,
            so_pin: require(so_pin_var)?,
        });
    }
    Ok(tokens)
}

// `require`, `optional`, `hex_decode`, and `ConfigError` now live in
// `emvault::config` (imported above) — deduplicated in extraction phase E5b.
// The pkcs11-only `discover_hsm_tokens`, `hardened`, `derivation_path_for`, and
// `default_bip48_coin_index` helpers stay here (single-consumer).
