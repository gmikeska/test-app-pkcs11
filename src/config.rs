//! Process-wide configuration loaded from environment variables (a sibling
//! `.env` file is loaded by `dotenvy` at startup if present).
//!
//! Three groups of variables are required:
//!
//! - **Web/server.** `APP_HOST`, `APP_PORT`, `APP_SESSION_SECRET`,
//!   `DATABASE_URL`.
//! - **Bitcoin Core RPC.** `BITCOIN_RPC_*`, `BITCOIN_NETWORK`,
//!   `BITCOIN_WALLET_NAME`.
//! - **HSM federation.** `PKCS11_LIB`, three `APP_HSM_{1,2,3}_LABEL`/`_PIN`/
//!   `_SO_PIN` triples, and `APP_FED_THRESHOLD` (defaulted to 3).

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use asterism_elements::ElementsNetwork;
use bitcoin::Network;
use bitcoin::bip32::{ChildNumber, DerivationPath};

/// Configuration for one of the three federation HSM tokens.
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
    /// Path to `libasterism_dev_hsm.so` (or, in production, the vendor
    /// PKCS#11 library).
    pub pkcs11_library_path: PathBuf,
    /// The three token configs, in HSM index order (1, 2, 3 → indices 0,
    /// 1, 2).
    pub hsm_tokens: [HsmTokenConfig; 3],
    /// Federation threshold. Always 3 in v1; surfaced for templates.
    pub fed_threshold: u32,

    // -- Elements chain config --
    /// Elements daemon JSON-RPC base URL.
    pub elements_rpc_url: String,
    /// Elements daemon RPC username.
    pub elements_rpc_user: String,
    /// Elements daemon RPC password.
    pub elements_rpc_password: String,
    /// Elements network (liquid / liquidtestnet / elementsregtest).
    pub elements_network: ElementsNetwork,
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
            optional("BITCOIN_WALLET_NAME").unwrap_or_else(|| "asterism-pkcs11".to_string());

        let pkcs11_library_path = PathBuf::from(require("PKCS11_LIB")?);

        let hsm_tokens = [load_hsm_token(1)?, load_hsm_token(2)?, load_hsm_token(3)?];

        let fed_threshold: u32 = match optional("APP_FED_THRESHOLD") {
            Some(s) => s
                .parse()
                .map_err(|e: std::num::ParseIntError| ConfigError::Parse {
                    var: "APP_FED_THRESHOLD",
                    reason: e.to_string(),
                })?,
            None => 3,
        };
        if fed_threshold != 3 {
            return Err(ConfigError::Parse {
                var: "APP_FED_THRESHOLD",
                reason: format!("v1 only supports threshold = 3 (got {fed_threshold})"),
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
            pkcs11_library_path,
            hsm_tokens,
            fed_threshold,
            elements_rpc_url,
            elements_rpc_user,
            elements_rpc_password,
            elements_network,
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

fn load_hsm_token(idx: u32) -> Result<HsmTokenConfig, ConfigError> {
    let label_var: &'static str = Box::leak(format!("APP_HSM_{idx}_LABEL").into_boxed_str());
    let pin_var: &'static str = Box::leak(format!("APP_HSM_{idx}_PIN").into_boxed_str());
    let so_pin_var: &'static str = Box::leak(format!("APP_HSM_{idx}_SO_PIN").into_boxed_str());
    Ok(HsmTokenConfig {
        label: require(label_var)?,
        pin: require(pin_var)?,
        so_pin: require(so_pin_var)?,
    })
}

fn require(var: &'static str) -> Result<String, ConfigError> {
    std::env::var(var).map_err(|_| ConfigError::Missing { var })
}

fn optional(var: &'static str) -> Option<String> {
    std::env::var(var).ok().filter(|s| !s.is_empty())
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("odd-length hex string ({} chars)", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at byte {}: {e}", i / 2))
        })
        .collect()
}

/// Configuration loading errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A required environment variable was not set.
    #[error("required env var `{var}` is not set")]
    Missing {
        /// The variable name.
        var: &'static str,
    },
    /// A variable was set but failed to parse.
    #[error("env var `{var}` is invalid: {reason}")]
    Parse {
        /// The variable name.
        var: &'static str,
        /// Human-readable reason.
        reason: String,
    },
}
