//! Shared modules for `test-app-pkcs11`.
//!
//! The web server binary lives in `main.rs`; the example CLI tools
//! (`examples/federation_migration.rs`, etc.) import these modules
//! through the library crate.

pub mod auth;
pub mod config;
pub mod db;
pub mod elements_rpc;
pub mod elements_wallet;
pub mod error;
pub mod handlers;
pub mod hsm;
pub mod models;
pub mod state;
pub mod wallet;
