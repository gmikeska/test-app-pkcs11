//! `test-app-pkcs11` — Axum web app exercising `asterism-pkcs11` with
//! customer wallets backed by an m-of-n federation of emulated HSMs.
//!
//! Boot sequence:
//!
//! 1. Load `.env`, init tracing, build [`AppConfig`].
//! 2. Connect to `PostgreSQL`, run domain migrations.
//! 3. Initialise `tower-sessions` Postgres store + run its own migration.
//! 4. Seed the three test users (idempotent).
//! 5. Verify `PKCS11_LIB`, init discovered dev tokens (idempotent).
//! 6. Construct the [`WalletManager`].
//! 7. Eager-seed wallets for `test1/2/3`.
//! 8. Build the router and serve on `APP_HOST:APP_PORT`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use axum::Router;
use axum::routing::{get, post};
use sqlx::postgres::PgPoolOptions;
use time::Duration as TimeDuration;
use tokio::signal;
use tokio::task::AbortHandle;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tower_sessions::cookie::Key;
use tower_sessions::session_store::ExpiredDeletion;
use tower_sessions::{Expiry, SessionManagerLayer};
use tower_sessions_sqlx_store::PostgresStore;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

use test_app_pkcs11::config::AppConfig;
use test_app_pkcs11::elements_wallet::ElementsWalletManager;
use test_app_pkcs11::hsm::HsmFleet;
use test_app_pkcs11::state::AppState;
use test_app_pkcs11::wallet::WalletManager;
use test_app_pkcs11::{auth, db, handlers};

#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let env_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".env");
    let _ = dotenvy::from_path(env_path);

    init_tracing();

    let config = AppConfig::from_env()?;
    let fed_labels: Vec<&str> = config
        .fed_signer_indices
        .iter()
        .filter_map(|&i| config.hsm_tokens.get(i).map(|t| t.label.as_str()))
        .collect();
    tracing::info!(
        bind = %config.bind,
        network = %config.network,
        bip48_coin_index = config.bip48_coin_index,
        federation = %format!("{}-of-{}", config.fed_threshold, config.fed_signer_indices.len()),
        hsm_pool = config.hsm_tokens.len(),
        fed_signers = ?fed_labels,
        "starting test-app-pkcs11"
    );

    let pool = PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(StdDuration::from_secs(8))
        .connect(&config.database_url)
        .await?;

    db::migrate(&pool).await?;
    tracing::info!("domain schema migrated");

    auth::seed_test_users(&pool).await?;
    tracing::info!("test users seeded");

    let session_store = PostgresStore::new(pool.clone());
    session_store.migrate().await?;

    let deletion_task = tokio::task::spawn(
        session_store
            .clone()
            .continuously_delete_expired(StdDuration::from_mins(1)),
    );

    let cookie_key = Key::try_from(config.session_secret.as_slice())
        .map_err(|e| format!("APP_SESSION_SECRET cannot be used as cookie signing key: {e}"))?;
    let session_layer = SessionManagerLayer::new(session_store)
        .with_signed(cookie_key)
        .with_secure(false)
        .with_same_site(tower_sessions::cookie::SameSite::Lax)
        .with_expiry(Expiry::OnInactivity(TimeDuration::days(7)))
        .with_name("asterism_session");

    let hsm = Arc::new(HsmFleet::new(&config)?);
    tracing::info!(
        lib = %config.pkcs11_library_path.display(),
        "PKCS#11 fleet ready"
    );

    let wallet_manager = Arc::new(WalletManager::new(pool.clone(), &config, hsm.clone())?);
    tracing::info!(
        rpc = %config.bitcoin_rpc_url,
        wallet = %config.bitcoin_wallet_name,
        "Bitcoin Core RPC client ready"
    );

    let elements_wallet_manager = Arc::new(ElementsWalletManager::new(
        pool.clone(),
        &config,
        hsm.clone(),
    ));
    tracing::info!(
        rpc = %config.elements_rpc_url,
        network = %config.elements_network,
        "Elements RPC client ready"
    );

    // Eager-seed wallets for the three seeded users so the first request
    // is responsive (cryptoki BIP-32 derivation across 3 tokens for a
    // fresh user is several seconds).
    seed_test_wallets(&pool, &wallet_manager).await;
    seed_test_elements_wallets(&pool, &elements_wallet_manager).await;

    let state = Arc::new(AppState {
        config: config.clone(),
        db: pool,
        hsm,
        wallet_manager,
        elements_wallet_manager,
    });

    let static_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static");

    let app = Router::new()
        .route("/", get(handlers::home::root))
        .route("/wallet", get(handlers::home::wallet_root))
        .route(
            "/login",
            get(handlers::auth::login_get).post(handlers::auth::login_post),
        )
        .route("/logout", post(handlers::auth::logout_post))
        .route("/wallet/receive", get(handlers::wallet::receive))
        .route(
            "/wallet/send",
            get(handlers::wallet::send_get).post(handlers::wallet::send_post),
        )
        .route("/wallet/federation", get(handlers::wallet::federation))
        .route(
            "/wallet/addresses/{address}",
            get(handlers::wallet::address_show),
        )
        .route(
            "/wallet/transactions/{txid}",
            get(handlers::transactions::show),
        )
        // -- Elements wallet routes --
        .route(
            "/elements/wallet",
            get(handlers::home::elements_wallet_root),
        )
        .route(
            "/elements/wallet/receive",
            get(handlers::elements_wallet::receive),
        )
        .route(
            "/elements/wallet/send",
            get(handlers::elements_wallet::send_get).post(handlers::elements_wallet::send_post),
        )
        .route(
            "/elements/wallet/federation",
            get(handlers::elements_wallet::federation),
        )
        .route(
            "/elements/wallet/addresses/{address}",
            get(handlers::elements_wallet::address_show),
        )
        .route(
            "/elements/wallet/transactions/{txid}",
            get(handlers::elements_transactions::show),
        )
        .nest_service("/static", ServeDir::new(static_dir))
        .layer(TraceLayer::new_for_http())
        .layer(session_layer)
        .with_state(state);

    let addr: SocketAddr = config.bind;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "listening");

    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal(deletion_task.abort_handle()))
        .await?;

    match deletion_task.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!(error = %e, "session-deletion task ended with error"),
        Err(e) if e.is_cancelled() => {}
        Err(e) => tracing::warn!(error = %e, "session-deletion task join error"),
    }

    Ok(())
}

async fn seed_test_wallets(pool: &sqlx::PgPool, wallet_manager: &WalletManager) {
    const EMAILS: &[&str] = &[
        "test1@test.com",
        "test2@test.com",
        "test3@test.com",
        "admin@test.com",
    ];
    for email in EMAILS {
        let user = match db::find_user_by_email(pool, email).await {
            Ok(Some(u)) => u,
            Ok(None) => {
                tracing::warn!(%email, "seeded user missing during wallet eager-init");
                continue;
            }
            Err(e) => {
                tracing::warn!(%email, error = %e, "lookup failed during wallet eager-init");
                continue;
            }
        };
        let result = if *email == "admin@test.com" {
            wallet_manager.ensure_wallet_for_user_at(user.id, 99).await
        } else {
            wallet_manager.ensure_wallet_for_user(user.id).await
        };
        match result {
            Ok(row) => tracing::info!(
                %email,
                account_idx = row.account_idx,
                "eager-seeded user wallet"
            ),
            Err(e) => tracing::warn!(
                %email,
                error = %e,
                "failed to eager-seed user wallet (continuing — first request will retry)"
            ),
        }
    }
}

async fn seed_test_elements_wallets(pool: &sqlx::PgPool, manager: &ElementsWalletManager) {
    const EMAILS: &[&str] = &[
        "test1@test.com",
        "test2@test.com",
        "test3@test.com",
        "admin@test.com",
    ];
    for email in EMAILS {
        let user = match db::find_user_by_email(pool, email).await {
            Ok(Some(u)) => u,
            Ok(None) => {
                tracing::warn!(%email, "seeded user missing during Elements wallet eager-init");
                continue;
            }
            Err(e) => {
                tracing::warn!(%email, error = %e, "lookup failed during Elements wallet eager-init");
                continue;
            }
        };
        let result = if *email == "admin@test.com" {
            manager.ensure_wallet_for_user_at(user.id, 99).await
        } else {
            manager.ensure_wallet_for_user(user.id).await
        };
        match result {
            Ok(row) => tracing::info!(
                %email,
                account_idx = row.account_idx,
                "eager-seeded Elements user wallet"
            ),
            Err(e) => tracing::warn!(
                %email,
                error = %e,
                "failed to eager-seed Elements user wallet (continuing)"
            ),
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("test_app_pkcs11=debug,tower_http=info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(true))
        .init();
}

async fn shutdown_signal(deletion_abort: AbortHandle) {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("install ctrl_c handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutdown signal received");
    deletion_abort.abort();
}
