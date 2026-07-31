//! Live balance WebSocket (`GET /ws`).
//!
//! Demonstrate receipt of a payment with **no page reload and no user
//! intervention**: when a browser on a wallet page opens this socket, the server
//! pushes the current balance whenever it changes and the client updates the
//! balance card in place.
//!
//! Two drive modes:
//! - **Electrum (P5, event-driven):** the session subscribes its revealed scripts
//!   to the shared [`WatchPool`]; an electrs status change wakes the socket, which
//!   re-syncs and pushes. Near-instant, no busy polling.
//! - **Other backends (fallback):** a short timer re-syncs and pushes on change.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use emvault::core::bitcoin::ScriptBuf;
use emvault::core::electrum::WatchPool;
use tokio::sync::broadcast::error::RecvError;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::handlers::wallet::BalanceView;
use crate::state::AppState;
use crate::wallet::UserWallet;

/// Re-sync cadence for the non-electrum fallback path.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// `GET /ws` — upgrade to a per-session live-balance WebSocket. Auth is enforced
/// by the [`AuthUser`] extractor (unauthenticated upgrades never reach here).
// axum handlers are `async` by contract; the upgrade itself is synchronous.
#[allow(clippy::unused_async)]
pub async fn ws(
    State(state): State<Arc<AppState>>,
    AuthUser(user): AuthUser,
    upgrade: WebSocketUpgrade,
) -> Response {
    upgrade.on_upgrade(move |socket| drive(socket, state, user.id))
}

/// Build the JSON pushed to the client for a balance snapshot.
fn balance_payload(view: &BalanceView) -> String {
    serde_json::json!({
        "type": "balance",
        "total": view.total_btc,
        "spendable": view.spendable_btc,
        "confirmed": view.confirmed_btc,
        "trusted_pending": view.trusted_pending_btc,
        "untrusted_pending": view.untrusted_pending_btc,
        "immature": view.immature_btc,
        "has_pending": view.has_pending,
    })
    .to_string()
}

/// Sync (best-effort) and push the balance if it changed since `last_sent`.
/// Returns `Err(())` only if the socket send failed (caller should stop).
async fn sync_and_push(
    socket: &mut WebSocket,
    wallet: &UserWallet,
    last_sent: &mut Option<String>,
) -> Result<(), ()> {
    // A transient backend hiccup shouldn't kill the socket — retry next wake.
    if let Err(e) = wallet.sync().await {
        tracing::debug!(error = %e, "ws balance sync failed (will retry)");
        return Ok(());
    }
    let payload = balance_payload(&BalanceView::from(wallet.balance().await));
    if last_sent.as_deref() != Some(payload.as_str()) {
        socket
            .send(Message::Text(payload.clone().into()))
            .await
            .map_err(|_| ())?;
        *last_sent = Some(payload);
    }
    Ok(())
}

/// Route to the event-driven (electrum) or polled (fallback) loop.
async fn drive(socket: WebSocket, state: Arc<AppState>, user_id: Uuid) {
    let Ok(wallet) = state.wallet_manager.load_or_init(user_id).await else {
        return;
    };
    match state.wallet_manager.watch_pool() {
        Some(pool) => drive_watched(socket, &wallet, pool).await,
        None => drive_polled(socket, &wallet).await,
    }
}

/// Event-driven loop: subscribe the session's revealed scripts to the shared
/// [`WatchPool`] and push on each relevant electrs status change. Unwatches on
/// exit (ref-counted, so shared addresses stay subscribed for other sessions).
async fn drive_watched(mut socket: WebSocket, wallet: &UserWallet, pool: Arc<WatchPool>) {
    let scripts: Vec<ScriptBuf> = wallet.watched_scripts().await;
    let watched: HashSet<ScriptBuf> = scripts.iter().cloned().collect();
    for spk in &scripts {
        if let Err(e) = pool.watch(spk).await {
            tracing::debug!(error = %e, "ws watch subscribe failed");
        }
    }

    let mut updates = pool.updates();
    let mut last_sent: Option<String> = None;
    // Initial snapshot on connect.
    let mut alive = sync_and_push(&mut socket, wallet, &mut last_sent)
        .await
        .is_ok();

    while alive {
        tokio::select! {
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                Some(Ok(_)) => {}
            },
            update = updates.recv() => match update {
                // A watched address changed status → re-sync + push.
                Ok(u) if watched.contains(&u.script) => {
                    alive = sync_and_push(&mut socket, wallet, &mut last_sent).await.is_ok();
                }
                Ok(_) => {} // another session's address; ignore.
                // Fell behind the broadcast buffer — reconcile with a fresh sync.
                Err(RecvError::Lagged(_)) => {
                    alive = sync_and_push(&mut socket, wallet, &mut last_sent).await.is_ok();
                }
                Err(RecvError::Closed) => break,
            },
        }
    }

    for spk in &scripts {
        if let Err(e) = pool.unwatch(spk).await {
            tracing::debug!(error = %e, "ws unwatch failed");
        }
    }
}

/// Fallback loop for non-electrum backends: re-sync on a short timer and push on
/// change. Exits when the client disconnects.
async fn drive_polled(mut socket: WebSocket, wallet: &UserWallet) {
    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    let mut last_sent: Option<String> = None;
    loop {
        tokio::select! {
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                Some(Ok(_)) => {}
            },
            _ = ticker.tick() => {
                if sync_and_push(&mut socket, wallet, &mut last_sent).await.is_err() {
                    break;
                }
            }
        }
    }
}
