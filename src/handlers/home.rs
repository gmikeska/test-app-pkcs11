//! Homepage routing.
//!
//! - `GET /`       — `/login` if anonymous, `/wallet/receive` if logged in.
//! - `GET /wallet` — convenience redirect to `/wallet/receive`.

use std::sync::Arc;

use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use tower_sessions::Session;

use crate::auth;
use crate::error::AppError;
use crate::state::AppState;

/// `GET /`
///
/// # Errors
/// Surfaces session/DB lookup errors as [`AppError`].
pub async fn root(
    State(state): State<Arc<AppState>>,
    session: Session,
) -> Result<Response, AppError> {
    let user = match auth::current_user(&session, &state.db).await {
        Ok(Some(u)) => u,
        Ok(None) => return Ok(Redirect::to("/login").into_response()),
        Err(e) => {
            return Err(match e {
                auth::AuthLookupError::Session(e) => AppError::Session(e),
                auth::AuthLookupError::Sqlx(e) => AppError::Sqlx(e),
            });
        }
    };
    tracing::debug!(user = %user.email, "/ redirecting authenticated user to /wallet/receive");
    Ok(Redirect::to("/wallet/receive").into_response())
}

/// `GET /wallet` — redirect to `/wallet/receive`.
#[allow(clippy::unused_async)]
pub async fn wallet_root() -> Response {
    Redirect::to("/wallet/receive").into_response()
}

/// `GET /elements/wallet` — redirect to `/elements/wallet/receive`.
#[allow(clippy::unused_async)]
pub async fn elements_wallet_root() -> Response {
    Redirect::to("/elements/wallet/receive").into_response()
}
