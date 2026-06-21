//! Login / logout handlers.
//!
//! - `GET  /login`  — render the form.
//! - `POST /login`  — validate credentials, log the user in, redirect.
//! - `POST /logout` — clear the session and redirect to `/login`.

use std::sync::Arc;

use askama::Template;
use askama_web::WebTemplate;
use axum::Form;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use tower_sessions::Session;

use crate::auth;
use crate::db;
use crate::error::AppError;
use crate::state::AppState;

/// Login form body.
#[derive(Debug, Deserialize)]
pub struct LoginForm {
    /// Login email.
    pub email: String,
    /// Plaintext password.
    pub password: String,
}

/// Login page template.
#[derive(Template, WebTemplate)]
#[template(path = "login.html")]
struct LoginTemplate {
    /// Email value to prefill (e.g. after a failed submission).
    email: String,
    /// Optional error message to display above the form.
    error: Option<String>,
}

/// `GET /login`
///
/// # Errors
/// Propagates session/database/render errors as [`AppError`].
pub async fn login_get(
    State(state): State<Arc<AppState>>,
    session: Session,
) -> Result<Response, AppError> {
    if let Some(user) = auth::current_user(&session, &state.db)
        .await
        .map_err(map_lookup)?
    {
        tracing::debug!(user = %user.email, "already logged in, redirecting from /login");
        return Ok(Redirect::to("/").into_response());
    }
    Ok(LoginTemplate {
        email: String::new(),
        error: None,
    }
    .into_response())
}

/// `POST /login`
///
/// # Errors
/// Propagates DB/session/render errors as [`AppError`]. Bad credentials
/// re-render the login page with an error message.
pub async fn login_post(
    State(state): State<Arc<AppState>>,
    session: Session,
    Form(form): Form<LoginForm>,
) -> Result<Response, AppError> {
    let Some(user) = db::find_user_by_email(&state.db, &form.email).await? else {
        return Ok(LoginTemplate {
            email: form.email,
            error: Some("Invalid email or password.".into()),
        }
        .into_response());
    };

    let ok = auth::verify_password(&form.password, &user.password_hash)?;
    if !ok {
        return Ok(LoginTemplate {
            email: form.email,
            error: Some("Invalid email or password.".into()),
        }
        .into_response());
    }

    auth::log_in(&session, user.id).await?;
    tracing::info!(user = %user.email, "login ok");
    Ok(Redirect::to("/").into_response())
}

/// `POST /logout`
///
/// # Errors
/// Propagates session-store errors as [`AppError`].
pub async fn logout_post(session: Session) -> Result<Response, AppError> {
    auth::log_out(&session).await?;
    Ok(Redirect::to("/login").into_response())
}

fn map_lookup(e: auth::AuthLookupError) -> AppError {
    match e {
        auth::AuthLookupError::Session(e) => AppError::Session(e),
        auth::AuthLookupError::Sqlx(e) => AppError::Sqlx(e),
    }
}
