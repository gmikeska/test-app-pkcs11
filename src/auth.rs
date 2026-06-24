//! Password hashing and login-session helpers.
//!
//! Mirrors `test-app-xpub::auth` — Argon2id PHC strings stored in the
//! `users` table, session state in `tower-sessions` Postgres backing.

use std::sync::Arc;

use argon2::Argon2;
use axum::extract::{FromRef, FromRequestParts, OptionalFromRequestParts};
use axum::http::request::Parts;
use axum::response::{IntoResponse, Redirect, Response};
use password_hash::rand_core::OsRng;
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use sqlx::PgPool;
use tower_sessions::Session;
use uuid::Uuid;

use crate::db;
use crate::models::UserRow;
use crate::state::AppState;

/// Session-storage key for the logged-in user's id.
pub const USER_ID_KEY: &str = "user_id";

/// Hash a plaintext password with Argon2id, producing a PHC-format string.
///
/// # Errors
/// Returns [`password_hash::Error`] if Argon2 fails.
pub fn hash_password(plain: &str) -> Result<String, password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(plain.as_bytes(), &salt)?
        .to_string();
    Ok(hash)
}

/// Verify a plaintext password against a stored PHC hash.
///
/// # Errors
/// Returns [`password_hash::Error`] if `hash_phc` is not a valid PHC string.
pub fn verify_password(plain: &str, hash_phc: &str) -> Result<bool, password_hash::Error> {
    let parsed = PasswordHash::new(hash_phc)?;
    match Argon2::default().verify_password(plain.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(password_hash::Error::Password) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Record `user_id` as the logged-in user on this session.
///
/// # Errors
/// Returns a [`tower_sessions::session::Error`] on session-store failure.
pub async fn log_in(
    session: &Session,
    user_id: Uuid,
) -> Result<(), tower_sessions::session::Error> {
    session.insert(USER_ID_KEY, user_id).await
}

/// Drop the session contents (logging the user out).
///
/// # Errors
/// Returns a [`tower_sessions::session::Error`] on session-store failure.
pub async fn log_out(session: &Session) -> Result<(), tower_sessions::session::Error> {
    session.flush().await
}

/// Resolve the currently logged-in user, if any.
///
/// # Errors
/// Returns [`AuthLookupError`] on session-store or DB failure.
pub async fn current_user(
    session: &Session,
    pool: &PgPool,
) -> Result<Option<UserRow>, AuthLookupError> {
    let user_id: Option<Uuid> = session.get(USER_ID_KEY).await?;
    let Some(user_id) = user_id else {
        return Ok(None);
    };
    Ok(db::find_user_by_id(pool, user_id).await?)
}

/// Errors raised by [`current_user`].
#[derive(Debug, thiserror::Error)]
pub enum AuthLookupError {
    /// Session-store error.
    #[error("session error: {0}")]
    Session(#[from] tower_sessions::session::Error),
    /// Database error.
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
}

/// Login-required extractor. Yields the current [`UserRow`] or short-
/// circuits with a `303 See Other` redirect to `/login`.
#[derive(Debug, Clone)]
pub struct AuthUser(pub UserRow);

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let session = Session::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;
        let app_state = Arc::<AppState>::from_ref(state);
        match current_user(&session, &app_state.db).await {
            Ok(Some(user)) => Ok(Self(user)),
            Ok(None) => Err(Redirect::to("/login").into_response()),
            Err(e) => {
                tracing::error!(error = %e, "AuthUser lookup failed");
                Err(Redirect::to("/login").into_response())
            }
        }
    }
}

/// Optional variant: `Option<AuthUser>` extractor that yields `None` for
/// anonymous visitors instead of redirecting.
impl<S> OptionalFromRequestParts<S> for AuthUser
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        let session = Session::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;
        let app_state = Arc::<AppState>::from_ref(state);
        match current_user(&session, &app_state.db).await {
            Ok(Some(user)) => Ok(Some(Self(user))),
            Ok(None) => Ok(None),
            Err(e) => {
                tracing::error!(error = %e, "AuthUser lookup failed");
                Ok(None)
            }
        }
    }
}

/// Seed the three test users (`test1..3@test.com`, password `test1234`).
/// Idempotent.
///
/// # Errors
/// Propagates database / hashing errors.
pub async fn seed_test_users(pool: &PgPool) -> Result<(), SeedError> {
    const TEST_PASSWORD: &str = "test1234";
    const EMAILS: &[&str] = &[
        "test1@test.com",
        "test2@test.com",
        "test3@test.com",
        "admin@test.com",
    ];

    for email in EMAILS {
        if db::find_user_by_email(pool, email).await?.is_some() {
            tracing::info!(%email, "test user already exists, skipping seed");
            continue;
        }
        let hash = hash_password(TEST_PASSWORD).map_err(|e| SeedError::Hash(e.to_string()))?;
        let inserted = db::upsert_user_if_absent(pool, email, &hash).await?;
        if inserted {
            tracing::info!(%email, "seeded test user");
        }
    }
    Ok(())
}

/// Errors raised by [`seed_test_users`].
#[derive(Debug, thiserror::Error)]
pub enum SeedError {
    /// Database error.
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
    /// Hash error.
    #[error("password hashing error: {0}")]
    Hash(String),
}
