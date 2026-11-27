use askama::Template;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use thiserror::Error;
use tracing::{debug, error};

use crate::{
    developer::{DevError, LoginError},
    routes::web::{Html, flash::Flash, session::SessionError},
    user::UserManagerError,
};

#[derive(Debug, Error)]
pub enum WebError {
    #[error("not logged in")]
    NotLoggedIn,
    #[error("invalid login credentials")]
    InvalidCredentials,
    #[error("forbidden")]
    Forbidden,
    #[error("database error: {0}")]
    Database(#[from] sea_orm::DbErr),
    #[error("session management error: {0}")]
    Session(#[from] tower_sessions::session::Error),
    #[error("CSRF token verification failed")]
    Csrf,
    #[error("page not found")]
    NotFound,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

pub type WebResult<T> = Result<T, WebError>;

impl From<DevError> for WebError {
    fn from(e: DevError) -> Self {
        match e {
            DevError::Database(e) | DevError::Login(LoginError::DatabaseError(e)) => Self::Database(e),
            DevError::Login(LoginError::InvalidCredentials) => Self::InvalidCredentials,
            DevError::NotFound => Self::NotFound,
            DevError::UsernameLength
            | DevError::PasswordLength
            | DevError::UsernameTaken
            | DevError::UsernameInvalidChars => Self::BadRequest(e.to_string()),
            DevError::PwHashFailed => Self::Internal(anyhow::Error::new(e)),
        }
    }
}

impl From<SessionError> for WebError {
    fn from(e: SessionError) -> Self {
        match e {
            SessionError::Session(e) => Self::Session(e),
            SessionError::Csrf => Self::Csrf,
        }
    }
}

impl From<UserManagerError> for WebError {
    fn from(value: UserManagerError) -> Self {
        match value {
            UserManagerError::UserNotFound => WebError::NotFound,
            UserManagerError::Database(e) => WebError::Database(e),
            UserManagerError::Discord(e) => WebError::Internal(anyhow::anyhow!("Discord error: {e}")),
            UserManagerError::AdvancedAuthNotEnabled => {
                WebError::BadRequest("Advanced auth is not enabled".to_owned())
            }
        }
    }
}

/// Turns a developer-domain error into a user-facing flash, or a fatal web error
/// if there is nothing useful to show the user.
pub fn flash_from_dev_error(e: DevError) -> Result<Flash, WebError> {
    match e {
        DevError::UsernameLength
        | DevError::PasswordLength
        | DevError::UsernameTaken
        | DevError::UsernameInvalidChars
        | DevError::Login(LoginError::InvalidCredentials)
        | DevError::NotFound => Ok(Flash::error(e.to_string())),
        DevError::PwHashFailed | DevError::Database(_) | DevError::Login(_) => Err(e.into()),
    }
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        debug!("web error: {self:?}");

        match self {
            Self::NotLoggedIn => Redirect::to("/dev/login").into_response(),
            Self::InvalidCredentials => render_error(StatusCode::UNAUTHORIZED, "Invalid login credentials"),
            Self::BadRequest(msg) => render_error(StatusCode::BAD_REQUEST, msg),
            Self::Csrf => render_error(StatusCode::FORBIDDEN, "CSRF verification failed, please try again"),
            Self::Forbidden => render_error(StatusCode::FORBIDDEN, "Forbidden"),
            Self::NotFound => render_error(StatusCode::NOT_FOUND, "Page not found"),

            Self::Database(_) | Self::Session(_) | Self::Internal(_) => {
                error!("Error handling request: {self:?}");
                render_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
        }
    }
}

#[derive(Template)]
#[template(path = "dev/error.html")]
struct ErrorTemplate<'a> {
    error: &'a str,
}

pub fn render_error(code: StatusCode, msg: impl AsRef<str>) -> Response {
    (
        code,
        Html(ErrorTemplate {
            error: msg.as_ref(),
        }),
    )
        .into_response()
}
