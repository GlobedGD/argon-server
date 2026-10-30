use askama::Template;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use thiserror::Error;
use tracing::{debug, error};

use crate::{
    developer::{DevError, LoginError},
    routes::web::util::Html,
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
            DevError::UsernameLength | DevError::PasswordLength | DevError::UsernameTaken => {
                Self::BadRequest(e.to_string())
            }
            DevError::PwHashFailed => Self::Internal(anyhow::Error::new(e)),
        }
    }
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        debug!("web error: {self:?}");

        match self {
            Self::NotLoggedIn => Redirect::to("/dashboard/login").into_response(),
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
#[template(path = "error.html")]
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
