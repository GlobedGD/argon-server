use askama::Template;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use thiserror::Error;
use tracing::{debug, error};

use crate::routes::web::{Html, session::SessionError};

#[derive(Debug, Error)]
pub enum WebError {
    #[error("not logged in")]
    NotLoggedIn,
    #[error("access code expired")]
    AccessCodeExpired,
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

impl From<SessionError> for WebError {
    fn from(e: SessionError) -> Self {
        match e {
            SessionError::Session(e) => Self::Session(e),
            SessionError::Csrf => Self::Csrf,
        }
    }
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        debug!("web error: {self:?}");

        match self {
            Self::NotLoggedIn => Redirect::to("/login").into_response(),
            Self::AccessCodeExpired => {
                render_error(StatusCode::UNAUTHORIZED, "Access code expired, please try to log in again")
            }
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
