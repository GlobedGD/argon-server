use std::time::Instant;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

use crate::{
    challenge::ChallengeError,
    user::{TokenValidationError, UserManagerError},
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to start auth challenge: {0}")]
    ChallengeStart(#[from] ChallengeError),
    #[error("Database error: {0}")]
    Database(#[from] sea_orm::DbErr),
    #[error("Missing authorization header")]
    MissingAuth,
    #[error("Malformed authorization header")]
    MalformedAuth,
    #[error("Token validation failed: {0}")]
    InvalidToken(#[from] TokenValidationError),
    #[error("{0}")]
    ApiKeyDecode(#[from] crate::developer::ApiKeyError),
    #[error("Internal server error: {0}")]
    Internal(#[from] anyhow::Error),
    #[error("discord client error: {0}")]
    Discord(#[from] crate::discord::error::Error),
    #[error("rate limited")]
    RateLimited {
        until: std::time::Instant,
    },
    #[error("resource not found")]
    NotFound,
    #[error("invalid developer credentials")]
    InvalidCredentials,
    #[error("access to this resource is forbidden for your account")]
    Forbidden,
    #[error("bad redirect URL")]
    BadRedirectUrl,
    #[error("advanced auth is not enabled")]
    AdvancedAuthNotEnabled,
}

impl Error {
    pub fn error_code(&self) -> &'static str {
        match self {
            Error::Internal(_) => "internal_error",
            Error::Database(_) => "database_error",
            Error::MissingAuth => "missing_auth",
            Error::MalformedAuth => "malformed_auth",
            Error::InvalidToken(e) => e.error_code(),
            Error::ApiKeyDecode(_) => "api_key_error",
            Error::ChallengeStart(e) => e.error_code(),
            Error::Discord(e) => e.error_code(),
            Error::RateLimited { .. } => "rate_limited",
            Error::NotFound => "not_found",
            Error::InvalidCredentials => "invalid_credentials",
            Error::Forbidden => "forbidden",
            Error::BadRedirectUrl => "bad_redirect_url",
            Error::AdvancedAuthNotEnabled => "advanced_auth_not_enabled",
        }
    }

    pub fn status_code(&self) -> StatusCode {
        match self {
            Error::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::MissingAuth => StatusCode::UNAUTHORIZED,
            Error::MalformedAuth => StatusCode::BAD_REQUEST,
            Error::InvalidToken(e) => e.status_code(),
            Error::ApiKeyDecode(e) => e.status_code(),
            Error::ChallengeStart(e) => e.status_code(),
            Error::Discord(e) => e.status_code(),
            Error::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Error::NotFound => StatusCode::NOT_FOUND,
            Error::InvalidCredentials => StatusCode::UNAUTHORIZED,
            Error::Forbidden => StatusCode::FORBIDDEN,
            Error::BadRedirectUrl => StatusCode::BAD_REQUEST,
            Error::AdvancedAuthNotEnabled => StatusCode::FORBIDDEN,
        }
    }
}

impl From<UserManagerError> for Error {
    fn from(value: UserManagerError) -> Self {
        match value {
            UserManagerError::UserNotFound => Error::NotFound,
            UserManagerError::Database(e) => Error::Database(e),
            UserManagerError::Discord(e) => Error::Discord(e),
            UserManagerError::AdvancedAuthNotEnabled => Error::AdvancedAuthNotEnabled,
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let mut body = serde_json::json!({
            "error": self.to_string(),
            "code": self.error_code(),
        });

        if let Error::RateLimited { until } = &self {
            body["retry_after"] = serde_json::json!(until.duration_since(Instant::now()).as_secs_f64());
        }

        (self.status_code(), axum::Json(body)).into_response()
    }
}
