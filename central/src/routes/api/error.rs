use std::time::Instant;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

use crate::{
    challenge::ChallengeError,
    developer::DevScope,
    user::{TokenValidationError, UserManagerError},
};

#[derive(Serialize, utoipa::ToSchema)]
pub struct ErrorBody {
    pub error: String,
    /// Code of the error that's expected to be stable, unlike `error`
    pub code: String,
    /// How many seconds until the request should be retried, present in 429 responses
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(ignore)]
    pub retry_after: Option<f64>,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to start auth challenge: {0}")]
    ChallengeStart(#[from] ChallengeError),
    #[error("Database error: {0}")]
    Database(#[from] sea_orm::DbErr),
    #[error("Missing authorization header")]
    MissingAuth,
    #[error("API key is missing a scope that is required for this endpoint: {0}")]
    MissingDevScope(DevScope),
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
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("advanced auth is not enabled")]
    AdvancedAuthNotEnabled,
}

impl Error {
    pub fn error_code(&self) -> &'static str {
        match self {
            Error::Internal(_) => "internal_error",
            Error::Database(_) => "database_error",
            Error::MissingAuth => "missing_auth",
            Error::MissingDevScope(_) => "missing_api_key_scope",
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
            Error::BadRequest(_) => "bad_request",
            Error::AdvancedAuthNotEnabled => "advanced_auth_not_enabled",
        }
    }

    pub fn status_code(&self) -> StatusCode {
        match self {
            Error::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::MissingAuth => StatusCode::UNAUTHORIZED,
            Error::MissingDevScope(_) => StatusCode::FORBIDDEN,
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
            Error::BadRequest(_) => StatusCode::BAD_REQUEST,
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
        let body = ErrorBody {
            retry_after: match &self {
                Error::RateLimited { until } => Some(until.duration_since(Instant::now()).as_secs_f64()),
                _ => None,
            },
            code: self.error_code().to_owned(),
            error: self.to_string(),
        };

        (self.status_code(), axum::Json(body)).into_response()
    }
}
