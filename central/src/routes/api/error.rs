use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

use crate::{challenge::ChallengeError, user::TokenValidationError};

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to start auth challenge: {0}")]
    ChallengeStart(#[from] ChallengeError),
    #[error("Database error: {0}")]
    Database(#[from] sea_orm::DbErr),
    #[error("Missing or malformed authorization header")]
    MissingAuth,
    #[error("Token validation failed: {0}")]
    InvalidToken(#[from] TokenValidationError),
    #[error("Internal server error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl Error {
    pub fn error_code(&self) -> &'static str {
        match self {
            Error::Internal(_) => "internal_error",
            Error::Database(_) => "database_error",
            Error::MissingAuth => "missing_auth",
            Error::InvalidToken(e) => e.error_code(),
            Error::ChallengeStart(e) => e.error_code(),
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status_code = match &self {
            Error::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::MissingAuth => StatusCode::UNAUTHORIZED,
            Error::InvalidToken(e) => e.status_code(),
            Error::ChallengeStart(e) => e.status_code(),
        };

        let body = axum::Json(serde_json::json!({
            "error": self.to_string(),
            "code": self.error_code(),
        }));

        (status_code, body).into_response()
    }
}
