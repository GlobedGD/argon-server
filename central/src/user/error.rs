use axum::http::StatusCode;
use thiserror::Error;

use crate::token::Scope;

#[derive(Debug, Error)]
pub enum TokenValidationError {
    #[error("token is missing a scope: {0}")]
    MissingScope(Scope),
    #[error("refresh token has expired due to epoch mismatch")]
    RefreshTokenExpired,
    #[error("legacy token is disallowed because the user has advanced auth enabled")]
    LegacyTokenNotAllowed,
    #[error("invalid token: {0}")]
    InvalidToken(#[from] jsonwebtoken::errors::Error),
    #[error("database error: {0}")]
    Database(#[from] sea_orm::DbErr),
}

impl TokenValidationError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::UNAUTHORIZED,
        }
    }

    pub fn error_code(&self) -> &'static str {
        match self {
            Self::MissingScope(_) => "missing_scope",
            Self::RefreshTokenExpired => "refresh_token_expired",
            Self::LegacyTokenNotAllowed => "legacy_token_not_allowed",
            Self::InvalidToken(_) => "invalid_token",
            Self::Database(_) => "database_error",
        }
    }

    pub fn is_token_issue(&self) -> bool {
        matches!(
            self,
            Self::MissingScope(_)
                | Self::RefreshTokenExpired
                | Self::LegacyTokenNotAllowed
                | Self::InvalidToken(_)
        )
    }
}
