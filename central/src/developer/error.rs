use std::ops::RangeInclusive;

use axum::http::StatusCode;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiKeyError {
    #[error("Invalid API key")]
    InvalidKey,
    #[error("Database error: {0}")]
    DatabaseError(#[from] sea_orm::error::DbErr),
}

impl ApiKeyError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            ApiKeyError::InvalidKey => StatusCode::UNAUTHORIZED,
            ApiKeyError::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LoginError {
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Database error: {0}")]
    DatabaseError(#[from] sea_orm::error::DbErr),
}

const USERNAME_LENGTH_RANGE: RangeInclusive<usize> = 3..=64;
const PASSWORD_LENGTH_RANGE: RangeInclusive<usize> = 8..=256;

#[derive(Debug, Error)]
pub enum DevError {
    #[error("failed to hash password")]
    PwHashFailed,
    #[error("username must be between {} and {} characters", USERNAME_LENGTH_RANGE.start(), USERNAME_LENGTH_RANGE.end())]
    UsernameLength,
    #[error("password must be between {} and {} characters", PASSWORD_LENGTH_RANGE.start(), PASSWORD_LENGTH_RANGE.end())]
    PasswordLength,
    #[error("username is already taken")]
    UsernameTaken,
    #[error("developer was not found")]
    NotFound,
    #[error("login error: {0}")]
    Login(#[from] LoginError),
    #[error("Database error: {0}")]
    Database(#[from] sea_orm::error::DbErr),
}
