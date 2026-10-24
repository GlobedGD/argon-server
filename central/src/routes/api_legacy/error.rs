use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

use crate::{challenge::ChallengeError, routes::api::ApiError, user::TokenValidationError};

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Api(#[from] ApiError),
    #[error("unsupported challenge type")]
    UnsupportedChallengeType,
    #[error("identity in token does not match the given user")]
    IdentityMismatch,
}

impl From<ChallengeError> for Error {
    fn from(err: ChallengeError) -> Self {
        ApiError::from(err).into()
    }
}

impl From<TokenValidationError> for Error {
    fn from(err: TokenValidationError) -> Self {
        ApiError::from(err).into()
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status_code = match &self {
            Error::UnsupportedChallengeType => StatusCode::BAD_REQUEST,
            Error::IdentityMismatch => StatusCode::UNAUTHORIZED,
            Error::Api(e) => e.status_code(),
        };

        let body = axum::Json(serde_json::json!({
            "success": false,
            "error": self.to_string(),
        }));

        (status_code, body).into_response()
    }
}
