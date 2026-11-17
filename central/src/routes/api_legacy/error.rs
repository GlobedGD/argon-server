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
    #[error("argon verification is down")]
    StatusArgonDown,
    #[error("identity in token does not match the given user")]
    IdentityMismatch,
    #[error("too many users in request, maximum is 50")]
    TooManyUsersInRequest,
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
            Error::StatusArgonDown => StatusCode::NOT_ACCEPTABLE, // 406
            Error::TooManyUsersInRequest => StatusCode::BAD_REQUEST,
            Error::Api(e) => e.status_code(),
        };

        let body = axum::Json(serde_json::json!({
            "success": false,
            "error": self.to_string(),
        }));

        (status_code, body).into_response()
    }
}
