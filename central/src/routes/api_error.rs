use std::io::Cursor;

use rocket::{
    Request, Response,
    http::{ContentType, Status},
    response::{self, Responder},
};
use serde_json::json;

use crate::api_token_manager::TokenFetchError;

pub struct ApiError<const JsonError: bool> {
    code: u16,
    message: String,
}

pub type ApiResult<T, const JsonError: bool> = Result<T, ApiError<JsonError>>;

impl<const JsonError: bool> ApiError<JsonError> {
    pub fn new(code: u16, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    #[allow(unused)]
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(401, message)
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(400, message)
    }

    #[allow(unused)]
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(403, message)
    }

    #[allow(unused)]
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(404, message)
    }

    pub fn not_acceptable(message: impl Into<String>) -> Self {
        Self::new(406, message)
    }

    pub fn too_many_requests(message: impl Into<String>) -> Self {
        Self::new(429, message)
    }

    pub fn internal_server_error(message: impl Into<String>) -> Self {
        Self::new(500, message)
    }
}

impl<const JsonError: bool> From<TokenFetchError> for ApiError<JsonError> {
    #[allow(unused)]
    fn from(value: TokenFetchError) -> Self {
        #[cfg(debug_assertions)]
        let err = Self::unauthorized(format!("invalid api token in authorization header: {value}"));
        #[cfg(not(debug_assertions))]
        let err = Self::unauthorized("invalid api token in authorization header");

        err
    }
}

impl<const JsonError: bool> Responder<'_, 'static> for ApiError<JsonError> {
    fn respond_to(self, _request: &'_ Request<'_>) -> response::Result<'static> {
        let code = Status::from_code(self.code).unwrap_or(Status::BadRequest);

        let body = if JsonError {
            json!({
                "success": false,
                "error": self.message
            })
            .to_string()
        } else {
            self.message
        };

        Response::build()
            .status(code)
            .header(if JsonError {
                ContentType::JSON
            } else {
                ContentType::Text
            })
            .sized_body(Some(body.len()), Cursor::new(body))
            .ok()
    }
}
