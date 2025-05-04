use std::io::Cursor;

use rocket::{
    Request, Response,
    http::{ContentType, Status},
    response::{self, Responder},
};
use serde_json::json;

pub struct ApiError {
    code: u16,
    message: String,
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
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

impl Responder<'_, 'static> for ApiError {
    fn respond_to(self, _request: &'_ Request<'_>) -> response::Result<'static> {
        let code = Status::from_code(self.code).unwrap_or(Status::BadRequest);

        let message = json!({
            "success": false,
            "error": self.message
        });

        let body = message.to_string();

        Response::build()
            .status(code)
            .header(ContentType::JSON)
            .sized_body(Some(body.len()), Cursor::new(body))
            .ok()
    }
}
