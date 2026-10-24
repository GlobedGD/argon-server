use axum::{
    Router,
    routing::{get, post},
};
use serde::Serialize;

use crate::state::AppState;

mod challenge;
mod error;
mod status;
mod validation;

type LegacyApiError = error::Error;
type LegacyApiResult<T> = Result<T, LegacyApiError>;

#[derive(Serialize)]
struct LegacyApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

impl<T> LegacyApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/challenge/start", post(challenge::start))
        .route("/challenge/restart", post(challenge::start))
        .route("/challenge/verify", post(challenge::poll))
        .route("/challenge/verifypoll", post(challenge::poll))
        .route("/validation/check", get(validation::check))
        .route("/validation/check-many", post(validation::check_many))
        .route("/validation/check-strong", get(validation::check_strong))
        .route("/validation/check-strong-many", post(validation::check_strong_many))
        .route("/validation/check-data-many", post(validation::check_data_many))
        .route("/status", get(status::status))
}
