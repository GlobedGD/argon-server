use axum::{
    Router,
    routing::{get, post},
};
use serde::Serialize;

use crate::{routes::util::rate_limited, state::AppState};

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

pub fn router(state: &AppState) -> Router<AppState> {
    let challenge_router = Router::new()
        .route("/challenge/start", post(challenge::start))
        .route("/challenge/restart", post(challenge::start))
        .route("/challenge/verify", post(challenge::poll))
        .route("/challenge/verifypoll", post(challenge::poll));

    let validation_router = Router::new()
        .route("/validation/check", get(validation::check))
        .route("/validation/check-many", post(validation::check_many))
        .route("/validation/check-strong", get(validation::check_strong))
        .route("/validation/check_strong", get(validation::check_strong))
        .route("/validation/check-strong-many", post(validation::check_strong_many))
        .route("/validation/check-data-many", post(validation::check_data_many));

    Router::new()
        .merge(rate_limited(challenge_router, state.clone(), 15, 3))
        .merge(rate_limited(validation_router, state.clone(), 10, 5))
        .route("/status", get(status::status))
}
