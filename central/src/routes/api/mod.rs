use axum::{
    Router,
    routing::{get, post},
};

use crate::state::AppState;

mod account;
mod check;
mod discord;
mod error;
mod status;

pub type ApiError = error::Error;
pub type ApiResult<T> = Result<T, ApiError>;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/account/login", post(account::login))
        .route("/account/refresh", post(account::refresh))
        .route("/account/verify", post(account::verify))
        .route("/check", post(check::check))
        .route("/status", get(status::status))
}
