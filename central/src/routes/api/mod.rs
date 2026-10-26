use axum::{
    Router,
    routing::{MethodRouter, delete, get, post},
};

use crate::{config::AppConfig, state::AppState};

mod account;
mod check;
mod discord;
mod error;
mod status;

pub type ApiError = error::Error;
pub type ApiResult<T> = Result<T, ApiError>;

pub fn router(config: &AppConfig) -> Router<AppState> {
    let mut router = Router::new()
        .route("/account/login", post(account::login))
        .route("/account/login/verify", post(account::verify))
        .route("/account/verify", post(account::verify)) // TODO: remove this on release
        .route("/account/refresh", post(account::refresh))
        .route("/token/validate", post(check::check))
        .route("/status", get(status::status));

    // conditionally enable discord endpoints
    if config.discord.enabled {
        router = router
            .route("/account/discord", get(discord::get_link_state))
            .route("/account/discord/link", post(discord::link))
            .route("/account/discord", delete(discord::unlink))
            .route("/account/discord/sync", post(discord::sync));
    }

    router
}

pub fn discord_oauth_callback() -> MethodRouter<AppState> {
    get(discord::link_callback)
}
