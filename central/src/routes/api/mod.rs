use axum::{
    Router,
    routing::{delete, get, post},
};

use crate::{config::AppConfig, routes::util::rate_limited, state::AppState};

mod account;
mod check;
mod discord;
mod error;
mod status;

pub type ApiError = error::Error;
pub type ApiResult<T> = Result<T, ApiError>;

pub fn router(state: &AppState, config: &AppConfig) -> Router<AppState> {
    let account_router = Router::new()
        .route("/v2/account/login", post(account::login))
        .route("/v2/account/login/verify", post(account::verify))
        .route("/v2/account/verify", post(account::verify)) // TODO: remove this on release
        .route("/v2/account/refresh", post(account::refresh))
        .route("/v2/account/webtoken", post(account::generate_web_token));

    let mut router = Router::new()
        // account
        .merge(rate_limited(account_router, state.clone(), 45, 10))
        // tokan validation (note: no rate limit, as already done by the extractor there)
        .route("/v2/token/validate", post(check::check))
        // misc
        .route("/v2/status", get(status::status));

    // conditionally enable discord endpoints
    if config.discord.enabled {
        let discord_router = Router::new()
            .route("/v2/account/discord", get(discord::get_link_state))
            .route("/v2/account/discord/link", post(discord::link))
            .route("/v2/account/discord", delete(discord::unlink))
            .route("/v2/account/discord/sync", post(discord::sync))
            // keep the callback outside of /v2/ so it doesn't need to be updated whenever /v3/ is out
            .route("/oauth/discord/callback", get(discord::link_callback));

        router = router.merge(rate_limited(discord_router, state.clone(), 45, 10));
    }

    router
}
