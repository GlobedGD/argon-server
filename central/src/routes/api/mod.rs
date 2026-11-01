use axum::{
    Router,
    routing::{get, post},
};
use utoipa::openapi::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{config::AppConfig, routes::util::rate_limited, state::AppState};

mod account;
mod check;
mod discord;
mod error;
pub mod openapi;
mod status;

pub type ApiError = error::Error;
pub type ApiResult<T> = Result<T, ApiError>;

fn account_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(account::login))
        .routes(routes!(account::verify))
        .routes(routes!(account::refresh))
        .routes(routes!(account::generate_web_token))
}

fn discord_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(discord::get_link_state))
        .routes(routes!(discord::unlink))
        .routes(routes!(discord::link))
        .routes(routes!(discord::sync))
        // keep the callback outside of /v2/ so it doesn't need to be updated whenever /v3/ is out
        .route("/oauth/discord/callback", get(discord::link_callback))
}

pub fn router(state: &AppState, config: &AppConfig) -> (Router<AppState>, OpenApi) {
    let (account_router, account_doc) = account_routes().split_for_parts();

    let (misc_router, misc_doc) = OpenApiRouter::new()
        // token validation (no rate limit, as already done by the extractor there)
        .routes(routes!(check::check))
        .routes(routes!(status::status))
        .split_for_parts();

    let mut router =
        Router::new().merge(rate_limited(account_router, state.clone(), 45, 10)).merge(misc_router);

    let mut doc = account_doc;
    doc.merge(misc_doc);

    // conditionally enable discord endpoints
    if config.discord.enabled {
        let (discord_router, discord_doc) = discord_routes().split_for_parts();

        router = router.merge(rate_limited(discord_router, state.clone(), 45, 10));
        doc.merge(discord_doc);
    }

    (router, doc)
}
