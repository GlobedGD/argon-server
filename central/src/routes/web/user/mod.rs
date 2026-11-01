use axum::{
    Router,
    response::Redirect,
    routing::{get, post},
};

use crate::{config::AppConfig, routes::util::rate_limited, state::AppState, util::SessionStoreAdapter};

mod account;
mod error;
mod session;

pub fn router(state: &AppState, config: &AppConfig) -> Router<AppState> {
    let session_layer = SessionStoreAdapter::new_layer(
        state.database.user_session_repository.clone(),
        config.web.session_expiry,
    )
    .with_name("argon_user");

    Router::new()
        .route("/", get(index))
        .route("/account", get(account::get_account))
        .route("/account/advanced-auth/enable", post(account::enable_advanced_auth))
        .route("/account/advanced-auth/rotate", post(account::rotate_advanced_auth))
        .route("/account/discord/link", post(account::link_discord))
        .route("/account/discord/unlink", post(account::unlink_discord))
        .route("/account/discord/sync", post(account::sync_discord))
        .route("/account/link-successful", get(account::link_successful))
        .route("/account/sync-successful", get(account::link_successful))
        // rate limit login
        .merge(rate_limited(Router::new().route("/login", get(account::get_login)), state.clone(), 30, 5))
        .route("/logout", post(account::logout))
        .layer(session_layer)
}

async fn index() -> Redirect {
    Redirect::to("/account")
}
