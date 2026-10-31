use axum::{
    Router,
    response::Redirect,
    routing::{get, post},
};

use crate::{config::AppConfig, state::AppState, util::SessionStoreAdapter};

mod account;
mod error;
mod session;

pub fn router(state: &AppState, config: &AppConfig) -> Router<AppState> {
    let session_layer = SessionStoreAdapter::new_layer(
        state.database.user_session_repository.clone(),
        config.web.session_expiry,
    );

    Router::new()
        .route("/", get(index))
        .route("/account", get(account::get_account))
        .route("/login", get(account::get_login))
        .route("/logout", post(account::logout))
        .layer(session_layer)
}

async fn index() -> Redirect {
    Redirect::to("/account")
}
