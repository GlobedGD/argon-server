use axum::Router;

use crate::{config::AppConfig, state::AppState, util::SessionStoreAdapter};

mod admin;
mod dashboard;
mod error;
mod session;

pub fn router(state: &AppState, config: &AppConfig) -> Router<AppState> {
    let session_layer = SessionStoreAdapter::new_layer(
        state.database.dev_session_repository.clone(),
        config.web.session_expiry,
    )
    .with_name("argon_dev");

    Router::new().merge(dashboard::router(state)).nest("/admin", admin::router()).layer(session_layer)
}
