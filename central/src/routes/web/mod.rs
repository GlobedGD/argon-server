use axum::{
    Router,
    response::Redirect,
    routing::{get, post},
};
use tower_http::services::ServeDir;
use tower_sessions::{Expiry, SessionManagerLayer};

use crate::{config::AppConfig, developer::DevSessionStore, state::AppState};

mod admin;
mod dashboard;
mod error;
mod user;
mod util;

pub fn router(state: &AppState, config: &AppConfig) -> Router<AppState> {
    let session_layer =
        SessionManagerLayer::new(DevSessionStore::new(state.database.dev_session_repository.clone()))
            .with_expiry(Expiry::OnInactivity(time::Duration::try_from(config.web.session_expiry).unwrap()))
            // insecure in debug
            .with_secure(!cfg!(debug_assertions));

    let dashboard_router = Router::new()
        .nest_service("/assets", ServeDir::new(&config.web.assets_dir))
        // General dashboard / login / logout
        .route("/dashboard", get(dashboard::get_dashboard))
        .route("/dashboard/login", get(dashboard::get_login))
        .route("/dashboard/login", post(dashboard::post_login))
        .route("/dashboard/logout", post(dashboard::post_logout))
        .route("/dashboard/setup", get(dashboard::setup))
        .route("/dashboard/setup", post(dashboard::post_setup))
        .route("/dashboard/password", get(dashboard::get_change_password))
        .route("/dashboard/password", post(dashboard::change_password))
        // Key management
        .route("/dashboard/keys/{id}/rotate", post(dashboard::rotate_key))
        // Admin dashboard
        .route("/dashboard/admin", get(admin::get_admin))
        .route("/dashboard/admin/developers", post(admin::create_developer))
        .route("/dashboard/admin/developers/{id}", get(admin::get_developer))
        .route("/dashboard/admin/developers/{id}/reset", post(admin::reset_developer_password))
        .route("/dashboard/admin/developers/{id}/delete", post(admin::delete_developer))
        .route("/dashboard/admin/developers/{id}/keys", post(admin::keys::create_key))
        .route("/dashboard/admin/developers/{id}/keys/{key_id}", get(admin::keys::get_key))
        .route("/dashboard/admin/developers/{id}/keys/{key_id}", post(admin::keys::edit_key))
        .route("/dashboard/admin/developers/{id}/keys/{key_id}/delete", post(admin::keys::delete_key))
        .route("/dashboard/admin/developers/{id}/keys/{key_id}/rotate", post(admin::keys::rotate_key))
        .layer(session_layer);

    let user_router = Router::new().route("/", get(index)).route("/account", get(user::get_account));

    Router::new().merge(dashboard_router).merge(user_router)
}

async fn index() -> Redirect {
    Redirect::to("/account")
}
