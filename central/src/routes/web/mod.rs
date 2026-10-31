use axum::Router;
use tower_http::services::ServeDir;

use crate::{config::AppConfig, state::AppState};

mod csrf;
mod dev;
mod flash;
mod html;
mod session;
mod user;

pub use html::Html;

pub fn router(state: &AppState, config: &AppConfig) -> Router<AppState> {
    Router::new()
        .nest_service("/assets", ServeDir::new(&config.web.assets_dir))
        .nest("/dev", dev::router(state, config))
        .merge(user::router(state, config))
}
