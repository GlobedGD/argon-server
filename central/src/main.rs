#![feature(duration_constructors)]
#![allow(clippy::module_inception)]

use std::net::SocketAddr;

use axum::Router;
use tokio::net::TcpListener;
use tracing::info;

use crate::{config::AppConfig, state::AppState};

pub mod challenge;
pub mod config;
pub mod db;
pub mod node_manager;
mod routes;
pub mod state;
pub mod token;
pub mod user;
pub mod util;

#[tokio::main]
async fn main() {
    let config = match AppConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load configuration: {e}");
            std::process::exit(1);
        }
    };

    let _guard = shared::logging::init(&config.logging);
    let state = AppState::new(&config).await;

    let app = Router::new()
        .nest("/v2/", routes::api::router())
        .nest("/v1/", routes::api_legacy::router())
        .with_state(state.clone());

    // Run node manager
    tokio::spawn(state.node_manager.clone().run());

    // run maintenace tasks in bg
    tokio::spawn(state.clone().run_maintenance_tasks());

    info!("Starting HTTP server on {}", config.http.bind);

    let listener = TcpListener::bind(config.http.bind).await.unwrap();
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}

// TODO:
// 1. rate limits for things, api keys get better limits defined in db
