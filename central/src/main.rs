#![feature(duration_constructors, min_adt_const_params)]
#![allow(clippy::module_inception)]

use std::{env, net::SocketAddr};

use axum::{
    Router,
    extract::{DefaultBodyLimit, Request},
    middleware::Next,
    response::Response,
};
use tokio::net::TcpListener;
use tower_http::catch_panic::CatchPanicLayer;
use tracing::{debug, error, info};

use crate::{config::AppConfig, state::AppState};

pub mod challenge;
pub mod config;
pub mod db;
pub mod developer;
pub mod discord;
pub mod node_manager;
mod routes;
pub mod state;
pub mod token;
pub mod user;
pub mod util;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = match AppConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load configuration: {e}");
            std::process::exit(1);
        }
    };

    let _guard = shared::logging::init(&config.logging);
    let state = AppState::new(&config).await;

    maybe_cli(&config, &state).await?;

    let mut app =
        Router::new().merge(routes::api::router(&state, &config)).merge(routes::web::router(&state, &config));

    // enable legacy routes, if enabled in config
    if config.legacy.enabled {
        app = app.nest("/v1/", routes::api_legacy::router(&state))
    }

    let app = app
        .layer(DefaultBodyLimit::max(128 * 1024))
        .layer(CatchPanicLayer::new())
        .layer(axum::middleware::from_fn(log_middleware))
        .with_state(state.clone());

    // Run node manager
    tokio::spawn(state.node_manager.clone().run());

    // run maintenace tasks in bg
    tokio::spawn(state.clone().run_maintenance_tasks());

    info!("Starting HTTP server on {}", config.http.bind);

    let listener = TcpListener::bind(config.http.bind).await.unwrap();
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();

    Ok(())
}

async fn maybe_cli(_config: &AppConfig, state: &AppState) -> anyhow::Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        return Ok(());
    }

    match args[0].as_str() {
        "create-admin" => {
            if args.len() != 3 {
                error!("Usage: create-admin <username> <password>");
                std::process::exit(1);
            }

            let username = &args[1];
            let password = &args[2];

            let dev = state.developer_manager.create_admin(username, password).await?;
            info!("Created admin user: {} (id: {})", dev.username, dev.id);
        }

        _ => {
            error!("Unknown command: {}", args[0]);
        }
    }

    std::process::exit(0);
}

async fn log_middleware(req: Request, next: Next) -> Response {
    debug!(method = %req.method(), path = %req.uri().path(), "incoming request");
    next.run(req).await
}
