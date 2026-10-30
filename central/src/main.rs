#![feature(duration_constructors, min_adt_const_params)]
#![allow(clippy::module_inception)]

use std::{env, net::SocketAddr};

use axum::Router;
use tokio::net::TcpListener;
use tower_http::services::ServeDir;
use tracing::{error, info};

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

    let mut app = Router::new()
        .nest("/v2/", routes::api::router(&config))
        .merge(routes::web::router(&state, &config))
        .nest_service("/assets", ServeDir::new(&config.web.assets_dir))
        // keep the callback outside of /v2/ so it doesn't need to be updated whenever /v3/ is out
        .route("/oauth/discord/callback", routes::api::discord_oauth_callback());

    // enable legacy routes, if enabled in config
    if config.legacy.enabled {
        app = app.nest("/v1/", routes::api_legacy::router())
    }

    let app = app.with_state(state.clone());

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

    std::process::exit(1);
}
