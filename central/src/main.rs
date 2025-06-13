#![feature(let_chains, duration_constructors_lite, iterator_try_collect)]
#![allow(non_upper_case_globals)] // tbh

use argon_shared::{get_log_level, logger::*};
use async_watcher::{AsyncDebouncer, notify::RecursiveMode};
use config::ServerConfig;
use database::ArgonDbPool;
use node_handler::NodeHandler;
use rand::RngCore;
use rocket::{http::Method, routes};
use state::{ServerState, ServerStateData};
use std::{
    error::Error,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::io::AsyncWriteExt;

mod api_token_manager;
mod config;
mod database;
mod health_state;
mod ip_allowlist;
mod ip_blocker;
mod node_handler;
mod rate_limiter;
mod routes;
mod schema;
mod state;
mod token_issuer;

fn abort_misconfig() -> ! {
    error!("aborting launch due to misconfiguration.");
    std::process::exit(1);
}

fn gen_secret_key() -> String {
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

#[rocket::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // setup logger

    let write_to_file = std::env::var("ARGON_NO_FILE_LOG")
        .map(|p| p.parse::<i32>().unwrap())
        .unwrap_or(0)
        == 0;

    log::set_logger(Logger::instance("argon_server", write_to_file)).unwrap();

    if let Some(log_level) = get_log_level("ARGON_LOG_LEVEL") {
        log::set_max_level(log_level);
    } else {
        log::set_max_level(LogLevelFilter::Warn);
        error!("invalid value for the log level environment varaible");
        warn!("hint: possible values are 'trace', 'debug', 'info', 'warn', 'error', and 'none'.");
        abort_misconfig();
    }

    // create Rocket.toml if it doesn't exist
    let rocket_toml = std::env::var("ROCKET_CONFIG").map_or_else(
        |_| std::env::current_dir().unwrap().join("Rocket.toml"),
        PathBuf::from,
    );

    if rocket_toml.file_name().is_none_or(|x| x != "Rocket.toml")
        || !rocket_toml.parent().is_some_and(Path::exists)
    {
        error!("invalid value for ROCKET_CONFIG");
        warn!("hint: the filename must be 'Rocket.toml' and the parent folder must exist on the disk");
        abort_misconfig();
    }

    if !rocket_toml.exists() {
        info!("Creating a template Rocket.toml file");
        let mut file = tokio::fs::File::create(rocket_toml).await?;

        let data = include_str!("misc/Rocket.toml.template").to_owned();
        let data = data.replace("$$ROCKET_SECRET_KEY$$", &gen_secret_key());

        file.write_all(data.as_bytes()).await?;
    }

    // config file

    let mut config_path =
        std::env::var("ARGON_CONFIG_PATH").map_or_else(|_| std::env::current_dir().unwrap(), PathBuf::from);

    if config_path.is_dir() {
        config_path = config_path.join("config.json");
    }

    let config = if config_path.exists() && config_path.is_file() {
        match ServerConfig::load(&config_path) {
            Ok(x) => x,
            Err(err) => {
                error!("failed to open/parse configuration file: {err}");
                warn!(
                    "hint: if you don't have anything important there, delete the file for a new template to be created."
                );
                warn!("hint: the faulty configuration resides at: {config_path:?}");
                abort_misconfig();
            }
        }
    } else {
        info!("Configuration file does not exist by given path, creating a template one.");

        let conf = ServerConfig::default();
        conf.save(&config_path)?;

        conf
    };

    let handler_addr = if config.distributed_mode {
        match config.handler_address.parse::<SocketAddr>() {
            Ok(x) => Some(x),
            Err(err) => {
                error!("invalid address passed as the handler address: {err}");
                warn!("hint: this is the listen address of the TCP socket that manages argon nodes");
                warn!("hint: it should be in form ip:port, for example 0.0.0.0:4340");
                warn!(
                    "hint: this error happens because distributed mode is on, for simpler setup you can turn it off"
                );
                abort_misconfig();
            }
        }
    } else {
        None
    };

    // validate secret key

    let mut tmp_buf = [0u8; 32];
    if config.secret_key.len() != 64 || hex::decode_to_slice(&config.secret_key, &mut tmp_buf).is_err() {
        error!("failed to decode the secret key in the config file");
        warn!("hint: the key should be a hex-encoded 32-byte key");
        warn!("hint: one can be generated using `openssl rand -hex 32`");
        abort_misconfig();
    }

    // create state

    let ssd = ServerStateData::new(config_path.clone(), config);
    let state = ServerState::new(ssd);

    let node_handler = match NodeHandler::new(handler_addr, state.clone()).await {
        Ok(x) => x,
        Err(err) => {
            error!("failed to create node handler: {err}");
            warn!("hint: make sure that the port you are using is not already taken");
            if handler_addr.is_some_and(|x| x.port() < 1024) {
                warn!(
                    "hint: you are also using a privileged port, note that ports below 1024 can only be used by the superuser"
                );
            }

            warn!(
                "hint: this error happens because distributed mode is on, for simpler setup you can turn it off"
            );

            abort_misconfig();
        }
    };

    let node_handler = Arc::new(node_handler);
    state.state_write().await.node_handler = Some(node_handler);

    // config file watcher

    let (mut debouncer, mut file_events) =
        AsyncDebouncer::new_with_channel(Duration::from_secs(1), Some(Duration::from_secs(1))).await?;

    debouncer
        .watcher()
        .watch(&config_path, RecursiveMode::NonRecursive)?;

    let watcher_state = state.clone();
    tokio::spawn(async move {
        while let Some(_event) = file_events.recv().await {
            let mut state = watcher_state.state_write().await;
            let cpath = state.config_path.clone();
            match state.config.reload_in_place(&cpath) {
                Ok(()) => {
                    info!("Successfully reloaded the configuration");
                    state.notify_config_change().await;

                    // notify node handler about config change in another task
                    let nh = state.node_handler.clone().unwrap();
                    tokio::spawn(async move {
                        nh.notify_config_change().await;
                    });
                }

                Err(err) => {
                    warn!("Failed to reload configuration: {err}");
                }
            }
        }
    });

    // start the node handler

    let nh_state = state.clone();
    tokio::spawn(async move {
        let node_handler = nh_state.node_handler().await;
        node_handler.run().await.unwrap();
    });

    // start periodic state cleanup
    let cl_state = state.clone();
    tokio::spawn(async move {
        cl_state.run_cleanup_loop().await;
    });

    // start rocket
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://db.sqlite".to_owned());

    let mut rocket = rocket::build()
        .mount("/v1/", routes::build_routes())
        .mount("/", routes![routes::index])
        .manage(ArgonDbPool::from_url(&database_url).expect("Failed to initialize the database"));

    if std::env::var("ARGON_DISABLE_CORS").map_or(false, |x| x.parse::<i32>().unwrap_or(0) != 0) {
        warn!("CORS is disabled, this is not recommended for production use");
    } else {
        rocket = rocket.attach(
            rocket_cors::CorsOptions::default()
                .allowed_origins(rocket_cors::AllowedOrigins::all())
                .allowed_methods(
                    vec![
                        Method::Get,
                        Method::Post,
                        Method::Put,
                        Method::Delete,
                        Method::Options,
                    ]
                    .into_iter()
                    .map(From::from)
                    .collect(),
                )
                .allow_credentials(true)
                .to_cors()?,
        );
    }

    {
        let state = state.state_read().await;

        rocket = rocket
            .manage(state.health_state.clone())
            .manage(state.token_issuer.clone())
            .manage(state.ip_blocker.clone())
            .manage(state.rate_limiter.clone())
            .manage(state.api_token_manager.clone());
    }

    let rocket = rocket.manage(state);

    rocket.launch().await?;

    Ok(())
}
