#![feature(let_chains)]

use argon_shared::{get_log_level, logger::*};
use async_watcher::{AsyncDebouncer, notify::RecursiveMode};
use config::ServerConfig;
use node_handler::NodeHandler;
use state::{ServerState, ServerStateData};
use std::{
    error::Error,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::io::AsyncWriteExt;

mod api_error;
mod config;
mod ip_blocker;
mod node_handler;
mod routes;
mod routes_util;
mod state;

fn abort_misconfig() -> ! {
    error!("aborting launch due to misconfiguration.");
    std::process::exit(1);
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
        file.write_all(include_bytes!("Rocket.toml.template")).await?;
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

    // start rocket

    let rocket = rocket::build()
        .mount("/v1/", routes::build_routes())
        .manage(state);

    rocket.launch().await?;

    Ok(())
}
