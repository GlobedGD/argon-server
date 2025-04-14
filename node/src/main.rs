#![feature(let_chains, duration_constructors)]

mod gd_client;
mod state;
mod worker;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use argon_shared::{get_log_level, logger::*};
use state::NodeState;

fn abort_misconfig() -> ! {
    error!("aborting launch due to misconfiguration.");
    std::process::exit(1);
}

fn get_next_arg(args: &mut std::env::Args) -> String {
    args.next().unwrap_or_else(|| {
        error!("missing argument, aborting launch.");
        let exe = std::env::current_exe().unwrap_or_default();
        let exe_name = exe.file_name().unwrap_or_default().to_string_lossy();
        warn!("usage: {exe_name} <server_address> <password>");
        std::process::exit(1);
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // setup logger

    let write_to_file = std::env::var("ARGON_NODE_NO_FILE_LOG")
        .map(|p| p.parse::<i32>().unwrap())
        .unwrap_or(0)
        == 0;

    log::set_logger(Logger::instance("argon_node", write_to_file)).unwrap();

    if let Some(log_level) = get_log_level("ARGON_NODE_LOG_LEVEL") {
        log::set_max_level(log_level);
    } else {
        log::set_max_level(LogLevelFilter::Warn);
        error!("invalid value for the log level environment varaible");
        warn!("hint: possible values are 'trace', 'debug', 'info', 'warn', 'error', and 'none'.");
        abort_misconfig();
    }

    let mut args = std::env::args();
    args.next().unwrap();

    let server_addr = get_next_arg(&mut args);
    let server_addr = match server_addr.parse::<SocketAddr>() {
        Ok(x) => x,
        Err(e) => {
            error!("invalid server address provided: {e}");
            warn!("hint: it should NOT be an HTTP address, but the node handler address");
            warn!("hint: the address should be in format ip:port, for example 127.0.0.1:4340");
            warn!("hint: IPv6 addresses are also allowed");
            abort_misconfig();
        }
    };

    let password = get_next_arg(&mut args);

    let state = Arc::new(NodeState::new());

    match state.try_connect(server_addr, &password).await {
        Ok(()) => {}
        Err(e) => {
            error!("connection failed: {e}");
            warn!("hint: ensure the server address and password are correct");
            warn!(
                "hint: ensure you are putting address and port of the node handler, not the HTTP server"
            );
            abort_misconfig();
        }
    }

    info!("Successfully connected to the central server, starting the worker loop");

    let state_clone = state.clone();
    tokio::spawn(async move {
        if let Err(err) = state_clone.run_loop().await {
            error!("Worker loop terminated due to error: {err}");

            match tokio::time::timeout(Duration::from_secs(5), state_clone.close_connection()).await
            {
                Ok(Ok(())) => {}
                Ok(Err(err)) => error!("Error during closing the connection: {err}"),
                Err(_) => warn!("Timed out during closing the connection"),
            }

            Logger::instance("argon_node", true).flush();

            std::process::exit(1);
        }
    });

    // Run the message handler

    tokio::select! {
        result = state.run_message_handler() => match result {
            Ok(()) => {
                // this likely only happens when the server sends a graceful close
                info!("Message handler loop terminated");
            },

            Err(err) => {
                error!("Message handler loop terminated: {err}");
            }
        },

        _ = tokio::signal::ctrl_c() => {
            warn!("Received interrupt, exiting");
        }
    }

    // send a closure packet to the server, flush the log file, and exit.
    if state.is_connection_open().await {
        info!("Attempting to cleanly close the connection..");

        match tokio::time::timeout(Duration::from_secs(5), state.close_connection()).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => error!("Error during closing the connection: {err}"),
            Err(_) => warn!("Timed out during closing the connection"),
        }
    }

    Logger::instance("argon_node", true).flush();

    Ok(())
}
