#![feature(iter_array_chunks)]

use std::time::Duration;

use shared::qunet::client::Client;
use tracing::error;

use crate::{config::NodeConfig, handler::Node};

mod config;
mod gd;
mod handler;
mod worker;

#[tokio::main]
async fn main() {
    let config = match NodeConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load configuration: {e}");
            std::process::exit(1);
        }
    };

    let _guard = shared::logging::init(&config.logging);
    if config.central.certificate.is_empty() {
        error!("Path to TLS certificate store is not set, see README");
        std::process::exit(1);
    }

    let client = Client::builder()
        .with_quic_cert_path(config.central.certificate.clone())
        .with_connect_timeout(Duration::from_secs(5))
        .with_keepalive_interval(Duration::from_secs(3))
        .with_event_handler(Node::new())
        .build()
        .await
        .expect("failed to build Qunet client");

    let weak = client.downgrade();

    if let Err(e) = client.handler().run(weak, config).await {
        error!("Node handler failed: {e}");
        std::process::exit(1);
    }
}
