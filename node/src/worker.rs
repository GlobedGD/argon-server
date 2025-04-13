use std::{error::Error, fmt::Display};

use crate::gd_client::GDClient;
use argon_shared::{MessageCode, NodeConnection, ReceiveError, SendError, WorkerConfiguration};
use serde_json::json;

pub struct Worker {
    gd_client: GDClient,
    central: Option<NodeConnection>,
    config: WorkerConfiguration,
}

#[derive(Debug)]
pub enum ClosureError {
    Send(SendError),
    Receive(ReceiveError),
    SocketShutdown(std::io::Error),
    Standalone,
}

impl From<SendError> for ClosureError {
    fn from(value: SendError) -> Self {
        Self::Send(value)
    }
}

impl From<ReceiveError> for ClosureError {
    fn from(value: ReceiveError) -> Self {
        Self::Receive(value)
    }
}

impl Display for ClosureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Send(e) => write!(f, "{e}"),
            Self::Receive(e) => write!(f, "{e}"),
            Self::SocketShutdown(e) => write!(f, "failed to shutdown socket: {e}"),
            Self::Standalone => write!(f, "attempting to close a standalone node"),
        }
    }
}

impl Error for ClosureError {}

impl Worker {
    pub fn new(central: NodeConnection, config: WorkerConfiguration) -> Self {
        let gd_client = GDClient::new(
            config.account_id,
            config.account_gjp.clone(),
            config.base_url.clone(),
        );

        Self {
            gd_client,
            central: Some(central),
            config,
        }
    }

    pub fn new_standalone(config: WorkerConfiguration) -> Self {
        let gd_client = GDClient::new(
            config.account_id,
            config.account_gjp.clone(),
            config.base_url.clone(),
        );

        Self {
            gd_client,
            central: None,
            config,
        }
    }

    /// If the connection to the central Argon server is alive, sends a closure packet, waits for a response, and then closes the connection.
    pub async fn close_connection(&self) -> Result<(), ClosureError> {
        if let Some(central) = self.central.as_ref() {
            central
                .send_message(MessageCode::Close, &json!(null))
                .await?;

            // wait for ack from the server
            loop {
                let message = central.receive_message().await?;

                if message.code == MessageCode::CloseAck {
                    break;
                }
            }

            central
                .close()
                .await
                .map_err(ClosureError::SocketShutdown)?;

            Ok(())
        } else {
            Err(ClosureError::Standalone)
        }
    }
}
