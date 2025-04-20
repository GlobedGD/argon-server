use std::{net::SocketAddr, sync::Arc};

use anyhow::{Result, anyhow, bail};
use argon_shared::{MessageCode, NodeConnection, WorkerConfiguration, logger::*};
use tokio::{net::TcpStream, sync::Mutex as AsyncMutex};

use crate::worker::Worker;

pub struct NodeState {
    worker: AsyncMutex<Option<Arc<Worker>>>,
}

impl NodeState {
    pub fn new() -> Self {
        Self {
            worker: AsyncMutex::new(None),
        }
    }

    pub async fn try_connect(&self, addr: SocketAddr, password: &str) -> Result<()> {
        let mut worker = self.worker.lock().await;

        if worker.is_some() {
            bail!("cannot call try_connect when already connected");
        }

        let stream = TcpStream::connect(addr).await?;
        let conn = NodeConnection::new(stream);

        conn.perform_handshake().await?;

        conn.send_message(MessageCode::NodeStartup, &password.to_owned())
            .await?;

        let msg = conn.receive_message().await?;

        let config = match msg.code {
            MessageCode::StartupConfig => match serde_json::from_value::<WorkerConfiguration>(msg.data) {
                Ok(x) => x,
                Err(e) => bail!("failed to parse worker configuration sent by the server: {e}"),
            },

            MessageCode::StartupAbort => {
                let reason = msg.data.as_str().unwrap_or("<none>");
                bail!("central server aborted the connection, reason: {reason}");
            }

            _ => {
                bail!("unexpected message code received during connection attempt");
            }
        };

        *worker = Some(Arc::new(Worker::new(conn, config)));

        Ok(())
    }

    pub async fn close_connection(&self) -> Result<()> {
        // use .take() here so that the worker will get dropped by the end of this function
        let worker = self.worker.lock().await.take();

        match worker {
            Some(worker) => {
                worker.close_connection().await?;

                Ok(())
            }

            None => Err(anyhow!("no connection currently opened")),
        }
    }

    pub async fn is_connection_open(&self) -> bool {
        self.worker.lock().await.is_some()
    }

    pub async fn run_loop(&self) -> Result<()> {
        let worker = self.worker.lock().await.clone().unwrap();
        worker.run_loop().await
    }

    pub async fn run_message_handler(&self) -> Result<()> {
        let worker = self.worker.lock().await.clone().unwrap();
        let node_conn = worker.central.as_ref().unwrap();

        loop {
            let message = node_conn.receive_message().await?;

            match message.code {
                MessageCode::Ping => {
                    // send a pong response
                    node_conn.send_message_code(MessageCode::Pong).await?;
                }

                MessageCode::Pong => {}

                MessageCode::Close => {
                    // send close ack and terminate
                    node_conn.send_message_code(MessageCode::CloseAck).await?;
                    break Ok(());
                }

                MessageCode::RefreshConfig => {
                    let config = match serde_json::from_value::<WorkerConfiguration>(message.data) {
                        Ok(x) => x,
                        Err(e) => {
                            bail!("failed to parse worker configuration sent by the server: {e}")
                        }
                    };

                    let mut worker_config = worker.config.lock().await;

                    // update the config if it has changed
                    if *worker_config != config {
                        *worker_config = config;
                        worker.gd_client.lock().await.update_config(
                            worker_config.account_id,
                            worker_config.account_gjp.clone(),
                            worker_config.base_url.clone(),
                        );
                    }
                }

                _ => warn!("Unexpected message code received: {:?}", message.code),
            }
        }
    }
}
