use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Result, anyhow, bail};
use argon_shared::{MessageCode, NodeConnection, VerifyProfileFieldData, WorkerConfiguration, logger::*};
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

    pub async fn run_loop(self: Arc<Self>) {
        let worker = self.worker.lock().await.clone().unwrap();

        if let Err(err) = worker.run_loop().await {
            error!("Worker loop terminated due to error: {err}");

            match tokio::time::timeout(Duration::from_secs(5), self.close_connection()).await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => error!("Error during closing the connection: {err}"),
                Err(_) => warn!("Timed out during closing the connection"),
            }

            Logger::instance("argon_node", true).flush();

            std::process::exit(1);
        }
    }

    pub async fn run_profile_fetch_loop(self: Arc<Self>) {
        let worker = self.worker.lock().await.clone().unwrap();

        if let Err(err) = worker.run_profile_fetch_loop().await {
            error!("Profile loop terminated due to error: {err}");

            match tokio::time::timeout(Duration::from_secs(5), self.close_connection()).await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => error!("Error during closing the connection: {err}"),
                Err(_) => warn!("Timed out during closing the connection"),
            }

            Logger::instance("argon_node", true).flush();

            std::process::exit(1);
        }
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
                        worker.gd_client.update_config(
                            worker_config.account_id,
                            worker_config.account_gjp.clone(),
                            worker_config.base_url.clone(),
                        );

                        worker.on_config_changed();
                    }
                }

                MessageCode::AskVerifyProfileField => {
                    let data = match serde_json::from_value::<VerifyProfileFieldData>(message.data) {
                        Ok(x) => x,
                        Err(e) => {
                            warn!("failed to parse VerifyProfileFieldData sent by the server: {e}");
                            continue;
                        }
                    };

                    if data.watch {
                        worker.start_watching_profile(data.account_id);
                    } else {
                        worker.stop_watching_profile(data.account_id);
                    }
                }

                _ => warn!("Unexpected message code received: {:?}", message.code),
            }
        }
    }
}
