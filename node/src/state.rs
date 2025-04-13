use std::{net::SocketAddr, time::Duration};

use anyhow::{Result, anyhow, bail};
use argon_shared::{MessageCode, NodeConnection, WorkerConfiguration};
use tokio::{net::TcpStream, sync::Mutex as AsyncMutex};

use crate::worker::Worker;

pub struct NodeState {
    worker: AsyncMutex<Option<Worker>>,
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
            MessageCode::StartupConfig => {
                match serde_json::from_value::<WorkerConfiguration>(msg.data) {
                    Ok(x) => x,
                    Err(e) => bail!("failed to parse worker configuration sent by the server: {e}"),
                }
            }

            MessageCode::StartupAbort => {
                let reason = msg.data.as_str().unwrap_or("<none>");
                bail!("central server aborted the connection, reason: {reason}");
            }

            _ => {
                bail!("unexpected message code received during connection attempt");
            }
        };

        *worker = Some(Worker::new(conn, config));

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
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        Ok(())
    }
}
