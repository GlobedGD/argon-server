use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, SystemTime},
};

use anyhow::{Result, anyhow, bail};
use argon_shared::{MessageCode, NodeConnection, WorkerAuthMessage, WorkerConfiguration, WorkerError, logger::*};
use nohash_hasher::{IntMap, IntSet};
use parking_lot::Mutex;
use tokio::{net::TcpStream, sync::Mutex as AsyncMutex, time::MissedTickBehavior};

use crate::{
    gd_client::{GDClient, GDMessage},
    worker::Worker,
};

pub const AMOUNT_TO_DELETE: usize = 500;

pub struct ToDeleteMessage {
    pub id: i32,
    pub fetched_at: SystemTime,
}

pub struct NodeState {
    worker: AsyncMutex<Option<Arc<Worker>>>,
    failcount: AtomicU32,
    history: Mutex<IntMap<i32, ToDeleteMessage>>,
    to_delete: Mutex<IntSet<i32>>,
}

// TODO: really move a lot of this to worker lol
impl NodeState {
    pub fn new() -> Self {
        Self {
            worker: AsyncMutex::new(None),
            failcount: AtomicU32::new(0),
            history: Mutex::new(IntMap::default()),
            to_delete: Mutex::new(IntSet::default()),
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

        conn.send_message(MessageCode::NodeStartup, &password.to_owned()).await?;

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
        let conn = worker.central.as_ref().unwrap();

        let mut interval_ms = worker.config.lock().msg_check_interval;
        let mut interval = tokio::time::interval(Duration::from_millis(interval_ms as u64));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        interval.tick().await;

        loop {
            interval.tick().await;

            let gd_client = worker.gd_client.lock().await;

            match self.fetch_messages(&*gd_client, conn).await {
                Ok(messages) => {
                    debug!("received {} auth messages, processing them", messages.len());

                    // process the messages
                    let auth_messages = self.process_auth_messages(messages);

                    // report the messages to the central server
                    conn.send_message(MessageCode::NodeReportMessages, &auth_messages).await?;
                }

                Err(err) => warn!("{err}"),
            }

            // process which messages need to be deleted
            let to_delete = self.queue_messages_for_deletion();
            if to_delete >= AMOUNT_TO_DELETE {
                // delete the messages
                if let Err(err) = self.delete_messages(&*gd_client).await {
                    warn!("{err}");
                }
            }

            // check if the interval has been changed and recreate if needed
            let new_interval = worker.config.lock().msg_check_interval;
            if new_interval != interval_ms {
                interval_ms = new_interval;
                interval = tokio::time::interval(Duration::from_millis(interval_ms as u64));
                interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
                interval.tick().await;
            }
        }

        Ok(())
    }

    async fn fetch_messages(&self, client: &GDClient, conn: &NodeConnection) -> Result<Vec<GDMessage>> {
        match client.fetch_messages().await {
            Ok(x) => {
                self.reset_failure_count();
                Ok(x)
            }

            Err(err) => {
                self.inc_failure_count();

                // report the error to central
                if let Err(err) = self.report_error(conn, err.to_string()).await {
                    warn!("failed to report the error to central: {err}");
                }

                Err(anyhow!("failed to fetch messages: {err}"))
            }
        }
    }

    async fn delete_messages(&self, client: &GDClient) -> anyhow::Result<()> {
        let mut message_vec;

        {
            let mut messages = self.to_delete.lock();
            message_vec = Vec::with_capacity(AMOUNT_TO_DELETE.min(messages.len()));

            // remove up to AMOUNT_TO_DELETE messages from the to_delete set and add to the vec
            messages.retain(|elem| {
                if message_vec.len() < AMOUNT_TO_DELETE {
                    message_vec.push(*elem);
                    false
                } else {
                    true
                }
            });
        }

        match client.delete_messages(&message_vec).await {
            Ok(()) => info!("Deleted {} messages", message_vec.len()),
            Err(err) => return Err(anyhow!("failed to delete messages: {err}")),
        }

        Ok(())
    }

    fn process_auth_messages(&self, messages: Vec<GDMessage>) -> Vec<WorkerAuthMessage> {
        let mut auth_messages = Vec::new();

        let mut history = self.history.lock();
        let to_delete = self.to_delete.lock();

        for message in messages {
            // if this message is already queued for deletion, skip processing it
            if to_delete.contains(&message.id) {
                continue;
            }

            // only count as an auth attempt if the message has been sent less than a minute ago
            // and the title matches what we expect
            if message.age < Duration::from_mins(1) && message.title.starts_with("#ARGON# ") {
                let challenge_answer = message.title.strip_prefix("#ARGON# ").and_then(|x| x.parse::<i32>().ok());

                if let Some(challenge_answer) = challenge_answer {
                    auth_messages.push(WorkerAuthMessage {
                        message_id: message.id,
                        account_id: message.author_id,
                        user_id: message.author_user_id,
                        username: message.author_name,
                        challenge_answer,
                    });
                }
            }

            // queue the message for deletion
            if !history.contains_key(&message.id) {
                history.insert(
                    message.id,
                    ToDeleteMessage {
                        id: message.id,
                        fetched_at: SystemTime::now(),
                    },
                );
            }
        }

        auth_messages
    }

    /// Processes message history, returns how many messages are to be deleted
    fn queue_messages_for_deletion(&self) -> usize {
        let mut history = self.history.lock();
        let mut to_delete = self.to_delete.lock();

        history.retain(|id, message| {
            let keep = message.fetched_at.elapsed().unwrap_or_default() <= Duration::from_mins(2);

            if !keep {
                to_delete.insert(*id);
            }

            keep
        });

        to_delete.len()
    }

    fn inc_failure_count(&self) {
        self.failcount.fetch_add(1, Ordering::SeqCst);
    }

    fn reset_failure_count(&self) {
        self.failcount.store(0, Ordering::SeqCst);
    }

    async fn report_error(&self, conn: &NodeConnection, err: String) -> Result<()> {
        conn.send_message(
            MessageCode::NodeReportError,
            &WorkerError {
                message: err,
                fail_count: self.failcount.load(Ordering::SeqCst),
            },
        )
        .await?;

        Ok(())
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

                    let mut worker_config = worker.config.lock();

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
