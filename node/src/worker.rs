use anyhow::{Result, anyhow};
use nohash_hasher::{IntMap, IntSet};
use std::{
    error::Error,
    fmt::Display,
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, SystemTime},
};
use tokio::{
    sync::{
        Mutex as AsyncMutex,
        mpsc::{Receiver, Sender},
    },
    time::MissedTickBehavior,
};

use crate::gd_client::{GDClient, GDMessage};
use argon_shared::{
    MessageCode, NodeConnection, ReceiveError, SendError, WorkerAuthMessage, WorkerConfiguration, WorkerError, logger::*,
};
use parking_lot::Mutex;
use serde_json::json;

pub const AMOUNT_TO_DELETE: usize = 500;

pub struct ToDeleteMessage {
    pub fetched_at: SystemTime,
}

type ChallengeChannel = (Sender<Vec<WorkerAuthMessage>>, AsyncMutex<Receiver<Vec<WorkerAuthMessage>>>);

pub struct Worker {
    pub gd_client: AsyncMutex<GDClient>,
    pub central: Option<NodeConnection>,
    pub config: AsyncMutex<WorkerConfiguration>,
    failcount: AtomicU32,
    history: Mutex<IntMap<i32, ToDeleteMessage>>,
    to_delete: Mutex<IntSet<i32>>,

    // these are for standalone
    auth_challenge_channel: Option<ChallengeChannel>,
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
        Self::_new_with_central(Some(central), config)
    }

    #[allow(unused)]
    pub fn new_standalone(config: WorkerConfiguration) -> Self {
        Self::_new_with_central(None, config)
    }

    fn _new_with_central(central: Option<NodeConnection>, config: WorkerConfiguration) -> Self {
        let gd_client = GDClient::new(config.account_id, config.account_gjp.clone(), config.base_url.clone());

        let auth_challenge_channel = if central.is_none() {
            let (tx, rx) = tokio::sync::mpsc::channel(16);
            Some((tx, AsyncMutex::new(rx)))
        } else {
            None
        };

        Self {
            gd_client: AsyncMutex::new(gd_client),
            central,
            config: AsyncMutex::new(config),
            failcount: AtomicU32::new(0),
            history: Mutex::new(IntMap::default()),
            to_delete: Mutex::new(IntSet::default()),
            auth_challenge_channel,
        }
    }

    /// If the connection to the central Argon server is alive, sends a closure packet, waits for a response, and then closes the connection.
    pub async fn close_connection(&self) -> Result<(), ClosureError> {
        if let Some(central) = self.central.as_ref() {
            central.send_message(MessageCode::Close, &json!(null)).await?;

            // wait for ack from the server
            loop {
                let message = central.receive_message().await?;

                if message.code == MessageCode::CloseAck {
                    break;
                }
            }

            central.close().await.map_err(ClosureError::SocketShutdown)?;

            Ok(())
        } else {
            Err(ClosureError::Standalone)
        }
    }

    pub async fn run_loop(&self) -> Result<()> {
        let mut interval_ms = self.config.lock().await.msg_check_interval;
        let mut interval = tokio::time::interval(Duration::from_millis(interval_ms as u64));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        interval.tick().await;

        loop {
            interval.tick().await;

            let gd_client = self.gd_client.lock().await;

            match self.fetch_messages(&gd_client, self.central.as_ref()).await {
                Ok(messages) => {
                    debug!("received {} auth messages, processing them", messages.len());

                    // process the messages
                    let auth_messages = self.process_auth_messages(messages);

                    self.report_messages(auth_messages).await?;
                }

                Err(err) => warn!("{err}"),
            }

            // process which messages need to be deleted
            let to_delete = self.queue_messages_for_deletion();
            if to_delete >= AMOUNT_TO_DELETE {
                // delete the messages
                if let Err(err) = self.delete_messages(&gd_client).await {
                    warn!("{err}");
                }
            }

            // check if the interval has been changed and recreate if needed
            let new_interval = self.config.lock().await.msg_check_interval;
            if new_interval != interval_ms {
                interval_ms = new_interval;
                interval = tokio::time::interval(Duration::from_millis(interval_ms as u64));
                interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
                interval.tick().await;
            }
        }
    }

    async fn fetch_messages(&self, client: &GDClient, conn: Option<&NodeConnection>) -> Result<Vec<GDMessage>> {
        match client.fetch_messages().await {
            Ok(x) => {
                self.reset_failure_count();
                Ok(x)
            }

            Err(err) => {
                self.inc_failure_count();

                // report the error to central
                if let Some(conn) = conn {
                    if let Err(err) = self.report_error(conn, err.to_string()).await {
                        warn!("failed to report the error to central: {err}");
                    }
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
            history.entry(message.id).or_insert_with(|| ToDeleteMessage {
                fetched_at: SystemTime::now(),
            });
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

    async fn report_messages(&self, messages: Vec<WorkerAuthMessage>) -> Result<()> {
        if let Some(conn) = self.central.as_ref() {
            // report the messages to the central server
            conn.send_message(MessageCode::NodeReportMessages, &messages).await?;
        } else {
            // report the messages to the mpsc channel
            self.auth_challenge_channel.as_ref().unwrap().0.send(messages).await?;
        }

        Ok(())
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

    fn inc_failure_count(&self) {
        self.failcount.fetch_add(1, Ordering::SeqCst);
    }

    fn reset_failure_count(&self) {
        self.failcount.store(0, Ordering::SeqCst);
    }

    #[allow(unused)]
    pub async fn receive_channel_messages(&self) -> Result<Vec<WorkerAuthMessage>> {
        let channel = self.auth_challenge_channel.as_ref().unwrap();

        channel.1.lock().await.recv().await.ok_or(anyhow!("mpsc channel closed"))
    }
}
