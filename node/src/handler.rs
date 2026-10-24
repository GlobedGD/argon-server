use anyhow::bail;
use parking_lot::Mutex;
use std::{
    net::{IpAddr, SocketAddr},
    sync::OnceLock,
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::{MissedTickBehavior, interval},
};
use tracing::{error, info, warn};

use shared::{
    message::{ArgonNodeMessage, UserChallengeResult},
    qunet::{
        client::{
            Client, ClientHandle, ConnectOptions, ConnectionError, ConnectionType, EventHandler,
            WeakClientHandle,
        },
        message::MsgData,
    },
};

use crate::{
    config::NodeConfig,
    worker::{NodeWorker, NodeWorkerChallenges},
};

pub struct Node {
    client: OnceLock<WeakClientHandle<Self>>,
    connect_tx: Mutex<Option<oneshot::Sender<Result<(), ConnectionError>>>>,
    msg_tx: Mutex<Option<mpsc::Sender<ArgonNodeMessage>>>,
}

struct ConnectedData {
    msg_rx: mpsc::Receiver<ArgonNodeMessage>,
    worker_rx: mpsc::Receiver<UserChallengeResult>,
    challenges_tx: mpsc::Sender<NodeWorkerChallenges>,
    worker: JoinHandle<()>,
}

impl Node {
    pub fn new() -> Self {
        Self {
            client: OnceLock::new(),
            connect_tx: Mutex::new(None),
            msg_tx: Mutex::new(None),
        }
    }

    pub async fn run(&self, client: WeakClientHandle<Self>, config: NodeConfig) -> anyhow::Result<()> {
        self.client.set(client).ok().unwrap();

        let ConnectedData {
            mut msg_rx,
            mut worker_rx,
            challenges_tx,
            worker,
        } = self.establish_connection(&config).await?;

        // process messages and other work

        let mut interval = interval(Duration::from_millis(100));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let mut results = Vec::new();

        loop {
            tokio::select! {
                // handle messages received from the central argon server
                msg = msg_rx.recv() => match msg {
                    Some(msg) => {
                        self.on_message(msg, &challenges_tx).await;
                    }

                    None => {
                        bail!("connection closed by server");
                    }
                },

                // periodically send current batch of results to the central server
                _ = interval.tick(), if !results.is_empty() => {
                    self.send(&ArgonNodeMessage::ChallengeResults { results: std::mem::take(&mut results) })?;
                }

                // handle messages from the worker
                Some(msg) = worker_rx.recv() => {
                    results.push(msg);
                }

                _ = tokio::signal::ctrl_c() => {
                    info!("Received Ctrl+C, shutting down...");
                    self.send_disconnect();

                    // actual disconnect is async so it takes time to process, wait a bit before returning
                    tokio::time::sleep(Duration::from_millis(100)).await;

                    break;
                }
            };
        }

        worker.abort();

        Ok(())
    }

    async fn establish_connection(&self, config: &NodeConfig) -> anyhow::Result<ConnectedData> {
        let (connect_tx, connect_rx) = oneshot::channel();
        self.connect_tx.lock().replace(connect_tx);

        let (msg_tx, mut msg_rx) = mpsc::channel(64);
        self.msg_tx.lock().replace(msg_tx);

        // asynchronously connect and wait for result
        self.connect_with_opts(self.client(), config)?;
        let result = connect_rx.await.unwrap();
        result?;

        // login
        self.send(&ArgonNodeMessage::Login {
            key: config.central.secret_key.clone(),
        })?;

        // wait for reply
        let Some(reply) = msg_rx.recv().await else {
            // if we got here, this means the server terminated the connection for whatever reason
            // the actual reason will separately be printed to the console by qunet, so there's nothing else to do here
            bail!("connection closed by server");
        };

        let ArgonNodeMessage::LoginSuccess { resources } = reply else {
            bail!("expected login success message, got {:?}", reply);
        };

        info!("Successfully connected to Argon central server");
        info!("Using auth resources:");
        for r in &resources {
            info!(" - {:?}", r);
        }

        // create worker
        let (worker_tx, worker_rx) = mpsc::channel(128);
        let (challenges_tx, challenges_rx) = mpsc::channel(128);

        let worker = NodeWorker::new(config, resources, worker_tx, challenges_rx);

        let handle = tokio::spawn(worker.run());

        Ok(ConnectedData {
            msg_rx,
            worker_rx,
            challenges_tx,
            worker: handle,
        })
    }

    async fn on_message(&self, msg: ArgonNodeMessage, challenges_tx: &mpsc::Sender<NodeWorkerChallenges>) {
        info!("Received message from central: {:?}", msg);

        match msg {
            ArgonNodeMessage::Challenges {
                challenges,
                cleanups,
            } => {
                let _ = challenges_tx
                    .send(NodeWorkerChallenges {
                        challenges,
                        cleanups,
                    })
                    .await;
            }

            _ => warn!("unexpected message from central: {:?}", msg),
        }
    }

    fn send_disconnect(&self) {
        self.client().disconnect();
    }

    pub fn send(&self, msg: &ArgonNodeMessage) -> anyhow::Result<()> {
        let client = self.client();
        client.send_data(msg.encode()?.as_slice());
        Ok(())
    }

    pub fn client(&self) -> ClientHandle<Self> {
        self.client.get().unwrap().upgrade().unwrap()
    }

    pub fn connect_with_opts(&self, client: ClientHandle<Node>, config: &NodeConfig) -> anyhow::Result<()> {
        let Some(address) = config.central.address.clone() else {
            bail!("Central server address is not set, cannot connect to central");
        };

        let (ip, port) = match address.parse::<SocketAddr>() {
            Ok(addr) => (Some(addr.ip()), Some(addr.port())),
            Err(_) => match address.parse::<IpAddr>() {
                Ok(ip) => (Some(ip), None),
                Err(_) => (None, None),
            },
        };

        // if this is an IP or a sockaddr...
        if let Some(ip) = ip {
            // connect to it directly and use hostname provided in config
            client.connect_opts(ConnectOptions {
                hostname: config.central.hostname.clone(),
                ip: Some(ip),
                port,
                connection_type: ConnectionType::Quic,
            })?;
        } else {
            // otherwise, this is likely a domain name
            let (hostname, port) = match address.split_once(':') {
                Some((host, port)) => (host.to_owned(), port.parse::<u16>().unwrap_or(8081)),
                None => (address.clone(), 8081),
            };

            client.connect_opts(ConnectOptions::new_hostname(&hostname, Some(port), ConnectionType::Quic))?;
        }

        Ok(())
    }
}

impl EventHandler for Node {
    async fn on_connected(&self, _client: &ClientHandle<Self>) {
        self.connect_tx.lock().take().unwrap().send(Ok(())).unwrap();
    }

    async fn on_connection_error(&self, _client: &ClientHandle<Self>, err: ConnectionError) {
        self.connect_tx.lock().take().unwrap().send(Err(err)).unwrap();
    }

    async fn on_disconnected(&self, _client: &ClientHandle<Self>) {
        // drop the message sender so receiver gets notified about it
        self.msg_tx.lock().take();
    }

    async fn on_recv_data(&self, _client: &Client<Self>, data: MsgData<'_>) {
        match ArgonNodeMessage::decode(&data) {
            Ok(msg) => {
                let tx = self.msg_tx.lock().clone().unwrap();
                let _ = tx.send(msg).await;
            }

            Err(e) => {
                error!("Failed to decode message: {:?}", e);
            }
        }
    }
}
