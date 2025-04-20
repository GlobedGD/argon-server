use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{anyhow, bail};
use argon_shared::{
    MessageCode, NodeConnection, ReceivedMessage, WorkerAuthMessage, WorkerConfiguration, WorkerError,
    logger::*,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Mutex,
};

use crate::{config::GDAccountCreds, state::ServerState};

pub struct NodeHandler {
    server_state: ServerState,
    // fields for the distributed mode
    listener: Option<TcpListener>,
    nodes: Mutex<Vec<Arc<Node>>>,
    // fields for the offline mode
    ofm_active: bool,
}

pub struct Node {
    pub conn: NodeConnection,
    pub active: AtomicBool,
    pub addr: SocketAddr,
    pub terminating: AtomicBool,
    pub used_account_id: i32,
}

impl Node {
    pub fn new(conn: NodeConnection, addr: SocketAddr, used_account_id: i32) -> Self {
        Self {
            conn,
            active: AtomicBool::new(false),
            addr,
            terminating: AtomicBool::new(false),
            used_account_id,
        }
    }

    pub fn set_active(&self, active: bool) {
        self.active.store(active, Ordering::SeqCst);
    }
}

pub fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;

    a.as_bytes()
        .iter()
        .take(a.len())
        .zip(b.as_bytes().iter().take(b.len()))
        .for_each(|(c1, c2)| result |= c1 ^ c2);

    result == 0
}

impl NodeHandler {
    pub async fn new(address: Option<SocketAddr>, state: ServerState) -> anyhow::Result<Self> {
        let listener = if let Some(address) = address {
            Some(TcpListener::bind(address).await?)
        } else {
            None
        };

        Ok(Self {
            server_state: state,
            listener,
            nodes: Mutex::new(Vec::new()),
            ofm_active: false,
        })
    }

    /// Returns `true` if distributed mode is disabled
    pub fn is_offline(&self) -> bool {
        self.listener.is_none()
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        // if we are not in distributed mode, simply run a node

        match self.listener.as_ref() {
            Some(_) => self.run_handler().await,
            None => self.run_node().await,
        }
    }

    pub async fn pick_challenge_account_id(&self) -> Option<i32> {
        let nodes = self.nodes.lock().await;

        // TODO: smarter load balancing logic
        for node in &*nodes {
            if node.active.load(Ordering::SeqCst) && node.used_account_id != -1 {
                return Some(node.used_account_id);
            }
        }

        None
    }

    async fn make_worker_config(&self, acc: &GDAccountCreds) -> WorkerConfiguration {
        let state = self.server_state.state_read().await;

        WorkerConfiguration {
            account_id: acc.id,
            account_gjp: acc.gjp.clone(),
            base_url: state.config.base_url.clone(),
            msg_check_interval: state.config.msg_check_interval,
        }
    }

    async fn pick_account_for_bot(&self) -> Option<GDAccountCreds> {
        let state = self.server_state.state_read().await;

        // find the account that is used by the least number of nodes
        let mut min_account: Option<&GDAccountCreds> = None;
        let mut min_account_used = usize::MAX;

        for account in &state.config.accounts {
            let mut nodes_using = 0usize;

            for node in &*self.nodes.lock().await {
                if node.used_account_id == account.id {
                    nodes_using += 1;
                }
            }

            if nodes_using < min_account_used {
                min_account_used = nodes_using;
                min_account = Some(account);
            }
        }

        min_account.cloned()
    }

    async fn update_node_counter(&self) {
        let mut state = self.server_state.state_write().await;

        if self.is_offline() {
            state.node_count = 1;
            state.active_node_count = if self.ofm_active { 1 } else { 0 };
        } else {
            let nodes = self.nodes.lock().await;
            state.node_count = nodes.len();
            state.active_node_count = nodes
                .iter()
                .filter(|node| node.active.load(Ordering::SeqCst))
                .count();
        }
    }

    async fn run_handler(&self) -> anyhow::Result<()> {
        let this = self.server_state.node_handler().await;

        tokio::spawn(async move {
            if let Err(err) = this._run_connection_listener().await {
                error!("Connection listener terminated: {err}");
            }
        });

        // uh todo

        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            // TODO: watch over nodes and mark as inactive if they didnt process anything
        }

        Ok(())
    }

    async fn _run_connection_listener(&self) -> anyhow::Result<()> {
        let listener = self.listener.as_ref().unwrap();

        loop {
            let (socket, address) = listener.accept().await?;

            debug!("handling connection from {address}");

            // handle this connection in another task, so that we don't make other incoming connections wait
            let state = self.server_state.clone();
            tokio::spawn(async move {
                let this = state.node_handler().await;

                // give them up to 10 seconds
                match tokio::time::timeout(
                    Duration::from_secs(10),
                    this.handle_incoming_connection(socket, address),
                )
                .await
                {
                    Ok(Ok(())) => {}

                    Ok(Err(err)) => {
                        warn!("[{address}] error during node connection: {err}");
                    }

                    Err(_) => {
                        warn!(
                            "[{address}] timed out waiting for the node to perform the handshake and login"
                        );
                    }
                }
            });
        }
    }

    async fn handle_incoming_connection(&self, socket: TcpStream, addr: SocketAddr) -> anyhow::Result<()> {
        let conn = NodeConnection::new(socket);

        // wait for client to perform the handshake
        conn.wait_for_handshake().await?;

        // wait for client to send the startup message
        let msg = conn.receive_message().await?;
        if msg.code != MessageCode::NodeStartup {
            bail!("expected NodeStartup after handshake, but got another message");
        }

        let password = msg.data.as_str().unwrap_or_default();

        if !constant_time_compare(&self.server_state.state_read().await.config.password, password) {
            // send abort message
            conn.send_message(MessageCode::StartupAbort, &"auth failure".to_owned())
                .await?;

            bail!("failed to authenticate node");
        }

        // otherwise, pick a gd account for them and send success
        let account = self.pick_account_for_bot().await;

        let acc = account.unwrap_or_else(|| GDAccountCreds {
            id: -1,
            gjp: String::new(),
        });

        conn.send_message(MessageCode::StartupConfig, &self.make_worker_config(&acc).await)
            .await?;

        // add to the client list
        let node = Arc::new(Node::new(conn, addr, acc.id));
        self.nodes.lock().await.push(node.clone());

        info!("[{addr}] added new node!");

        self.update_node_counter().await;

        // run the node receive loop
        let sclone = self.server_state.clone();
        tokio::spawn(async move {
            let this = sclone.node_handler().await;

            if let Err(err) = this.run_node_receive_loop(node.clone()).await {
                warn!("[{}] error during node receive loop: {err}", node.addr);
            }

            // remove node from the list
            {
                let mut nodes = this.nodes.lock().await;
                if let Some(node_idx) = nodes.iter().position(|n| Arc::ptr_eq(n, &node)) {
                    nodes.remove(node_idx);
                }
            }

            info!("[{addr}] removed node");

            this.update_node_counter().await;
        });

        Ok(())
    }

    async fn run_node_receive_loop(&self, node: Arc<Node>) -> anyhow::Result<()> {
        while !node.terminating.load(Ordering::SeqCst) {
            tokio::select! {
                message = node.conn.receive_message() => {
                    let message = message?;

                    trace!("[{}] received message from node, code: {:?}", node.addr, message.code);

                    match self.handle_node_message(&node, message).await {
                        Ok(()) => {},
                        Err(err) => warn!("[{}] error handling a message from the node: {err}", node.addr)
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_node_message(&self, node: &Node, message: ReceivedMessage) -> anyhow::Result<()> {
        match message.code {
            MessageCode::Close => {
                info!("[{}] received close, terminating connection", node.addr);

                // send a CloseAck
                node.conn.send_message_code(MessageCode::CloseAck).await?;

                node.terminating.store(true, Ordering::SeqCst);
            }

            MessageCode::Ping => {
                node.conn.send_message_code(MessageCode::Pong).await?;
            }

            MessageCode::Pong => {}

            MessageCode::NodeReportMessages => {
                let messages = match serde_json::from_value::<Vec<WorkerAuthMessage>>(message.data) {
                    Ok(x) => x,
                    Err(err) => return Err(anyhow!("failed to parse messages: {err}")),
                };

                trace!(
                    "[{}] received {} auth messages from node",
                    node.addr,
                    messages.len()
                );

                // mark node as active
                node.set_active(true);
                self.update_node_counter().await;

                self.handle_auth_messages(messages).await;
            }

            MessageCode::NodeReportError => {
                let data = match serde_json::from_value::<WorkerError>(message.data) {
                    Ok(x) => x,
                    Err(err) => return Err(anyhow!("failed to parse worker error: {err}")),
                };

                warn!(
                    "[{}] node reported error: {} (fail count: {})",
                    node.addr, data.message, data.fail_count
                );

                if data.fail_count > 3 {
                    // mark node as inactive
                    node.set_active(false);
                    self.update_node_counter().await;
                }
            }

            _ => {
                warn!("[{}] invalid message code received, not handling", node.addr);
            }
        }

        Ok(())
    }

    async fn run_node(&self) -> anyhow::Result<()> {
        let account = self.pick_account_for_bot().await;

        let acc = account.unwrap_or_else(|| GDAccountCreds {
            id: -1,
            gjp: String::new(),
        });

        let worker = Arc::new(argon_node::Worker::new_standalone(
            self.make_worker_config(&acc).await,
        ));

        let worker_clone = worker.clone();
        tokio::spawn(async move {
            match worker_clone.run_loop().await {
                Ok(()) => unreachable!("worker loop should never terminate"),
                Err(err) => {
                    warn!("Standalone node worker loop terminated: {err}");
                }
            }
        });

        loop {
            // just receive messages from the node..
            let messages = worker.receive_channel_messages().await?;
            self.handle_auth_messages(messages).await;
        }

        Ok(())
    }

    pub async fn notify_config_change(&self) {
        // TODO also note we cant touch state here !
    }

    /* handling stuff */

    async fn handle_auth_messages(&self, messages: Vec<WorkerAuthMessage>) {
        self.server_state
            .state_write()
            .await
            .validate_challenges(messages)
            .await;
    }
}
