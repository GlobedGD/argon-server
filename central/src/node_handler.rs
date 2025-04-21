use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use anyhow::{anyhow, bail};
use argon_shared::{
    MessageCode, NodeConnection, ReceivedMessage, WorkerAuthMessage, WorkerConfiguration, WorkerError,
    logger::*,
};
use parking_lot::Mutex as SyncMutex;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Mutex,
    time::MissedTickBehavior,
};

use crate::{config::GDAccountCreds, state::ServerState};

pub struct NodeHandler {
    server_state: ServerState,
    // fields for the distributed mode
    listener: Option<TcpListener>,
    nodes: Mutex<Vec<Arc<Node>>>,
    // fields for the offline mode
    ofm_active: AtomicBool,
    ofm_id: AtomicI32,
}

pub struct Node {
    pub conn: NodeConnection,
    pub active: AtomicBool,
    pub addr: SocketAddr,
    pub terminating: AtomicBool,
    pub terminated_fully: AtomicBool,
    pub used_account_id: AtomicI32,
    pub last_account_switch: SyncMutex<SystemTime>,
    pub last_recv_challenges: SyncMutex<Instant>,
    pub last_recv_anything: SyncMutex<Instant>,
    pub sent_close: AtomicBool,
    pub fail_count: AtomicU32,
}

impl Node {
    pub fn new(conn: NodeConnection, addr: SocketAddr, used_account_id: i32) -> Self {
        Self {
            conn,
            active: AtomicBool::new(false),
            addr,
            terminating: AtomicBool::new(false),
            terminated_fully: AtomicBool::new(false),
            used_account_id: AtomicI32::new(used_account_id),
            last_account_switch: SyncMutex::new(SystemTime::now()),
            last_recv_challenges: SyncMutex::new(Instant::now()),
            last_recv_anything: SyncMutex::new(Instant::now()),
            sent_close: AtomicBool::new(false),
            fail_count: AtomicU32::new(0),
        }
    }

    pub fn set_active(&self, active: bool) {
        self.active.store(active, Ordering::SeqCst);
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst) && !self.terminating.load(Ordering::SeqCst)
    }

    pub fn set_fail_count(&self, count: u32) {
        self.fail_count.store(count, Ordering::SeqCst);
    }

    pub fn get_fail_count(&self) -> u32 {
        self.fail_count.load(Ordering::SeqCst)
    }

    pub fn since_account_switch(&self) -> Duration {
        self.last_account_switch.lock().elapsed().unwrap_or_default()
    }

    pub fn since_received_challenges(&self) -> Duration {
        self.last_recv_challenges.lock().elapsed()
    }

    pub fn since_received_anything(&self) -> Duration {
        self.last_recv_anything.lock().elapsed()
    }

    pub fn mark_account_switch(&self) {
        *self.last_account_switch.lock() = SystemTime::now();
    }

    pub fn mark_received_challenges(&self) {
        *self.last_recv_challenges.lock() = Instant::now();
    }

    pub fn mark_received_anything(&self) {
        *self.last_recv_anything.lock() = Instant::now();
    }

    pub fn wants_account(&self) -> bool {
        !self.terminating.load(Ordering::SeqCst)
            && self.used_account_id.load(Ordering::SeqCst) <= 0
            && self.since_received_anything() < Duration::from_secs(30)
    }

    pub fn should_give_account(&self) -> bool {
        !self.is_active()
            && self.used_account_id.load(Ordering::SeqCst) > 0
            && self.since_account_switch() > Duration::from_secs(30)
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
            ofm_active: AtomicBool::new(false),
            ofm_id: AtomicI32::new(0),
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
        match self.listener.as_ref() {
            Some(_) => {
                let nodes = self.nodes.lock().await;

                // TODO: smarter load balancing logic
                for node in &*nodes {
                    let id = node.used_account_id.load(Ordering::SeqCst);
                    if node.is_active() && id != -1 {
                        return Some(id);
                    }
                }

                None
            }

            None => {
                if !self.ofm_active.load(Ordering::SeqCst) {
                    None
                } else {
                    Some(self.ofm_id.load(Ordering::SeqCst))
                }
            }
        }
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

    async fn pick_account_for_bot(&self, nodes: &[Arc<Node>]) -> Option<GDAccountCreds> {
        let state = self.server_state.state_read().await;

        // find an account that is not used by any active nodes

        for account in &state.config.accounts {
            if !nodes
                .iter()
                .any(|node| node.used_account_id.load(Ordering::SeqCst) == account.id)
            {
                return Some(account.clone());
            }
        }

        None
    }

    async fn update_node_counter(&self) {
        let mut state = self.server_state.state_write().await;

        if self.is_offline() {
            state.node_count = 1;
            state.active_node_count = if self.ofm_active.load(Ordering::SeqCst) {
                1
            } else {
                0
            };
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

        let mut interval: tokio::time::Interval = tokio::time::interval(Duration::from_secs(10));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        interval.tick().await;

        loop {
            interval.tick().await;

            let mut nodes = self.nodes.lock().await;
            let state = self.server_state.state_read().await;

            // remove all nodes that have terminated from the list
            nodes.retain(|node| {
                let term = node.terminated_fully.load(Ordering::SeqCst);
                if term {
                    info!("[{}] removed node", node.addr);
                }

                !term
            });

            for node in &*nodes {
                if node.terminating.load(Ordering::SeqCst) {
                    continue;
                }

                let mut terminate = false;

                // if nothing received in 30 seconds, try sending a ping
                if node.since_received_anything() > Duration::from_secs(30) {
                    if let Err(err) = node.conn.send_message_code(MessageCode::Ping).await {
                        warn!(
                            "[{}] failed to send ping to node, terminating it: {err}",
                            node.addr
                        );
                        terminate = true;
                    }
                }
                // if nothing received in 90 seconds, terminate the node
                else if node.since_received_anything() > Duration::from_secs(90) {
                    // if we already sent a close packet and got no response, just hard terminate it
                    if node.sent_close.load(Ordering::SeqCst) {
                        warn!(
                            "[{}] node did not respond to our Close message, terminating it",
                            node.addr
                        );
                        terminate = true;
                    } else if let Err(err) = node.conn.send_message_code(MessageCode::Close).await {
                        warn!(
                            "[{}] failed to send close packet to node, terminating it: {err}",
                            node.addr
                        );
                        terminate = true;
                    }

                    // otherwise, we just wait for a CloseAck from the node and hopefully terminate gracefully
                }

                // if no auth messages received recently or failures were received
                if node.since_received_challenges() > Duration::from_secs(30) || node.get_fail_count() > 3 {
                    node.set_active(false);
                }

                // if node is inactive and has an account, and there's another node with no account, we release this gd account from this node
                if node.should_give_account() && nodes.iter().any(|node| node.wants_account()) {
                    info!(
                        "releasing account {} from dead node {}",
                        node.used_account_id.load(Ordering::SeqCst),
                        node.addr
                    );

                    node.used_account_id.store(-1, Ordering::SeqCst);
                    node.mark_account_switch();
                    if let Err(err) = node
                        .conn
                        .send_message(
                            MessageCode::RefreshConfig,
                            &WorkerConfiguration {
                                account_id: -1,
                                account_gjp: String::new(),
                                base_url: String::new(),
                                msg_check_interval: state.config.msg_check_interval,
                            },
                        )
                        .await
                    {
                        warn!(
                            "[{}] failed to send RefreshConfig message to node, terminating it: {err}",
                            node.addr
                        );

                        terminate = true;
                    }
                }

                if terminate {
                    node.terminating.store(true, Ordering::SeqCst);
                }
            }

            drop(state);

            // loop again, assign gd accounts to nodes that don't have them
            for node in &*nodes {
                if node.wants_account() {
                    if let Some(account) = self.pick_account_for_bot(&nodes).await {
                        let state = self.server_state.state_read().await;

                        info!("assigning account {} to node {}", account.id, node.addr);

                        node.used_account_id.store(account.id, Ordering::SeqCst);
                        node.mark_account_switch();
                        if let Err(err) = node
                            .conn
                            .send_message(
                                MessageCode::RefreshConfig,
                                &WorkerConfiguration {
                                    account_id: account.id,
                                    account_gjp: account.gjp,
                                    base_url: state.config.base_url.clone(),
                                    msg_check_interval: state.config.msg_check_interval,
                                },
                            )
                            .await
                        {
                            warn!(
                                "[{}] failed to send RefreshConfig message to node, terminating it: {err}",
                                node.addr
                            );

                            node.terminating.store(true, Ordering::SeqCst);
                        }
                    }
                }
            }

            drop(nodes);

            self.update_node_counter().await;
        }
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
        let account = self.pick_account_for_bot(&self.nodes.lock().await).await;

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
                warn!("[{addr}] error during node receive loop: {err}");
            }

            debug!("[{addr}] node receive loop terminated");

            node.terminated_fully.store(true, Ordering::SeqCst);
        });

        Ok(())
    }

    async fn run_node_receive_loop(&self, node: Arc<Node>) -> anyhow::Result<()> {
        while !node.terminating.load(Ordering::SeqCst) {
            tokio::select! {
                message = node.conn.receive_message() => {
                    let message = message?;

                    node.mark_received_anything();

                    trace!("[{}] received message from node, code: {:?}", node.addr, message.code);

                    match self.handle_node_message(&node, message).await {
                        Ok(()) => {},
                        Err(err) => warn!("[{}] error handling a message from the node: {err}", node.addr)
                    }
                }

                // so that if terminating is set to true, it takes up to 5s for the node to actually terminate
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
            }
        }

        Ok(())
    }

    async fn handle_node_message(&self, node: &Node, message: ReceivedMessage) -> anyhow::Result<()> {
        match message.code {
            MessageCode::Close => {
                debug!("[{}] received close, terminating connection", node.addr);

                // send a CloseAck
                node.conn.send_message_code(MessageCode::CloseAck).await?;

                node.terminating.store(true, Ordering::SeqCst);
            }

            MessageCode::CloseAck => {
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

                // check if this was expected at all
                if node.used_account_id.load(Ordering::SeqCst) <= 0 {
                    // likely something wrong happened in the communication,
                    // node thinks it still has an account but we disagree.
                    // just send them a close packet and let them restart the entire node process for consistency sake
                    if let Err(err) = node.conn.send_message_code(MessageCode::Close).await {
                        warn!("[{}] error sending close message to node: {err}", node.addr);
                        node.terminating.store(true, Ordering::SeqCst);
                    }
                }

                node.mark_received_challenges();

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

                node.set_fail_count(data.fail_count);
            }

            _ => {
                warn!("[{}] invalid message code received, not handling", node.addr);
            }
        }

        Ok(())
    }

    async fn run_node(&self) -> anyhow::Result<()> {
        let account = self.pick_account_for_bot(&self.nodes.lock().await).await;

        let acc = account.unwrap_or_else(|| GDAccountCreds {
            id: -1,
            gjp: String::new(),
        });

        let worker = Arc::new(argon_node::Worker::new_standalone(
            self.make_worker_config(&acc).await,
        ));

        self.ofm_id.store(acc.id, Ordering::SeqCst);

        let worker_clone = worker.clone();
        tokio::spawn(async move {
            match worker_clone.run_loop().await {
                Ok(()) => unreachable!("worker loop should never terminate"),

                Err(err) => {
                    warn!("Standalone node worker loop terminated: {err}");
                }
            }
        });

        trace!("Starting receive message loop (non-distributed mode)");

        let mut last_received = Instant::now();

        loop {
            // if no messages were successfully received in 30 seconds, mark us as inactive
            if last_received.elapsed() > Duration::from_secs(30) {
                self.ofm_active.store(false, Ordering::SeqCst);
            }

            // just receive messages from the node..
            let messages =
                match tokio::time::timeout(Duration::from_secs(5), worker.receive_channel_messages()).await {
                    Ok(Ok(messages)) => messages,
                    Ok(Err(err)) => return Err(err),
                    Err(_) => continue,
                };

            // mark as active if we got any kind of response
            self.ofm_active.store(true, Ordering::SeqCst);
            last_received = Instant::now();

            self.update_node_counter().await;

            self.handle_auth_messages(messages).await;
        }
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
