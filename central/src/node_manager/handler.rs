use std::{
    net::SocketAddr,
    sync::{Arc, OnceLock},
};

use shared::{
    message::ArgonNodeMessage,
    qunet::{
        message::MsgData,
        server::{
            Server, ServerHandle, WeakServerHandle,
            app_handler::{AppHandler, AppResult},
            client::ClientState,
        },
    },
};
use tracing::{debug, warn};

use crate::node_manager::{NodeManager, node::ArgonNode};

pub struct NodeMessageHandler {
    node_manager: Arc<NodeManager>,
    server: OnceLock<WeakServerHandle<Self>>,
}

impl AppHandler for NodeMessageHandler {
    type ClientData = Arc<ArgonNode>;

    async fn on_launch(&self, server: ServerHandle<Self>) -> AppResult<()> {
        self.server.set(server.downgrade()).ok().unwrap();
        Ok(())
    }

    async fn on_client_connect(
        &self,
        _server: &Server<Self>,
        _connection_id: u64,
        address: SocketAddr,
        _kind_str: &str,
    ) -> AppResult<Arc<ArgonNode>> {
        debug!("New node connection ({})", address);
        Ok(Arc::new(ArgonNode::new(address)))
    }

    async fn on_client_disconnect(&self, _server: &Server<Self>, client: &Arc<ClientState<Self>>) {
        if client.data().authorized() {
            self.node_manager.on_node_disconnected(client.data().clone()).await;
        }
    }

    async fn on_client_data(
        &self,
        _server: &Server<Self>,
        client: &Arc<ClientState<Self>>,
        data: MsgData<'_>,
    ) {
        let msg = match ArgonNodeMessage::decode(&data) {
            Ok(msg) => msg,

            Err(e) => {
                debug!("failed to decode message from node {}: {e:?}", client.address);
                return;
            }
        };

        self.handle_message(msg, client).await;
    }
}

impl NodeMessageHandler {
    pub fn new(node_manager: Arc<NodeManager>) -> Self {
        Self {
            node_manager,
            server: OnceLock::new(),
        }
    }

    fn server(&self) -> ServerHandle<Self> {
        self.server.get().unwrap().upgrade().unwrap()
    }

    async fn handle_message(&self, msg: ArgonNodeMessage, client: &Arc<ClientState<Self>>) {
        match msg {
            ArgonNodeMessage::Ping { time } => {
                self.send_message(client, &ArgonNodeMessage::Pong { time });
            }

            ArgonNodeMessage::Pong { .. } => {}

            ArgonNodeMessage::Login { key } => {
                self.handle_login(&key, client).await;
            }

            ArgonNodeMessage::ChallengeResults { results } => {
                self.node_manager.handle_challenge_results(client, results);
            }

            _ => {
                warn!("unexpected message from node {}: {:?}", client.address, msg);
            }
        }
    }

    async fn handle_login(&self, attempted_key: &str, client: &Arc<ClientState<Self>>) {
        if client.data().authorized() {
            // already authorized
            return;
        }

        let correct = constant_time_eq::constant_time_eq(
            attempted_key.as_bytes(),
            self.node_manager.config.secret_key.as_bytes(),
        );
        if !correct {
            client.disconnect("incorrect secret key");
            return;
        }

        client.data().set_authorized(true);

        self.node_manager.on_node_connected(client.clone()).await;
    }

    pub fn send_message(&self, client: &ClientState<Self>, msg: &ArgonNodeMessage) {
        let data = msg.encode().expect("failed to encode");
        client.send_data(&data, &self.server());
    }
}
