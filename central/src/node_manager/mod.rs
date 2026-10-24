use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use dashmap::DashMap;
use parking_lot::Mutex;
use sea_orm::Iterable;
use shared::{
    message::{ArgonNodeMessage, UserChallengeResult},
    qunet::server::{Server, ServerHandle, ServerOutcome, client::ClientState},
    resource::{ResourceKey, ResourceType},
};
use tokio::{sync::Mutex as AsyncMutex, time::interval};
use tracing::{debug, error, info, warn};

use crate::{
    config::{AppConfig, NodeHandlerConfig},
    node_manager::{handler::NodeMessageHandler, node::ArgonNode, resource::AuthResource},
};

mod handler;
pub mod node;
mod performance_tracker;
pub mod resource;

struct RoundRobinPool {
    nodes: Vec<(ResourceKey, Arc<ArgonNode>)>,
    next_index: AtomicUsize,
}

impl RoundRobinPool {
    pub fn new(nodes: Vec<(ResourceKey, Arc<ArgonNode>)>) -> Self {
        Self {
            nodes,
            next_index: AtomicUsize::new(0),
        }
    }

    pub fn next(&self) -> (ResourceKey, Arc<ArgonNode>) {
        let len = self.nodes.len();
        assert_ne!(len, 0, "RoundRobinPool is empty");

        // fast common path
        if len == 1 {
            return self.nodes[0].clone();
        }

        let index = self.next_index.fetch_add(1, Ordering::Relaxed);
        let node = &self.nodes[index % len];
        (node.0, node.1.clone())
    }
}

pub struct NodeManager {
    resources: HashMap<ResourceKey, AuthResource>,
    server: Mutex<Option<ServerHandle<NodeMessageHandler>>>,
    config: NodeHandlerConfig,

    nodes: AsyncMutex<Vec<Arc<ArgonNode>>>,
    node_count: AtomicUsize,
    client_map: DashMap<u64, Arc<ClientState<NodeMessageHandler>>>,

    resource_pool: DashMap<ResourceType, RoundRobinPool>,
}

impl NodeManager {
    pub fn new(config: &AppConfig) -> Self {
        let resources = config
            .auth
            .resources
            .iter()
            .map(|r| {
                let resource = AuthResource::new(r);
                (resource.key(), resource)
            })
            .collect::<HashMap<_, _>>();

        // if legacy mode is enabled, error if no legacy resource is added
        let any_legacy = resources.values().any(|r| r.r#type == ResourceType::LegacyProfileField);
        if config.legacy.enabled && !any_legacy {
            error!("note: you enabled legacy API, but did not add a legacy resource for authentication.");
            error!("disable legacy API or add a resource with type \"legacy_profile_field\"");
            std::process::exit(1);
        }

        NodeManager {
            resources,
            nodes: AsyncMutex::new(Vec::new()),
            node_count: AtomicUsize::new(0),
            client_map: DashMap::new(),
            server: Mutex::new(None),
            config: config.node_handler.clone(),
            resource_pool: DashMap::new(),
        }
    }

    pub async fn run(self: Arc<NodeManager>) {
        if self.config.tls_cert.is_empty() || self.config.tls_key.is_empty() {
            error!("TLS certificate or key is not configured. Node manager will not work.");
            error!("Add a [node_handler] section in config.toml and specify tls_cert and tls_key.");
            error!("See README for more details.");
            std::process::exit(1);
        }

        if self.config.secret_key.len() < 16 {
            error!(
                "Secret key is not configured or too short (must be 16 chars or more), refusing to start server with insecure configuration."
            );
            error!("See README for more details.");
            std::process::exit(1);
        }

        let server = Server::builder()
            .with_app_handler(NodeMessageHandler::new(self.clone()))
            .with_handshake_timeout(Duration::from_secs(3))
            .with_idle_timeout(Duration::from_secs(15))
            .with_max_suspend_time(Duration::ZERO)
            .with_quic(self.config.bind, &self.config.tls_cert, &self.config.tls_key)
            .build()
            .await
            .expect("failed to build server");

        let processor_task = tokio::spawn(self.clone().run_processor_loop());

        *self.server.lock() = Some(server.clone());

        info!("Starting node manager on {}", self.config.bind);
        let outcome = server.run().await;

        *self.server.lock() = None;

        processor_task.abort();

        if !matches!(outcome, ServerOutcome::GracefulShutdown) {
            panic!("Node manager terminated: {outcome:?}");
        }

        std::process::exit(0);
    }

    async fn run_processor_loop(self: Arc<NodeManager>) {
        let mut interval = interval(Duration::from_millis(100));

        loop {
            interval.tick().await;

            let nodes = self.nodes.lock().await;
            for node in nodes.iter() {
                if self.maybe_kill_node(node) {
                    continue;
                }

                // send all accumulated challenges / cleanups to this node
                let challenges = node.get_queued_challenges();
                let cleanups = node.get_queued_cleanups();
                let should_poll = node.get_queued_should_poll();

                if challenges.is_empty() && cleanups.is_empty() && should_poll.is_empty() {
                    continue;
                }

                self.send_message_to_node(
                    node,
                    &ArgonNodeMessage::Challenges {
                        challenges,
                        cleanups,
                        should_poll,
                    },
                );
            }
        }
    }

    fn maybe_kill_node(&self, node: &Arc<ArgonNode>) -> bool {
        // check if this node is performing well
        let success_over_5m = node.success_rate(Duration::from_mins(5));
        let success_over_1m = node.success_rate(Duration::from_mins(1));
        let poor_performance = success_over_5m < 0.75 || success_over_1m < 0.5;
        if poor_performance {
            node.inc_poor_perf();
        } else {
            node.dec_poor_perf();
        }

        // after ~2 minutes of sustained poor performance, disconnect the node
        if node.poor_perf_count() > 1200 {
            let Some(client) = self.client_map.get(&node.id) else {
                error!("Unable to find node '{}' ({}) in map", node.address, node.id);
                return true;
            };

            client.disconnect("Disconnecting due to poor verification performance");
            return true;
        }

        false
    }

    fn server(&self) -> ServerHandle<NodeMessageHandler> {
        self.server.lock().as_ref().unwrap().clone()
    }

    fn send_message_to_node(&self, node: &ArgonNode, message: &ArgonNodeMessage) {
        if let Some(client) = self.client_map.get(&node.id) {
            let data = message.encode().expect("failed to encode");
            client.send_data(&data, &self.server());
        }
    }

    pub async fn on_node_connected(&self, client: Arc<ClientState<NodeMessageHandler>>) {
        let node = client.data().clone();
        info!("[{}] Node logged in", node.address);

        self.nodes.lock().await.push(node.clone());
        self.client_map.insert(node.id, client.clone());
        self.node_count.fetch_add(1, Ordering::Relaxed);

        let resources = self.pick_free_resources(&node);
        if resources.is_empty() {
            client.disconnect("No free auth resources available");
            return;
        }

        *node.used_resources.lock() = resources.clone();

        // send success message
        self.send_message_to_node(&node, &ArgonNodeMessage::LoginSuccess { resources });
        self.reset_resource_pool();
    }

    pub async fn on_node_disconnected(&self, node: Arc<ArgonNode>) {
        info!("[{}] Node lost connection", node.address);

        self.client_map.remove(&node.id);
        self.nodes.lock().await.retain(|n| !Arc::ptr_eq(n, &node));
        self.node_count.fetch_sub(1, Ordering::Relaxed);

        let used_resources = std::mem::take(&mut *node.used_resources.lock());
        self.release_resources(&node, &used_resources);
        self.reset_resource_pool();
    }

    pub fn handle_challenge_results(&self, node: &Arc<ArgonNode>, results: Vec<UserChallengeResult>) {
        debug!("[{}] Received challenge results: {:?}", node.address, results);

        // don't act on the results immediately, let the challenge controller dequeue them
        node.queue_results(&results);
    }

    fn pick_free_resources(&self, node: &Arc<ArgonNode>) -> Vec<ResourceKey> {
        let mut resources = HashMap::new();

        for (key, r) in self.resources.iter() {
            if resources.contains_key(&key.r#type) {
                continue;
            }

            if !r.try_claim(node) {
                continue;
            }

            resources.insert(key.r#type, *key);
        }

        resources.into_values().collect()
    }

    fn release_resources(&self, node: &Arc<ArgonNode>, resources: &[ResourceKey]) {
        for key in resources {
            let Some(r) = self.resources.get(key) else {
                warn!("Resource {:?} not found when releasing", key);
                continue;
            };

            r.release(node);
        }
    }

    pub fn reset_resource_pool(&self) {
        self.resource_pool.clear();

        for ty in ResourceType::iter() {
            let candidates = self.compute_candidates_for_challenge(ty);
            if !candidates.is_empty() {
                self.resource_pool.insert(ty, RoundRobinPool::new(candidates));
            }
        }
    }

    pub fn find_resource_for_challenge(
        &self,
        challenge_type: ResourceType,
    ) -> Option<(ResourceKey, Arc<ArgonNode>)> {
        if let Some(pool) = self.resource_pool.get(&challenge_type) {
            return Some(pool.next());
        }

        warn!("failed to pick any candidates for resource type {:?}", challenge_type);
        None
    }

    pub fn supports_resource_type(&self, ty: ResourceType) -> bool {
        self.resource_pool.contains_key(&ty)
    }

    pub async fn get_nodes(&self) -> Vec<Arc<ArgonNode>> {
        self.nodes.lock().await.clone()
    }

    pub fn any_nodes_up(&self) -> bool {
        self.node_count.load(Ordering::Relaxed) > 0
    }

    fn compute_candidates_for_challenge(
        &self,
        prefer_type: ResourceType,
    ) -> Vec<(ResourceKey, Arc<ArgonNode>)> {
        self.resources
            .iter()
            .filter(|(k, _)| k.r#type == prefer_type)
            .flat_map(|(k, v)| v.nodes().into_iter().map(|n| (*k, n)))
            .collect::<Vec<_>>()
    }
}
