use std::{
    collections::HashMap,
    net::IpAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::bail;
use rand::Rng;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::{config::ServerConfig, node_handler::NodeHandler};

struct AuthChallenge {
    pub account_id: i32,
    pub user_id: i32,
    pub username: String,
    pub challenge_value: i32,
    pub challenge_answer: i32,
    pub started_at: SystemTime,
}

pub struct ServerStateData {
    pub config_path: PathBuf,
    pub config: ServerConfig,
    pub active_challenges: HashMap<IpAddr, AuthChallenge>,

    // node handler stuff
    pub node_handler: Option<Arc<NodeHandler>>,
    pub node_count: usize,
    pub active_node_count: usize,
}

impl ServerStateData {
    pub fn new(config_path: PathBuf, config: ServerConfig) -> Self {
        Self {
            config,
            config_path,
            active_challenges: HashMap::new(),
            node_handler: None,
            node_count: 0,
            active_node_count: 0,
        }
    }

    /// creates a new challenge, returns the challenge value to the user.
    /// returns error if challenge already exists for the ip address and `return_existing` is false
    pub fn create_challenge(
        &mut self,
        account_id: i32,
        user_id: i32,
        account_name: String,
        ip_address: IpAddr,
        return_existing: bool,
    ) -> anyhow::Result<i32> {
        // check if a challenge already exists for this ip and it has not expired
        if let Some(c) = self.active_challenges.get(&ip_address)
            && c.started_at.elapsed()? < Duration::from_secs(120)
        {
            if c.account_id != account_id || c.user_id != user_id || c.username != account_name {
                bail!("challenge already exists for this IP address and for a different account");
            }

            if return_existing {
                return Ok(c.challenge_value);
            }

            bail!("challenge already exists for this IP address");
        }

        let challenge_value = rand::rng().random::<i32>();
        let answer = challenge_value ^ 0x5F3759DF;

        let challenge = AuthChallenge {
            account_id,
            user_id,
            username: account_name,
            challenge_value,
            challenge_answer: answer,
            started_at: SystemTime::now(),
        };

        self.active_challenges.insert(ip_address, challenge);

        Ok(challenge_value)
    }

    pub fn erase_challenge(&mut self, ip_address: IpAddr) {
        self.active_challenges.remove(&ip_address);
    }

    pub async fn send_config_to_nodes(&self) {}
}

#[derive(Clone)]
pub struct ServerState {
    pub inner: Arc<RwLock<ServerStateData>>,
}

impl ServerState {
    pub fn new(ssd: ServerStateData) -> Self {
        Self {
            inner: Arc::new(RwLock::new(ssd)),
        }
    }

    pub async fn state_read(&self) -> RwLockReadGuard<'_, ServerStateData> {
        self.inner.read().await
    }

    pub async fn state_write(&self) -> RwLockWriteGuard<'_, ServerStateData> {
        self.inner.write().await
    }

    pub async fn node_handler(&self) -> Arc<NodeHandler> {
        self.state_read()
            .await
            .node_handler
            .clone()
            .expect("NodeHandler must be initialized by now")
    }
}
