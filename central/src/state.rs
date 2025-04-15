use std::{
    collections::HashMap,
    net::IpAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::bail;
use argon_shared::WorkerAuthMessage;
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
    pub validated: bool,
    pub validated_strong: bool,
}

pub enum ChallengeValidationError {
    NoChallenge,
    WrongSolution,
    WrongAccount,
}

pub struct ServerStateData {
    pub config_path: PathBuf,
    pub config: ServerConfig,
    active_challenges: HashMap<IpAddr, AuthChallenge>,

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
        let answer = Self::make_challenge_answer(challenge_value);

        let challenge = AuthChallenge {
            account_id,
            user_id,
            username: account_name,
            challenge_value,
            challenge_answer: answer,
            started_at: SystemTime::now(),
            validated: false,
            validated_strong: false,
        };

        self.active_challenges.insert(ip_address, challenge);

        Ok(challenge_value)
    }

    /// Returns whether the challenge has been validated, first bool is validated, second is strong validation.
    /// Returns None if no challenge exists for this IP.
    pub fn is_challenge_validated(
        &self,
        ip_address: IpAddr,
        account_id: i32,
        solution: i32,
    ) -> Result<(bool, bool), ChallengeValidationError> {
        let challenge = self.active_challenges.get(&ip_address);

        if let Some(c) = challenge {
            if c.account_id != account_id {
                return Err(ChallengeValidationError::WrongAccount);
            }

            if c.challenge_answer != solution {
                return Err(ChallengeValidationError::WrongSolution);
            }

            Ok((c.validated, c.validated_strong))
        } else {
            Err(ChallengeValidationError::NoChallenge)
        }
    }

    pub async fn pick_id_for_message_challenge(&self) -> Option<i32> {
        let node_handler = self.node_handler.as_ref().unwrap();
        node_handler.pick_challenge_account_id().await
    }

    pub fn erase_challenge(&mut self, ip_address: IpAddr) {
        self.active_challenges.remove(&ip_address);
    }

    pub async fn validate_challenges(&mut self, messages: Vec<WorkerAuthMessage>) {
        // this is pretty inefficient as it has n*m time complexity but what can we do :p

        self.active_challenges.values_mut().for_each(|challenge| {
            for message in &messages {
                if message.account_id != challenge.account_id
                    || message.user_id != challenge.user_id
                    || message.challenge_answer != challenge.challenge_answer
                {
                    continue;
                }

                // we found a matching message
                challenge.validated = true;

                // validate username for strong integrity
                if message.username.trim().eq_ignore_ascii_case(challenge.username.trim()) {
                    challenge.validated_strong = true;
                }

                break;
            }
        });
    }

    pub fn make_challenge_answer(challenge: i32) -> i32 {
        challenge ^ 0x5F3759DF
    }

    pub async fn notify_config_change(&self) {
        self.node_handler.as_ref().unwrap().notify_config_change().await;
    }
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
