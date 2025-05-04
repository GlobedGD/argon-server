use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};

use argon_shared::{WorkerAuthMessage, logger::*};
use nohash_hasher::IntMap;
use parking_lot::Mutex as SyncMutex;
use rand::Rng;
use tokio::{
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::MissedTickBehavior,
};

use crate::{
    api_token_manager::ApiTokenManager, config::ServerConfig, health_state::ServerHealthState,
    ip_blocker::IpBlocker, node_handler::NodeHandler, rate_limiter::RateLimiter, token_issuer::TokenIssuer,
};

pub enum ChallengeValidationError {
    NoChallenge,
    WrongSolution,
    WrongAccount,
}

pub struct AuthChallenge {
    pub account_id: i32,
    pub user_id: i32,
    pub username: String,
    pub actual_username: String,
    pub challenge_answer: i32,
    pub started_at: SystemTime,
    pub force_strong: bool,
    pub validated: bool,
    pub validated_strong: bool,
    pub user_comment_id: i32,
}

fn compute_server_ident(secret_key: &str) -> String {
    // the server ident is a truncated hash of our secret key hexstring
    let mut res = blake3::hash(secret_key.as_bytes()).to_hex().to_string();

    res.truncate(16);

    res
}

pub struct ServerStateData {
    pub config_path: PathBuf,
    pub config: ServerConfig,
    pub token_issuer: Arc<TokenIssuer>,
    pub ip_blocker: Arc<IpBlocker>,
    pub rate_limiter: Arc<SyncMutex<RateLimiter>>,
    pub api_token_manager: Arc<ApiTokenManager>,
    active_challenges: SyncMutex<IntMap<u32, AuthChallenge>>,

    // node handler stuff
    pub node_handler: Option<Arc<NodeHandler>>,
    pub health_state: Arc<ServerHealthState>,
}

impl ServerStateData {
    pub fn new(config_path: PathBuf, config: ServerConfig) -> Self {
        let server_ident = compute_server_ident(&config.secret_key);

        let rate_limiter = Arc::new(SyncMutex::new(RateLimiter::new(&config)));
        let token_issuer = Arc::new(
            TokenIssuer::new(&config.secret_key, server_ident.clone()).expect("Failed to create TokenIssuer"),
        );
        let ip_blocker = Arc::new(IpBlocker::new(config.cloudflare_protection));
        let api_token_manager = Arc::new(
            ApiTokenManager::new(&config.secret_key, server_ident.clone(), rate_limiter.clone())
                .expect("Failed to create ApiTokenManager"),
        );

        Self {
            rate_limiter,
            config,
            config_path,
            active_challenges: SyncMutex::new(IntMap::default()),
            node_handler: None,
            health_state: Arc::new(ServerHealthState::new(server_ident)),
            token_issuer,
            ip_blocker,
            api_token_manager,
        }
    }

    pub fn ident(&self) -> &str {
        &self.health_state.ident
    }

    /// creates a new challenge, returns the challenge id and value to the user.
    pub fn create_challenge(
        &self,
        account_id: i32,
        user_id: i32,
        account_name: String,
        force_strong: bool,
    ) -> anyhow::Result<(u32, i32)> {
        let challenge_value = rand::rng().random::<i32>();
        let challenge_id = rand::rng().random::<u32>();
        let answer = Self::make_challenge_answer(challenge_value);

        let challenge = AuthChallenge {
            account_id,
            user_id,
            username: account_name,
            actual_username: String::new(),
            challenge_answer: answer,
            started_at: SystemTime::now(),
            force_strong,
            validated: false,
            validated_strong: false,
            user_comment_id: 0,
        };

        self.active_challenges.lock().insert(challenge_id, challenge);

        Ok((challenge_id, challenge_value))
    }

    /// Returns whether the challenge has been validated, first bool is validated, second is strong validation.
    /// Returns an error if no challenge exists for the given challenge ID, or other errors have occurred.
    pub fn is_challenge_validated(
        &self,
        challenge_id: u32,
        account_id: i32,
        solution: i32,
    ) -> Result<(bool, bool), ChallengeValidationError> {
        let challenges = self.active_challenges.lock();
        let challenge = challenges.get(&challenge_id);

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

    pub fn erase_challenge(&self, challenge_id: u32) -> Option<AuthChallenge> {
        self.active_challenges.lock().remove(&challenge_id)
    }

    pub async fn validate_challenges(&self, messages: Vec<WorkerAuthMessage>) {
        // this is pretty inefficient as it has n*m time complexity but what can we do :p

        self.active_challenges.lock().values_mut().for_each(|challenge| {
            for message in &messages {
                if message.account_id != challenge.account_id
                    || message.user_id != challenge.user_id
                    || message.challenge_answer != challenge.challenge_answer
                {
                    continue;
                }

                // we found a matching message

                challenge.user_comment_id = message.message_id;
                challenge.validated = true;
                challenge.actual_username = message.username.clone();

                // validate username for strong integrity
                challenge.validated_strong = message
                    .username
                    .trim()
                    .eq_ignore_ascii_case(challenge.username.trim());

                trace!(
                    "validated challenge for {} (strong: {})",
                    challenge.account_id, challenge.validated_strong
                );

                break;
            }
        });
    }

    pub fn make_challenge_answer(challenge: i32) -> i32 {
        challenge ^ 0x5F3759DF
    }

    pub async fn run_cleanup(&mut self) {
        self.active_challenges
            .lock()
            .retain(|_k, v| v.started_at.elapsed().unwrap_or_default() < Duration::from_mins(3));
    }

    pub async fn notify_config_change(&mut self) {
        self.ip_blocker.set_enabled(self.config.cloudflare_protection);
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

    pub async fn run_cleanup_loop(&self) -> ! {
        let mut interval = tokio::time::interval(Duration::from_mins(15));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        interval.tick().await;

        let mut counter = 0usize;

        loop {
            interval.tick().await;

            let mut state = self.state_write().await;
            state.run_cleanup().await;

            // every hour, clear the rate limiter cache

            counter += 1;
            if counter == 4 {
                counter = 0;
                let mut limiter = state.rate_limiter.lock();
                limiter.clear_cache();
                let results = limiter.record_hourly_results();
                drop(limiter);
                drop(state);

                // TODO: do smth with the results, store in a db

                let sum: usize = results.clients.iter().map(|x| x.1.validations).sum();

                info!("Hourly logs for token validation:");
                info!("- Total validations: {sum}");

                // sort by numver of validated tokens
                let mut items = results.clients.iter().collect::<Vec<_>>();
                items.sort_by_key(|(_, res)| res.validations);

                for (ip, results) in items.iter().rev() {
                    info!("- {} validations by {}", results.validations, ip);
                }
            }
        }
    }
}
