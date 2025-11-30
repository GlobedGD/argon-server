use std::{
    net::IpAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use argon_shared::{WorkerAuthMessage, logger::*};
use nohash_hasher::IntMap;
use parking_lot::Mutex as SyncMutex;
use rand::Rng;
use tokio::{
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard, mpsc},
    time::MissedTickBehavior,
};

use crate::{
    api_token_manager::ApiTokenManager,
    config::ServerConfig,
    database::{ArgonDbPool, TokenLog},
    health_state::ServerHealthState,
    ip_blocker::IpBlocker,
    node_handler::NodeHandler,
    rate_limiter::RateLimiter,
    token_issuer::TokenIssuer,
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
    pub requested_mod: String,
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
    pub database: Arc<ArgonDbPool>,
    active_challenges: SyncMutex<IntMap<u32, AuthChallenge>>,
    token_log_tx: mpsc::Sender<TokenLog>,
    token_log_rx: Option<mpsc::Receiver<TokenLog>>,

    // node handler stuff
    pub node_handler: Option<Arc<NodeHandler>>,
    pub health_state: Arc<ServerHealthState>,
}

impl ServerStateData {
    pub fn new(config_path: PathBuf, config: ServerConfig, database: Arc<ArgonDbPool>) -> Self {
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

        let (token_log_tx, token_log_rx) = mpsc::channel(128);

        Self {
            rate_limiter,
            config,
            config_path,
            database,
            token_log_tx,
            token_log_rx: Some(token_log_rx),
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
        requested_mod: String,
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
            requested_mod,
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

    pub async fn submit_token_log(&self, log: TokenLog) {
        let _ = self.token_log_tx.send(log).await;
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

                enum IpOrName<'a> {
                    Ip(&'a IpAddr),
                    Name(&'a String),
                }

                let mut items = results
                    .clients
                    .iter()
                    .map(|x| (IpOrName::Ip(x.0), x.1.validations))
                    .collect::<Vec<_>>();

                let sum_1: usize = items.iter().map(|x| x.1).sum();

                items.extend(
                    results
                        .reg_clients
                        .iter()
                        .map(|x| (IpOrName::Name(&x.1.name), x.1.validations)),
                );

                let sum: usize = items.iter().map(|x| x.1).sum();
                let sum_2 = sum - sum_1;

                info!("Hourly logs for token validation:");
                info!("- Total validations: {sum} (from registered: {sum_2}, unregistered: {sum_1})");

                // sort by number of validated tokens
                items.sort_by_key(|(_, res)| *res);

                for (ip_or_name, validations) in items.iter().rev() {
                    match ip_or_name {
                        IpOrName::Ip(ip) => info!("- {} validations by {}", validations, ip),
                        IpOrName::Name(name) => {
                            info!("- {} validations by {} (registered)", validations, name);
                        }
                    }
                }
            }
        }
    }

    // this function flushes the logs way more often in debug mode for testing purpose
    pub async fn run_token_log_worker(&self) {
        let retention_period = {
            let state = self.state_read().await;
            if !state.config.enable_anonymous_logs {
                return;
            }

            Duration::from_secs(state.config.log_retention as u64)
        };

        let mut rx = self.state_write().await.token_log_rx.take().unwrap();

        let interval = if cfg!(debug_assertions) {
            Duration::from_secs(3)
        } else {
            Duration::from_mins(3)
        };
        let delete_interval = interval * 20;

        let mut interval = tokio::time::interval(interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Burst);

        let mut batch = Vec::new();
        let mut last_commit = Instant::now();
        let mut last_deletion = Instant::now();

        loop {
            let mut commit = false;

            tokio::select! {
                _ = interval.tick() => {
                    commit = !batch.is_empty();

                    if !cfg!(debug_assertions) {
                        commit |= last_commit.elapsed() >= Duration::from_secs(60);
                    }
                },

                log = rx.recv() => match log {
                    Some(log) => {
                        batch.push(log);
                        if batch.len() >= 50 {
                            commit = true;
                        }
                    },
                    None => break,
                }
            }

            if commit {
                last_commit = Instant::now();

                if let Err(e) = self._commit_token_logs(std::mem::take(&mut batch)).await {
                    error!("Failed to commit token logs: {e}");
                }
            }

            if last_deletion.elapsed() >= delete_interval {
                // delete old logs every once in a while
                last_deletion = Instant::now();

                if let Err(e) = self._delete_old_token_logs(retention_period).await {
                    error!("Failed to delete old token logs: {e}");
                }
            }
        }
    }

    async fn _commit_token_logs(&self, batch: Vec<TokenLog>) -> anyhow::Result<()> {
        if batch.is_empty() {
            return Ok(());
        }

        info!("Committing {} token logs to the database", batch.len());

        self.state_read()
            .await
            .database
            .get_one()
            .await
            .map_err(|e| anyhow::anyhow!(e))?
            .insert_token_logs(batch)
            .await?;

        Ok(())
    }

    async fn _delete_old_token_logs(&self, period: Duration) -> anyhow::Result<()> {
        let deleted = self
            .state_read()
            .await
            .database
            .get_one()
            .await
            .map_err(|e| anyhow::anyhow!(e))?
            .delete_old_token_logs(period)
            .await?;

        if deleted > 0 {
            info!("Deleted {} old token logs from the database", deleted);
        }

        Ok(())
    }
}
