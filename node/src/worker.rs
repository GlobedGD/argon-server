use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Duration,
};

use shared::{
    message::{UserChallenge, UserChallengeOutcome, UserChallengeResult},
    resource::{ResourceKey, ResourceType},
};
use tokio::{
    sync::mpsc,
    time::{MissedTickBehavior, interval},
};
use tracing::{debug, error, info, warn};

use crate::{config::NodeConfig, gd::Client as GDClient};

struct PendingChallenge {
    account_id: i32,
    challenge_id: u32,
    should_poll: AtomicBool,
    resource: ResourceKey,
}

struct WorkerResource {
    pending_ids: HashMap<u32, Arc<PendingChallenge>>,
    queue: Option<VecDeque<Arc<PendingChallenge>>>,
    consecutive_errors: AtomicU32,
}

impl WorkerResource {
    pub fn new(uses_queue: bool) -> Self {
        Self {
            pending_ids: HashMap::new(),
            queue: uses_queue.then_some(VecDeque::new()),
            consecutive_errors: AtomicU32::new(0),
        }
    }

    pub fn add_pending(&mut self, challenge: Arc<PendingChallenge>) {
        self.pending_ids.insert(challenge.challenge_id, challenge.clone());
        if let Some(queue) = &mut self.queue {
            queue.push_back(challenge);
        }
    }

    /// Returns whether removal was successful
    pub fn remove_pending(&mut self, challenge_id: u32, account_id: i32) -> bool {
        let challenge = self.pending_ids.get(&challenge_id);
        if challenge.is_some_and(|c| c.account_id == account_id) {
            self.pending_ids.remove(&challenge_id);
            if let Some(queue) = &mut self.queue {
                queue.retain(|c| c.challenge_id != challenge_id);
            }
            true
        } else {
            false // not found or account_id mismatch
        }
    }

    pub fn evict_all(&mut self) -> Vec<Arc<PendingChallenge>> {
        let evicted = self.pending_ids.drain().map(|(_, c)| c).collect::<Vec<_>>();
        if let Some(queue) = &mut self.queue {
            queue.clear();
        }
        evicted
    }

    pub fn on_error(&self) {
        self.consecutive_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn consecutive_errors(&self) -> u32 {
        self.consecutive_errors.load(Ordering::Relaxed)
    }

    pub fn reset_errors(&self) {
        self.consecutive_errors.store(0, Ordering::Relaxed);
    }
}

pub struct NodeWorkerChallenges {
    pub challenges: Vec<UserChallenge>,
    pub cleanups: Vec<u32>,
    pub should_poll: Vec<u32>,
}

pub struct NodeWorker {
    client: GDClient,
    resources: HashMap<ResourceKey, WorkerResource>,
    challenges: HashMap<u32, Arc<PendingChallenge>>,
    result_tx: mpsc::Sender<UserChallengeResult>,
    incoming_rx: mpsc::Receiver<NodeWorkerChallenges>,
}

impl NodeWorker {
    pub fn new(
        config: &NodeConfig,
        resources: Vec<ResourceKey>,
        result_tx: mpsc::Sender<UserChallengeResult>,
        incoming_rx: mpsc::Receiver<NodeWorkerChallenges>,
    ) -> Self {
        Self {
            client: GDClient::new(config.gd.url.clone(), config.gd.auth_token.clone()),
            resources: resources
                .into_iter()
                .map(|key| (key, WorkerResource::new(uses_queue(key.r#type))))
                .collect(),
            challenges: HashMap::new(),
            result_tx,
            incoming_rx,
        }
    }

    pub fn handle_new_challenges(&mut self, challenges: &[UserChallenge]) {
        for c in challenges {
            let Some(resource) = self.resources.get_mut(&c.resource) else {
                continue;
            };

            let challenge = Arc::new(PendingChallenge {
                account_id: c.account_id,
                challenge_id: c.challenge_id,
                should_poll: AtomicBool::new(should_poll_eager(c.resource.r#type)),
                resource: c.resource,
            });

            resource.add_pending(challenge.clone());
            self.challenges.insert(c.challenge_id, challenge);
        }
    }

    pub fn cleanup_challenges(&mut self, ids: &[u32]) {
        for id in ids {
            let Some(challenge) = self.challenges.remove(id) else {
                continue;
            };

            if let Some(resource) = self.resources.get_mut(&challenge.resource) {
                resource.remove_pending(challenge.challenge_id, challenge.account_id);
            }
        }
    }

    pub fn handle_should_poll(&mut self, ids: &[u32]) {
        for id in ids {
            let Some(challenge) = self.challenges.get(id) else {
                continue;
            };

            challenge.should_poll.store(true, Ordering::Relaxed);
        }
    }

    pub async fn run(mut self) {
        let mut interval = interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.process_resource_batch().await;
                }

                Some(msg) = self.incoming_rx.recv() => {
                    self.handle_new_challenges(&msg.challenges);
                    self.cleanup_challenges(&msg.cleanups);
                    self.handle_should_poll(&msg.should_poll);
                }
            }
        }
    }

    async fn process_resource_batch(&mut self) {
        let mut results = Vec::new();

        let keys = self.resources.keys().copied().collect::<Vec<_>>();
        for key in keys {
            let resource = self.resources.get_mut(&key).unwrap();

            let r_results = match key.r#type {
                ResourceType::Level => Self::process_level_resource(&self.client, key, resource).await,
                ResourceType::ProfileField => {
                    Self::process_profile_field_resource(&self.client, resource, false).await
                }

                ResourceType::LegacyProfileField => {
                    Self::process_profile_field_resource(&self.client, resource, true).await
                }
            };

            if let Some(r_results) = r_results {
                results.extend(r_results);
                resource.reset_errors();

                for result in &results {
                    self.challenges.remove(&result.challenge_id);
                }
            } else {
                resource.on_error();
                if resource.consecutive_errors() >= 5 {
                    // this resource is consistently failing and likely currently unusable,
                    // we should evict all challenges that are pending on it and mark them as failed
                    for pending in resource.evict_all() {
                        results.push(UserChallengeResult::new_failure(
                            pending.account_id,
                            pending.challenge_id,
                            UserChallengeOutcome::ResourceFailing,
                        ));
                    }

                    self.challenges.retain(|_, c| c.resource != key);
                }
            }
        }

        for result in results {
            let _ = self.result_tx.send(result).await;
        }
    }

    async fn process_level_resource(
        client: &GDClient,
        key: ResourceKey,
        resource: &mut WorkerResource,
    ) -> Option<Vec<UserChallengeResult>> {
        if resource.pending_ids.is_empty() {
            return Some(Vec::new());
        }

        // fetch comments on the level
        let comments = match client.get_level_comments(key.id).await {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to fetch comments for level {}: {:?}", key.id, e);
                return None;
            }
        };
        debug!("Fetched {} comments for level {}", comments.len(), key.id);

        let mut results = Vec::new();
        for comment in comments {
            let Some((id, secret)) = extract_id_and_secret_from_text(&comment.text) else {
                continue;
            };

            // is there a valid challenge for this id & user?
            if !resource.remove_pending(id, comment.account_id) {
                debug!("ignoring bogus comment for challenge {} from user {}", id, comment.account_id);
                continue;
            }

            // consider this challenge completed
            info!("challenge {} completed for user {}", id, comment.account_id);
            results.push(UserChallengeResult::new_success(
                comment.account_id,
                id,
                secret,
                comment.account_data(),
            ));
        }

        Some(results)
    }

    async fn process_profile_field_resource(
        client: &GDClient,
        resource: &mut WorkerResource,
        legacy: bool,
    ) -> Option<Vec<UserChallengeResult>> {
        if resource.pending_ids.is_empty() {
            return Some(Vec::new());
        }

        // fetch up to 3 users at once
        let mut budget = 3;
        let mut i = 0;

        let mut completed = Vec::new();
        let queue = resource.queue.as_ref().unwrap();

        while budget > 0 {
            let Some(challenge) = queue.get(i) else {
                break;
            };

            i += 1;
            if !challenge.should_poll.load(Ordering::Relaxed) {
                continue;
            }

            // decrement budget once we get to the part where we actually fetch something
            budget -= 1;

            let user_info = match client.get_user_info(challenge.account_id).await {
                Ok(u) => u,
                Err(e) => {
                    warn!("Failed to fetch user info for account {}: {:?}", challenge.account_id, e);
                    continue;
                }
            };

            let (id, secret) = if !legacy {
                match extract_id_and_secret_from_text(&user_info.custom) {
                    Some(ans) => ans,
                    None => continue,
                }
            } else {
                // legacy is more tricky, since the client never sent the challenge ID in the response,
                // we need to find it ourselves given the account ID
                let Some(secret) = extract_secret_from_legacy_text(&user_info.custom) else {
                    continue;
                };

                let Some((&id, _)) = resource.pending_ids.iter().find(|(_, c)| {
                    c.account_id == user_info.account_id && c.should_poll.load(Ordering::Relaxed)
                }) else {
                    continue;
                };

                (id, secret)
            };

            // consider this challenge completed
            info!("challenge {} completed for user {} (profile field)", id, user_info.account_id);
            completed.push(UserChallengeResult::new_success(
                user_info.account_id,
                id,
                secret,
                user_info.account_data(),
            ));
        }

        // remove all completed challenges from queue and resource tracker,
        // we do it outside of the loop to keep the index stable
        completed.retain(|c| resource.remove_pending(c.challenge_id, c.account_id));

        Some(completed)
    }
}

fn extract_id_and_secret_from_text(text: &str) -> Option<(u32, u32)> {
    // challenge answers have the format of "argon-<id>-<answer>"
    let text = text.strip_prefix("argon-")?;
    let (id_str, secret_str) = text.split_once('-')?;
    let id = id_str.parse::<u32>().ok()?;
    let secret = secret_str.parse::<u32>().ok()?;
    Some((id, secret))
}

fn extract_secret_from_legacy_text(text: &str) -> Option<u32> {
    // legacy challenge answers have the format of "aRg<answer>"
    let text = text.strip_prefix("aRg")?;
    let secret = text.parse::<i32>().ok()?;
    Some(secret as u32)
}

fn uses_queue(r#type: ResourceType) -> bool {
    match r#type {
        ResourceType::Level => false,
        ResourceType::ProfileField => true,
        ResourceType::LegacyProfileField => true,
    }
}

fn should_poll_eager(r#type: ResourceType) -> bool {
    match r#type {
        ResourceType::Level => true,
        ResourceType::ProfileField => false,
        ResourceType::LegacyProfileField => false,
    }
}
