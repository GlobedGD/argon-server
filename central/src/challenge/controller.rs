use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

use crate::{
    challenge::{ChallengeError, ChallengeType, compute_challenge_pair},
    config::AppConfig,
    node_manager::{NodeManager, node::ArgonNode},
};

use super::ChallengeData;
use dashmap::DashMap;
use parking_lot::Mutex;
use shared::{
    message::{GDAccountData, UserChallengeOutcome},
    resource::ResourceKey,
};
use tracing::warn;

const CHALLENGE_TIMEOUT: Duration = Duration::from_secs(30);
const CHALLENGE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_PENDING_CHALLENGES: usize = 1024;

struct PendingChallenge {
    answer: u32,
    id: u32,
    account_id: i32,
    started_at: Instant,
    node: Arc<ArgonNode>,
    still_pending: AtomicBool,
    result: Mutex<Option<Result<GDAccountData, ChallengeError>>>,
}

impl PendingChallenge {
    // Run once the challenge is completed or timed out, will tell the node to clean up the state
    pub fn deregister(&self) {
        if self.still_pending.swap(false, Ordering::Relaxed) {
            self.node.queue_cleanup(self.id);
        }
    }

    pub fn no_deregister(&self) {
        self.still_pending.store(false, Ordering::Relaxed);
    }

    pub fn get_result(&self) -> Result<Option<GDAccountData>, ChallengeError> {
        self.result.lock().take().transpose()
    }
}

impl Drop for PendingChallenge {
    fn drop(&mut self) {
        self.deregister();
    }
}

pub struct ChallengeController {
    next_challenge_id: AtomicU32,
    pending_challenges: DashMap<u32, PendingChallenge>,
    node_manager: Arc<NodeManager>,
}

impl ChallengeController {
    pub fn new(_config: &AppConfig, node_manager: Arc<NodeManager>) -> Self {
        Self {
            next_challenge_id: AtomicU32::new(0),
            pending_challenges: DashMap::new(),
            node_manager,
        }
    }

    pub fn run_cleanup(&self) {
        let now = Instant::now();
        let cutoff = now - CHALLENGE_CLEANUP_TIMEOUT;

        self.pending_challenges.retain(|_, c| c.started_at > cutoff);
    }

    pub fn node_manager(&self) -> &Arc<NodeManager> {
        &self.node_manager
    }

    pub fn start_challenge(
        &self,
        account_id: i32,
        challenge_type: ChallengeType,
    ) -> Result<ChallengeData, ChallengeError> {
        if self.pending_challenges.len() >= MAX_PENDING_CHALLENGES {
            return Err(ChallengeError::TooManyChallengesInProgress);
        }

        let (resource_key, node) = self.find_resource_for_challenge(challenge_type)?;
        let (secret, answer) = compute_challenge_pair();
        let challenge_id = self.next_challenge_id.fetch_add(1, Ordering::Relaxed);

        // tell the node to start watching for the challenge result
        node.queue_challenge(resource_key, account_id, challenge_id);

        self.pending_challenges.insert(
            challenge_id,
            PendingChallenge {
                id: challenge_id,
                answer,
                account_id,
                started_at: Instant::now(),
                node,
                still_pending: AtomicBool::new(true),
                result: Mutex::new(None),
            },
        );

        Ok(ChallengeData {
            r#type: resource_key.r#type.into(),
            resource_id: resource_key.id,
            challenge_id,
            secret,
        })
    }

    pub fn poll_challenge(&self, challenge_id: u32) -> Result<Option<GDAccountData>, ChallengeError> {
        let node = match self.pending_challenges.get(&challenge_id) {
            None => Err(ChallengeError::ChallengeNotFound)?,
            Some(c) => c.node.clone(),
        };

        // drive progres on all messages, unconditionally
        self.process_pending_results_from_node(&node);

        // and check again
        let result = {
            let challenge =
                self.pending_challenges.get(&challenge_id).ok_or(ChallengeError::ChallengeNotFound)?;

            if challenge.started_at.elapsed() > CHALLENGE_TIMEOUT {
                Err(ChallengeError::TimedOut)
            } else {
                challenge.get_result()
            }
        };

        // remove challenge only if the result is not Ok(None), aka pending
        let terminal = matches!(result, Ok(Some(_)) | Err(_));
        if terminal {
            self.pending_challenges.remove(&challenge_id);
        }

        result
    }

    fn process_pending_results_from_node(&self, node: &ArgonNode) {
        for result in node.get_pending_results() {
            let Some(c) = self.pending_challenges.get(&result.challenge_id) else {
                warn!("worker sent unknown challenge ID: {}", result.challenge_id);
                continue;
            };

            *c.result.lock() = Some(if result.outcome == UserChallengeOutcome::Success {
                let Some(data) = result.account_data else {
                    warn!("worker sent no account data for completed challenge ID: {}", result.challenge_id);
                    continue;
                };

                if data.account_id != c.account_id {
                    warn!(
                        "wrong account ID in challenge result: {} (expected {})",
                        data.account_id, c.account_id
                    );
                    continue;
                }

                if result.answer == c.answer {
                    Ok(data)
                } else {
                    Err(ChallengeError::IncorrectAnswer)
                }
            } else {
                Err(result.outcome.into())
            });

            // because we received a reply for this auth challenge from the node, the node automatically deregisters the challenge
            c.no_deregister();
        }
    }

    fn find_resource_for_challenge(
        &self,
        challenge_type: ChallengeType,
    ) -> Result<(ResourceKey, Arc<ArgonNode>), ChallengeError> {
        self.node_manager
            .find_resource_for_challenge(challenge_type.into())
            .ok_or(ChallengeError::NoAvailableResource)
    }

    pub fn pick_supported_challenge_type(
        &self,
        client_supported: &[ChallengeType],
    ) -> Result<ChallengeType, ChallengeError> {
        // challenge types sorted in order of preference
        const ALL_CHALLENGES: &[ChallengeType] = &[ChallengeType::Comment, ChallengeType::ProfileField];

        for &c in ALL_CHALLENGES {
            if !client_supported.contains(&c) {
                continue;
            }

            if self.node_manager.supports_resource_type(c.into()) {
                return Ok(c);
            }
        }

        Err(ChallengeError::ChallengeTypeNotSupported)
    }
}
