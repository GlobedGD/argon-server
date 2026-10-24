use std::{
    net::SocketAddr,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
    time::Duration,
};

use parking_lot::Mutex;
use shared::{
    message::{UserChallenge, UserChallengeResult},
    resource::ResourceKey,
};

use crate::node_manager::performance_tracker::PerformanceTracker;

pub struct ArgonNode {
    pub address: SocketAddr,
    pub authorized: AtomicBool,
    pub used_resources: Mutex<Vec<ResourceKey>>,
    pub id: u64,
    pub perf_tracker: Mutex<PerformanceTracker>,

    poor_perf_counter: AtomicU32,
    total_challenges_completed: AtomicU32,

    queued_challenges: Mutex<Vec<UserChallenge>>,
    queued_should_poll: Mutex<Vec<u32>>,
    queued_cleanups: Mutex<Vec<u32>>,
    pending_results: Mutex<Vec<UserChallengeResult>>,
}

impl ArgonNode {
    pub fn new(address: SocketAddr) -> Self {
        ArgonNode {
            address,
            authorized: AtomicBool::new(false),
            used_resources: Mutex::new(Vec::new()),
            id: rand::random(),
            perf_tracker: Mutex::new(PerformanceTracker::new()),
            poor_perf_counter: AtomicU32::new(0),
            total_challenges_completed: AtomicU32::new(0),
            queued_challenges: Mutex::new(Vec::new()),
            queued_should_poll: Mutex::new(Vec::new()),
            queued_cleanups: Mutex::new(Vec::new()),
            pending_results: Mutex::new(Vec::new()),
        }
    }

    pub fn authorized(&self) -> bool {
        self.authorized.load(Ordering::Relaxed)
    }

    pub fn set_authorized(&self, authorized: bool) {
        self.authorized.store(authorized, Ordering::Relaxed);
    }

    pub fn success_rate(&self, window: Duration) -> f64 {
        self.perf_tracker.lock().success_rate(window)
    }

    pub fn inc_poor_perf(&self) {
        self.poor_perf_counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_poor_perf(&self) {
        let mut c = self.poor_perf_counter.load(Ordering::Relaxed);

        loop {
            if c == 0 {
                break;
            }

            let new = c - 1;

            match self.poor_perf_counter.compare_exchange(c, new, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(current) => c = current,
            }
        }
    }

    pub fn poor_perf_count(&self) -> u32 {
        self.poor_perf_counter.load(Ordering::Relaxed)
    }

    pub fn queue_challenge(&self, resource_key: ResourceKey, account_id: i32, challenge_id: u32) {
        self.queued_challenges.lock().push(UserChallenge {
            resource: resource_key,
            account_id,
            challenge_id,
        });
    }

    pub fn queue_cleanup(&self, challenge_id: u32) {
        self.queued_cleanups.lock().push(challenge_id);
    }

    pub fn queue_should_poll(&self, challenge_id: u32) {
        self.queued_should_poll.lock().push(challenge_id);
    }

    pub fn queue_results(&self, results: &[UserChallengeResult]) {
        self.pending_results.lock().extend(results.iter().cloned());

        let mut tracker = self.perf_tracker.lock();
        for result in results {
            tracker.log(result.outcome);
        }

        self.total_challenges_completed.fetch_add(results.len() as u32, Ordering::Relaxed);
    }

    pub fn challenges_completed(&self) -> u32 {
        self.total_challenges_completed.load(Ordering::Relaxed)
    }

    pub fn get_queued_challenges(&self) -> Vec<UserChallenge> {
        std::mem::take(&mut *self.queued_challenges.lock())
    }

    pub fn get_queued_cleanups(&self) -> Vec<u32> {
        std::mem::take(&mut *self.queued_cleanups.lock())
    }

    pub fn get_queued_should_poll(&self) -> Vec<u32> {
        std::mem::take(&mut *self.queued_should_poll.lock())
    }

    pub fn get_pending_results(&self) -> Vec<UserChallengeResult> {
        std::mem::take(&mut *self.pending_results.lock())
    }
}
