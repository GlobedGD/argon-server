use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use shared::message::UserChallengeOutcome;

/// Tracks performance of "something". What exactly is up to you.
#[derive(Clone)]
pub struct PerformanceTracker {
    entries: VecDeque<(bool, Instant)>,
    last_cleanup: Instant,
}

const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const CLEANUP_WINDOW: Duration = Duration::from_mins(30);
const MAX_ENTRIES: usize = 16384;

impl PerformanceTracker {
    pub fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            last_cleanup: Instant::now(),
        }
    }

    pub fn log(&mut self, outcome: UserChallengeOutcome) {
        match outcome {
            UserChallengeOutcome::Success => self.log_success(),
            _ => self.log_failure(),
        }
    }

    pub fn log_success(&mut self) {
        self.entries.push_back((true, Instant::now()));
        self.maybe_cleanup();
    }

    pub fn log_failure(&mut self) {
        self.entries.push_back((false, Instant::now()));
        self.maybe_cleanup();
    }

    fn maybe_cleanup(&mut self) {
        if self.last_cleanup.elapsed() < CLEANUP_INTERVAL || self.entries.is_empty() {
            return;
        }

        let now = Instant::now();
        self.last_cleanup = now;
        let cutoff = now - CLEANUP_WINDOW;

        // erase everything that's too old or exceeds the max entries limit
        let first_kept = self.entries.iter().position(|&(_, t)| t >= cutoff).unwrap_or(self.entries.len());
        let to_keep = (self.entries.len() - first_kept).min(MAX_ENTRIES);
        let actual_first_kept = self.entries.len() - to_keep;

        self.entries.drain(..actual_first_kept);
    }

    pub fn success_rate(&self, window: Duration) -> f64 {
        let cutoff = Instant::now() - window;

        // find cutoff index via binary search
        let first_matching = self.entries.binary_search_by_key(&cutoff, |&(_, t)| t).unwrap_or_else(|x| x);
        let (successes, total) = self
            .entries
            .range(first_matching..)
            .fold((0usize, 0usize), |(successes, total), &(s, _)| (successes + s as usize, total + 1));

        if total == 0 {
            1.0
        } else {
            successes as f64 / total as f64
        }
    }
}
