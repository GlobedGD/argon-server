use std::time::{Duration, Instant};

use shared::message::UserChallengeOutcome;

const BUCKET_SECS: u64 = 10;
const BUCKETS: usize = 180;

#[derive(Clone, Copy, Default)]
struct Bucket {
    id: u64,
    success: u32,
    failure: u32,
}

/// Tracks performance of "something". What exactly is up to you.
#[derive(Clone)]
pub struct PerformanceTracker {
    epoch: Instant,
    buckets: Box<[Bucket; BUCKETS]>,
    poor_since: Option<Instant>,
}

impl PerformanceTracker {
    pub fn new() -> Self {
        Self {
            epoch: Instant::now(),
            buckets: Box::new([Bucket::default(); BUCKETS]),
            poor_since: None,
        }
    }

    pub fn log(&mut self, outcome: UserChallengeOutcome) {
        match outcome {
            UserChallengeOutcome::Success => self.log_success(),
            _ => self.log_failure(),
        }
    }

    pub fn log_success(&mut self) {
        self.log_inner(true);
    }

    pub fn log_failure(&mut self) {
        self.log_inner(false);
    }

    fn log_inner(&mut self, success: bool) {
        let bucket_id = self.epoch.elapsed().as_secs() / BUCKET_SECS;
        let bucket_index = (bucket_id as usize) % BUCKETS;

        let bucket = &mut self.buckets[bucket_index];
        if bucket.id != bucket_id {
            // reset this bucket
            *bucket = Bucket {
                id: bucket_id,
                success: 0,
                failure: 0,
            };
        }

        if success {
            bucket.success += 1;
        } else {
            bucket.failure += 1;
        }
    }

    pub fn success_rate(&self, window: Duration) -> f64 {
        let current_bucket_id = self.epoch.elapsed().as_secs() / BUCKET_SECS;
        let span = window.as_secs() / BUCKET_SECS;
        let start_bucket_id = current_bucket_id.saturating_sub(span);

        let mut successes = 0u64;
        let mut total = 0u64;

        for id in start_bucket_id..=current_bucket_id {
            let bucket = &self.buckets[(id as usize) % BUCKETS];
            if bucket.id != id {
                continue;
            }

            successes += bucket.success as u64;
            total += (bucket.success + bucket.failure) as u64;
        }

        if total == 0 {
            1.0
        } else {
            successes as f64 / total as f64
        }
    }

    pub fn update_health(&mut self, now: Instant, sustain: Duration) -> bool {
        let healthy = self.success_rate(Duration::from_mins(5)) >= 0.75
            && self.success_rate(Duration::from_mins(1)) >= 0.5;

        if healthy {
            self.poor_since = None;
            false
        } else {
            let since = *self.poor_since.get_or_insert(now);
            now.duration_since(since) >= sustain
        }
    }
}
