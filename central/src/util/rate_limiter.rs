use std::{
    hash::Hash,
    num::NonZeroU32,
    sync::{Arc, atomic::AtomicU64},
    time::{Duration, Instant},
};

use governor::{DefaultDirectRateLimiter, Quota};
use moka::sync::Cache;

struct Entry {
    limiter: DefaultDirectRateLimiter,
}

pub struct RateLimiter<K: Hash + Eq> {
    limiters: Cache<K, Arc<Entry>>,

    replenish_1_per: Duration,
    max_burst: NonZeroU32,

    next_cleanup: AtomicU64,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RateLimitOutcome {
    Allowed,
    RateLimited { until: Instant },
}

impl<K: Hash + Eq + Send + Sync + 'static> RateLimiter<K> {
    pub fn new(max_retain: Duration, max_entries: usize) -> Self {
        Self {
            limiters: Cache::builder()
                .time_to_live(max_retain)
                .time_to_idle(Duration::from_mins(5))
                .max_capacity(max_entries as u64)
                .build(),

            replenish_1_per: Duration::from_secs(1),
            max_burst: NonZeroU32::new(1).unwrap(),
            next_cleanup: AtomicU64::new(0),
        }
    }

    pub fn set_replenish_1_per(&mut self, replenish_1_per: Duration) {
        self.replenish_1_per = replenish_1_per;
    }

    pub fn set_max_burst(&mut self, max_burst: NonZeroU32) {
        self.max_burst = max_burst;
    }

    pub fn check(&self, key: K) -> RateLimitOutcome {
        self.check_ext(key, self.replenish_1_per, self.max_burst)
    }

    pub fn check_ext(&self, key: K, replenish_1_per: Duration, max_burst: NonZeroU32) -> RateLimitOutcome {
        let entry = self.limiters.entry(key).or_insert_with(|| {
            let limiter = governor::RateLimiter::direct(
                Quota::with_period(replenish_1_per).unwrap().allow_burst(max_burst),
            );
            Arc::new(Entry { limiter })
        });

        self.tick(entry.value())
    }

    fn tick(&self, entry: &Entry) -> RateLimitOutcome {
        match entry.limiter.check() {
            Ok(()) => RateLimitOutcome::Allowed,
            Err(not_until) => RateLimitOutcome::RateLimited {
                until: not_until.earliest_possible(),
            },
        }
    }
}
