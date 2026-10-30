use std::{
    hash::Hash,
    num::NonZeroU32,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

use dashmap::DashMap;
use governor::{DefaultDirectRateLimiter, Quota};

struct Entry {
    limiter: DefaultDirectRateLimiter,
    last_access: Instant,
}

pub struct RateLimiter<K: Hash + Eq> {
    limiters: DashMap<K, Entry>,
    limiter_count: AtomicUsize,
    max_retain: Duration,
    max_entries: usize,

    replenish_1_per: Duration,
    max_burst: NonZeroU32,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RateLimitOutcome {
    Allowed,
    RateLimited { until: Instant },
    TooManyLimiters,
}

impl<K: Hash + Eq> RateLimiter<K> {
    pub fn new(max_retain: Duration, max_entries: usize) -> Self {
        Self {
            limiters: DashMap::new(),
            limiter_count: AtomicUsize::new(0),
            max_retain,
            max_entries,

            replenish_1_per: Duration::from_secs(1),
            max_burst: NonZeroU32::new(1).unwrap(),
        }
    }

    pub fn set_replenish_1_per(&mut self, replenish_1_per: Duration) {
        self.replenish_1_per = replenish_1_per;
    }

    pub fn set_max_burst(&mut self, max_burst: NonZeroU32) {
        self.max_burst = max_burst;
    }

    pub fn run_cleanup(&self) {
        self.limiters.retain(|_, entry| {
            let keep = entry.last_access.elapsed() < self.max_retain;
            if !keep {
                self.limiter_count.fetch_sub(1, Ordering::Relaxed);
            }
            keep
        });
    }

    pub fn check(&self, key: K) -> RateLimitOutcome {
        self.check_ext(key, self.replenish_1_per, self.max_burst)
    }

    pub fn check_ext(&self, key: K, replenish_1_per: Duration, max_burst: NonZeroU32) -> RateLimitOutcome {
        if let Some(mut limiter) = self.limiters.get_mut(&key) {
            return self.tick(limiter.value_mut());
        }

        if self.limiter_count.load(Ordering::Acquire) >= self.max_entries {
            return RateLimitOutcome::TooManyLimiters;
        }

        let limiter = governor::RateLimiter::direct(
            Quota::with_period(replenish_1_per).unwrap().allow_burst(max_burst),
        );
        let entry = Entry {
            limiter,
            last_access: Instant::now(),
        };
        self.limiter_count.fetch_add(1, Ordering::Release);
        self.limiters.insert(key, entry);

        RateLimitOutcome::Allowed
    }

    fn tick(&self, entry: &mut Entry) -> RateLimitOutcome {
        entry.last_access = Instant::now();

        match entry.limiter.check() {
            Ok(()) => RateLimitOutcome::Allowed,
            Err(not_until) => RateLimitOutcome::RateLimited {
                until: not_until.earliest_possible(),
            },
        }
    }
}
