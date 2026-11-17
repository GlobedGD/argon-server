use std::{
    net::IpAddr,
    num::NonZeroU32,
    time::{Duration, Instant},
};

use dashmap::DashMap;
use governor::{DefaultDirectRateLimiter, Quota};

use crate::routes::api::ApiError;

// Avoid storing stale limiters forever
const LIMITER_RETAIN_TIME: Duration = Duration::from_mins(30);
// Avoid allowing the map to grow boundless
const MAX_LIMITERS: usize = 4096;

struct Entry {
    limiter: DefaultDirectRateLimiter,
    last_access: Instant,
}

pub struct DevRateLimiter {
    limiters: DashMap<String, Entry>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RateLimitOutcome {
    Allowed,
    RateLimited { until: Instant },
    NotPresent,
}

pub enum RateLimitInsertError {
    TooManyLimiters,
}

impl From<RateLimitInsertError> for ApiError {
    fn from(value: RateLimitInsertError) -> Self {
        match value {
            RateLimitInsertError::TooManyLimiters => {
                ApiError::Internal(anyhow::anyhow!("too many limiters, cannot insert new limiter"))
            }
        }
    }
}

impl DevRateLimiter {
    pub fn new() -> Self {
        Self {
            limiters: DashMap::new(),
        }
    }

    pub fn run_cleanup(&self) {
        self.limiters.retain(|_, entry| entry.last_access.elapsed() < LIMITER_RETAIN_TIME);
    }

    pub fn check_ip(&self, ip: IpAddr) -> RateLimitOutcome {
        self.check(&Self::ip_key(ip))
    }

    pub fn check_key_id(&self, id: i64) -> RateLimitOutcome {
        self.check(&Self::api_key_id_key(id))
    }

    pub fn check(&self, key: &str) -> RateLimitOutcome {
        let now = Instant::now();
        let Some(mut entry) = self.limiters.get_mut(key) else {
            return RateLimitOutcome::NotPresent;
        };

        entry.last_access = now;
        match entry.limiter.check() {
            Ok(()) => RateLimitOutcome::Allowed,
            Err(not_until) => RateLimitOutcome::RateLimited {
                until: not_until.earliest_possible(),
            },
        }
    }

    pub fn insert_ip(
        &self,
        ip: IpAddr,
        replenish_1_per: Duration,
        max_burst: NonZeroU32,
    ) -> Result<(), RateLimitInsertError> {
        self.insert(Self::ip_key(ip), replenish_1_per, max_burst)
    }

    pub fn insert_key_id(
        &self,
        id: i64,
        replenish_1_per: Duration,
        max_burst: NonZeroU32,
    ) -> Result<(), RateLimitInsertError> {
        self.insert(Self::api_key_id_key(id), replenish_1_per, max_burst)
    }

    pub fn insert(
        &self,
        key: String,
        replenish_1_per: Duration,
        max_burst: NonZeroU32,
    ) -> Result<(), RateLimitInsertError> {
        if self.limiters.len() >= MAX_LIMITERS {
            return Err(RateLimitInsertError::TooManyLimiters);
        }

        let limiter = governor::RateLimiter::direct(
            Quota::with_period(replenish_1_per).unwrap().allow_burst(max_burst),
        );
        let entry = Entry {
            limiter,
            last_access: Instant::now(),
        };
        self.limiters.insert(key, entry);

        Ok(())
    }

    fn ip_key(ip: IpAddr) -> String {
        format!("ip-{ip}")
    }

    fn api_key_id_key(id: i64) -> String {
        format!("api-key-{id}")
    }
}
