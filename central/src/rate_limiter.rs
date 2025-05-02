use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

use crate::config::{RateLimitConfig, ServerConfig};

#[derive(Default)]
struct LimiterEntry {
    // for optimization, we store the first id in account_id, and then if more than 1 account from the same ip tries to make a challenge,
    // only then we push both ids into the vec, and clear the initial account_id field
    pub account_id: i32,
    pub account_ids: Vec<i32>,
    pub challenges: u32,
    pub tokens: u32,
    pub failures: u32,
}

struct ValidationLimiterEntry {
    pub first_at: Instant,
    pub last_day: usize,
    pub last_hour: usize,
}

impl Default for ValidationLimiterEntry {
    fn default() -> Self {
        Self {
            first_at: Instant::now(),
            last_day: 0,
            last_hour: 0,
        }
    }
}

pub struct ClientResults {
    pub validations: usize,
}

pub struct HourlyValidationResults {
    pub clients: HashMap<IpAddr, ClientResults>,
}

pub struct RateLimiter {
    pub config: RateLimitConfig,
    cache_map: HashMap<IpAddr, LimiterEntry>,
    val_cache: HashMap<IpAddr, ValidationLimiterEntry>,
}

impl RateLimiter {
    pub fn new(_config: &ServerConfig) -> Self {
        Self {
            config: _config.rate_limits.clone(),
            cache_map: HashMap::default(),
            val_cache: HashMap::default(),
        }
    }

    /* functions for checking if user is blocked */

    fn can_start_challenge(&self, user_ip: IpAddr, _account_id: i32) -> bool {
        self.cache_map.get(&user_ip).is_none_or(|x| self.allow(x))
    }

    pub fn can_verify_poll(&self, user_ip: IpAddr, _account_id: i32) -> bool {
        self.cache_map.get(&user_ip).is_none_or(|x| self.allow(x))
    }

    fn can_validate_n(&self, count: usize, user_ip: IpAddr) -> bool {
        self.val_cache
            .get(&user_ip)
            .is_none_or(|x| self.allow_validation(x, count))
    }

    /* functions that record the activity */

    fn record_challenge_start(&mut self, user_ip: IpAddr, account_id: i32) {
        let ent = self.cache_map.entry(user_ip).or_default();

        // if vec is not empty, push into it when needed
        if !ent.account_ids.is_empty() {
            if !ent.account_ids.contains(&account_id) {
                ent.account_ids.push(account_id);
            }
        } else if ent.account_id == 0 || ent.account_id == account_id {
            ent.account_id = account_id
        } else {
            // they are different and both nonzero
            ent.account_ids.push(ent.account_id);
            ent.account_ids.push(account_id);
            ent.account_id = 0;
        }

        ent.challenges += 1;
    }

    pub fn record_challenge_success(&mut self, user_ip: IpAddr, _account_id: i32) {
        let ent = self.cache_map.entry(user_ip).or_default();

        ent.tokens += 1;
    }

    pub fn record_challenge_fail(&mut self, user_ip: IpAddr, _account_id: i32) {
        let ent = self.cache_map.entry(user_ip).or_default();

        ent.failures += 1;
    }

    fn record_validated(&mut self, ip: IpAddr, n: usize) {
        let ent = self.val_cache.entry(ip).or_default();

        ent.last_day += n;
        ent.last_hour += n;
    }

    /* functions that first check if user is blocked, then record activity if allowed */

    pub fn start_challenge(&mut self, user_ip: IpAddr, account_id: i32) -> bool {
        self.can_start_challenge(user_ip, account_id)
            .then(|| self.record_challenge_start(user_ip, account_id))
            .is_some()
    }

    pub fn validate_tokens(&mut self, n: usize, ip: IpAddr) -> bool {
        self.can_validate_n(n, ip)
            .then(|| self.record_validated(ip, n))
            .is_some()
    }

    pub fn validate_token(&mut self, ip: IpAddr) -> bool {
        self.validate_tokens(1, ip)
    }

    /* misc */

    pub fn clear_cache(&mut self) {
        self.cache_map.clear();
    }

    pub fn record_hourly_results(&mut self) -> HourlyValidationResults {
        const NEAR_DAY: Duration = Duration::from_mins(23 * 60 + 30); // 23.5 hours

        let mut results = HourlyValidationResults {
            clients: HashMap::with_capacity(self.val_cache.len()),
        };

        for (ip, entry) in self.val_cache.iter_mut() {
            let validations = std::mem::take(&mut entry.last_hour);

            results.clients.insert(*ip, ClientResults { validations });
        }

        // keep entries that have been there for less than a day
        self.val_cache.retain(|_, v| v.first_at.elapsed() < NEAR_DAY);

        results
    }

    fn allow(&self, entry: &LimiterEntry) -> bool {
        entry.account_ids.len() <= self.config.max_accounts_per_ip
            && entry.tokens as usize <= self.config.max_tokens_per_ip
            && entry.failures as usize <= self.config.max_failures_per_ip
            && entry.challenges as usize <= self.config.max_attempts_per_ip
    }

    fn allow_validation(&self, entry: &ValidationLimiterEntry, count: usize) -> bool {
        (entry.last_day + count) <= self.config.validations_per_day
            && (entry.last_hour + count) <= self.config.validations_per_hour
    }
}
