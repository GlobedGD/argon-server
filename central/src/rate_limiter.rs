use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

use nohash_hasher::IntMap;

use crate::{
    config::{RateLimitConfig, ServerConfig},
    database::ApiToken,
};

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

struct RegisteredValidationLimiterEntry {
    pub first_at: Instant,
    pub last_day: usize,
    pub last_hour: usize,
    pub max_per_day: usize,
    pub max_per_hour: usize,
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

impl Default for RegisteredValidationLimiterEntry {
    fn default() -> Self {
        Self {
            first_at: Instant::now(),
            last_day: 0,
            last_hour: 0,
            max_per_day: 0,
            max_per_hour: 0,
        }
    }
}

pub struct ClientResults {
    pub validations: usize,
}

pub struct HourlyValidationResults {
    pub clients: HashMap<IpAddr, ClientResults>,
    pub reg_clients: IntMap<i32, ClientResults>,
}

pub struct RateLimiter {
    pub config: RateLimitConfig,
    cache_map: HashMap<IpAddr, LimiterEntry>,
    val_cache: HashMap<IpAddr, ValidationLimiterEntry>,
    val_cache_registered: IntMap<i32, RegisteredValidationLimiterEntry>, // cache for registered users with an api token
}

#[derive(Debug)]
pub struct RegisteredTokenNotAdded;

impl RateLimiter {
    pub fn new(_config: &ServerConfig) -> Self {
        Self {
            config: _config.rate_limits.clone(),
            cache_map: HashMap::default(),
            val_cache: HashMap::default(),
            val_cache_registered: IntMap::default(),
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

    fn can_validate_n_registered(
        &self,
        count: usize,
        token_id: i32,
    ) -> Result<bool, RegisteredTokenNotAdded> {
        if let Some(user) = self.val_cache_registered.get(&token_id) {
            Ok(self.allow_validation_registered(user, count))
        } else {
            Err(RegisteredTokenNotAdded)
        }
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

    fn record_validated_registered(&mut self, token_id: i32, n: usize) {
        let ent = self.val_cache_registered.entry(token_id).or_default();

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

    /// records N token validations for the api user with the given token id,
    /// just like other methods returns false if the limit was exceeded
    /// also returns an error if the token was not added to the cache
    pub fn validate_tokens_registered(
        &mut self,
        n: usize,
        token_id: i32,
    ) -> Result<bool, RegisteredTokenNotAdded> {
        Ok(self
            .can_validate_n_registered(n, token_id)?
            .then(|| self.record_validated_registered(token_id, n))
            .is_some())
    }

    pub fn add_registered_token(&mut self, token: &ApiToken) {
        self.val_cache_registered.insert(
            token.id,
            RegisteredValidationLimiterEntry {
                max_per_day: usize::try_from(token.validations_per_day).unwrap_or(0),
                max_per_hour: usize::try_from(token.validations_per_hour).unwrap_or(0),
                ..Default::default()
            },
        );
    }

    /* misc */

    pub fn clear_cache(&mut self) {
        self.cache_map.clear();
    }

    pub fn record_hourly_results(&mut self) -> HourlyValidationResults {
        const NEAR_DAY: Duration = Duration::from_mins(23 * 60 + 30); // 23.5 hours

        let mut results = HourlyValidationResults {
            clients: HashMap::with_capacity(self.val_cache.len()),
            reg_clients: IntMap::default(),
        };

        for (ip, entry) in self.val_cache.iter_mut() {
            let validations = std::mem::take(&mut entry.last_hour);

            results.clients.insert(*ip, ClientResults { validations });
        }

        for (token_id, entry) in self.val_cache_registered.iter_mut() {
            let validations = std::mem::take(&mut entry.last_hour);

            results
                .reg_clients
                .insert(*token_id, ClientResults { validations });
        }

        // keep entries that have been there for less than a day
        self.val_cache.retain(|_, v| v.first_at.elapsed() < NEAR_DAY);
        self.val_cache_registered
            .retain(|_, v| v.first_at.elapsed() < NEAR_DAY);

        results
    }

    fn allow(&self, entry: &LimiterEntry) -> bool {
        entry.account_ids.len() <= self.config.max_accounts_per_ip
            && entry.tokens as usize <= self.config.max_tokens_per_ip
            && entry.failures as usize <= self.config.max_failures_per_ip
            && entry.challenges as usize <= self.config.max_attempts_per_ip
    }

    fn allow_validation(&self, entry: &ValidationLimiterEntry, count: usize) -> bool {
        let day_limit = self.config.validations_per_day;
        let hour_limit = self.config.validations_per_hour;

        let day_ok = day_limit == 0 || (entry.last_day + count) <= day_limit;
        let hour_ok = hour_limit == 0 || (entry.last_hour + count) <= hour_limit;

        day_ok && hour_ok
    }

    fn allow_validation_registered(&self, entry: &RegisteredValidationLimiterEntry, count: usize) -> bool {
        let day_ok = entry.max_per_day == 0 || (entry.last_day + count) <= entry.max_per_day;
        let hour_ok = entry.max_per_hour == 0 || (entry.last_hour + count) <= entry.max_per_hour;

        day_ok && hour_ok
    }
}
