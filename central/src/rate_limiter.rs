use std::{collections::HashMap, net::IpAddr};

use crate::config::ServerConfig;

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

pub struct RateLimiter {
    pub max_accounts_per_ip: usize,
    pub max_tokens_per_ip: usize,
    pub max_failures_per_ip: usize,
    pub max_attempts_per_ip: usize,
    cache_map: HashMap<IpAddr, LimiterEntry>,
}

impl RateLimiter {
    pub fn new(_config: &ServerConfig) -> Self {
        // TODO: read from config
        Self {
            max_accounts_per_ip: 10,
            max_tokens_per_ip: 20,
            max_failures_per_ip: 30,
            max_attempts_per_ip: 120,
            cache_map: HashMap::default(),
        }
    }

    pub fn can_start_challenge(&self, user_ip: IpAddr, _account_id: i32) -> bool {
        self.cache_map.get(&user_ip).is_none_or(|x| self.allow(x))
    }

    pub fn can_verify_poll(&self, user_ip: IpAddr, _account_id: i32) -> bool {
        self.cache_map.get(&user_ip).is_none_or(|x| self.allow(x))
    }

    pub fn can_validate(&self, _user_ip: IpAddr) -> bool {
        true
    }

    pub fn record_challenge_start(&mut self, user_ip: IpAddr, account_id: i32) {
        let ent = self.cache_map.entry(user_ip).or_default();

        if ent.account_id == 0 && ent.account_ids.is_empty() {
            ent.account_id = account_id;
        } else if ent.account_ids.is_empty() {
            ent.account_ids.push(ent.account_id);
            ent.account_ids.push(account_id);
            ent.account_id = 0;
        } else {
            ent.account_ids.push(account_id);
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

    pub fn clear_cache(&mut self) {
        self.cache_map.clear();
    }

    fn allow(&self, entry: &LimiterEntry) -> bool {
        entry.account_ids.len() <= self.max_accounts_per_ip
            && entry.tokens as usize <= self.max_tokens_per_ip
            && entry.failures as usize <= self.max_failures_per_ip
            && entry.challenges as usize <= self.max_attempts_per_ip
    }
}
