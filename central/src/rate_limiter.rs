use std::net::IpAddr;

use crate::config::ServerConfig;

pub struct RateLimiter {}

impl RateLimiter {
    pub fn new(config: &ServerConfig) -> Self {
        Self {}
    }

    pub fn can_start_challenge(&self, user_ip: IpAddr, account_id: i32) -> bool {
        true
    }

    pub fn can_verify_poll(&self, user_ip: IpAddr, account_id: i32) -> bool {
        true
    }

    pub fn can_validate(&self, user_ip: IpAddr) -> bool {
        true
    }

    pub fn record_challenge_success(&self, user_ip: IpAddr, account_id: i32) {}

    pub fn record_challenge_fail(&self, user_ip: IpAddr, account_id: i32) {}
}
