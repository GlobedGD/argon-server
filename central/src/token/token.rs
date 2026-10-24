use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use shared::message::GDAccountData;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TokenClaims {
    /// Unix timestamp of expiration time
    pub exp: u64,
    /// Unix timestamp of issued at time
    pub iat: u64,
    /// Epoch of the token, or 0 for tokens without an epoch
    pub epoch: u32,
    /// Scope, currently "refresh" or "access"
    pub scope: String,
    /// Account ID of the user
    pub sub: i32,
    /// Player ID (user ID)
    pub u_id: i32,
    /// Username
    pub name: String,
}

impl TokenClaims {
    pub fn new_expires_in(account_data: &GDAccountData, epoch: u32, scope: String, dur: Duration) -> Self {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        let exp = now + dur.as_secs();
        Self {
            sub: account_data.account_id,
            u_id: account_data.user_id,
            name: account_data.username.clone(),
            iat: now,
            exp,
            epoch,
            scope,
        }
    }

    pub fn account_id(&self) -> i32 {
        self.sub
    }

    pub fn user_id(&self) -> i32 {
        self.u_id
    }

    pub fn username(&self) -> &str {
        &self.name
    }

    pub fn account_data(&self) -> GDAccountData {
        GDAccountData {
            account_id: self.sub,
            user_id: self.u_id,
            username: self.name.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RefreshToken(pub String);

#[derive(Serialize, Deserialize, Clone)]
pub struct AccessToken(pub String);
