use std::{
    fmt::Display,
    marker::ConstParamTy,
    time::{Duration, SystemTime},
};

use serde::{Deserialize, Serialize};
use shared::message::GDAccountData;

use crate::user::TokenValidationError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ConstParamTy)]
pub enum Scope {
    /// This scope allows refreshing the refresh token & also get other types of tokens such as access
    Refresh,
    /// This scope allows verifying own identity and fetching other data about the user, such as discord account.
    /// Access tokens are considered less sensitive and typically are shared with 3rd party servers.
    Access,
    /// This scope is for a token issued via /v1/ api, used by an older version of Argon. It is considered slightly less secure than the new refresh token.
    /// The scope is typically combined with Access
    Legacy,
    /// This is a scope that allows the user to perform various account management actions, such as link/unlink discord account,
    /// change security properties, sync data, etc.
    AccountManagement,
}

impl Scope {
    pub fn to_str(self) -> &'static str {
        match self {
            Scope::Refresh => "refresh",
            Scope::Access => "access",
            Scope::Legacy => "legacy",
            Scope::AccountManagement => "acc_mgmt",
        }
    }
}

impl Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_str())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TokenClaims {
    /// Unix timestamp of expiration time
    pub exp: u64,
    /// Unix timestamp of issued at time
    pub iat: u64,
    /// Epoch of the token, or 0 for tokens without an epoch
    epoch: u64,
    /// Comma separated list of scopes (see `Scope` enum)
    scope: String,
    /// Account ID of the user
    sub: i32,
    /// Player ID (user ID)
    u_id: i32,
    /// Username
    name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TokenBuilder {
    claims: TokenClaims,
}

impl TokenBuilder {
    pub fn new() -> Self {
        Self {
            claims: TokenClaims::default(),
        }
    }

    pub fn build(self) -> TokenClaims {
        assert!(!self.claims.scope.is_empty(), "Token must have at least one scope");
        assert!(self.claims.exp > 0 && self.claims.iat > 0, "iat/exp not set in token");
        assert!(self.claims.sub != 0 && self.claims.u_id != 0, "sub/u_id not set in token");
        assert!(!self.claims.name.is_empty(), "name not set in token");

        self.claims
    }

    pub fn expiry(self, dur: Duration) -> Self {
        let issued_at = SystemTime::now();
        let expires_at = issued_at + dur;
        self.expiry_absolute(issued_at, expires_at)
    }

    pub fn expiry_absolute(mut self, issued_at: SystemTime, expires_at: SystemTime) -> Self {
        let issued_at = issued_at.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        let expires_at = expires_at.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        self.claims.iat = issued_at;
        self.claims.exp = expires_at;
        self
    }

    pub fn epoch(mut self, epoch: u64) -> Self {
        self.claims.epoch = epoch;
        self
    }

    /// Appends another scope, for multiple scopes in one shot see `scopes`
    pub fn scope(mut self, scope: Scope) -> Self {
        if !self.claims.scope.is_empty() {
            self.claims.scope.push(',');
        }
        self.claims.scope.push_str(scope.to_str());
        self
    }

    /// Replaces the list of scopes with the provided list
    pub fn scopes(mut self, scopes: impl IntoIterator<Item = Scope>) -> Self {
        self.claims.scope.clear();
        for scope in scopes {
            self = self.scope(scope);
        }
        self
    }

    pub fn account_data(mut self, account_data: &GDAccountData) -> Self {
        self.claims.sub = account_data.account_id;
        self.claims.u_id = account_data.user_id;
        self.claims.name = account_data.username.clone();
        self
    }
}

impl TokenClaims {
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

    pub fn has_scope(&self, scope: Scope) -> bool {
        let str = scope.to_str();
        self.scope.split(',').any(|s| s == str)
    }

    pub fn must_scope(&self, scope: Scope) -> Result<(), TokenValidationError> {
        if self.has_scope(scope) {
            Ok(())
        } else {
            Err(TokenValidationError::MissingScope(scope))
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

// Convenience types for returning a token pair

#[derive(Serialize, Deserialize, Clone)]
pub struct RefreshToken(pub String);

#[derive(Serialize, Deserialize, Clone)]
pub struct AccessToken(pub String);
