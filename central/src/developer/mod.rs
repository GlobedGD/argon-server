use std::{net::IpAddr, num::NonZeroU32, time::Duration};

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use sea_orm::{ActiveValue::Set, IntoActiveModel};

use crate::{
    config::AppConfig,
    db::{
        Database,
        entity::{dev_account, dev_api_key},
        repository::{DevAccountRepository, DevApiKeyRepository, DevSessionRepository},
    },
    developer::rate_limiter::{DevRateLimiter, RateLimitOutcome},
    routes::api::ApiError,
};

mod error;
mod models;
mod rate_limiter;

pub use error::*;
pub use models::*;

pub struct DeveloperManager {
    account_repo: DevAccountRepository,
    api_key_repo: DevApiKeyRepository,
    session_repo: DevSessionRepository,
    limiter: DevRateLimiter,
    ip_limiter_token_interval: Duration,
    ip_max_burst: NonZeroU32,
}

#[derive(Clone, Debug)]
pub struct ApiKeyClaims {
    pub id: i64,
    pub secret: String,
}

impl DeveloperManager {
    pub fn new(database: &Database, config: &AppConfig) -> Self {
        Self {
            account_repo: database.dev_account_repository.clone(),
            api_key_repo: database.dev_api_key_repository.clone(),
            session_repo: database.dev_session_repository.clone(),
            limiter: DevRateLimiter::new(),
            ip_limiter_token_interval: config
                .developers
                .request_rate_limit_period
                .div_f64(config.developers.request_rate_limit as f64),
            ip_max_burst: NonZeroU32::new(config.developers.request_max_burst)
                .expect("invalid request_max_burst value, must be above 0"),
        }
    }

    pub async fn run_cleanup(&self) {
        self.limiter.run_cleanup();

        // cleanup sessions
        let _ = self.session_repo.delete_expired(chrono::Utc::now().naive_utc()).await;
    }

    pub async fn validate_api_key(&self, key: &str) -> Result<ApiKeyClaims, ApiKeyError> {
        // TODO: some sort of cache so this doesn't hit the db every time
        let (id, secret) = self.decode_key(key)?;
        let key =
            self.api_key_repo.get_key_by_id_and_secret(id, secret).await?.ok_or(ApiKeyError::InvalidKey)?;

        Ok(ApiKeyClaims {
            id: key.id,
            secret: key.secret,
        })
    }

    fn encode_key(&self, key_id: i64, secret: &str) -> String {
        format!("{}:{}", key_id, secret)
    }

    fn decode_key<'a>(&self, key: &'a str) -> Result<(i64, &'a str), ApiKeyError> {
        let (id_str, secret) = key.split_once(':').ok_or(ApiKeyError::InvalidKey)?;
        let id = id_str.parse::<i64>().map_err(|_| ApiKeyError::InvalidKey)?;
        Ok((id, secret))
    }

    pub async fn check_rate_limit(&self, claims: Option<&ApiKeyClaims>, ip: IpAddr) -> Result<(), ApiError> {
        let mut result = self.do_check(claims, ip);

        if result == RateLimitOutcome::NotPresent {
            match claims {
                Some(claims) => {
                    let key = self
                        .api_key_repo
                        .get_key(claims.id)
                        .await?
                        .ok_or(ApiError::ApiKeyDecode(ApiKeyError::InvalidKey))?;

                    let replenish_per = Duration::from_nanos(key.request_reload_ns as u64);
                    self.limiter.insert_key_id(claims.id, replenish_per, self.ip_max_burst)?;
                }
                None => {
                    self.limiter.insert_ip(ip, self.ip_limiter_token_interval, self.ip_max_burst)?;
                }
            }

            result = self.do_check(claims, ip);
        }

        match result {
            RateLimitOutcome::Allowed => Ok(()),
            RateLimitOutcome::RateLimited { until } => Err(ApiError::RateLimited { until }),
            RateLimitOutcome::NotPresent => unreachable!(),
        }
    }

    fn do_check(&self, claims: Option<&ApiKeyClaims>, ip: IpAddr) -> RateLimitOutcome {
        match claims {
            Some(claims) => self.limiter.check_key_id(claims.id),
            None => self.limiter.check_ip(ip),
        }
    }

    /// Handles a login and returns the developer struct if credentials are good
    pub async fn handle_login(&self, username: &str, password: &str) -> Result<Developer, LoginError> {
        let dev = self.account_repo.get_by_username(username).await?.ok_or(LoginError::InvalidCredentials)?;
        if !self.verify_password(password, &dev.password_hash) {
            return Err(LoginError::InvalidCredentials);
        }

        Ok(dev.into())
    }

    pub async fn handle_change_password(
        &self,
        id: i64,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), DevError> {
        let dev = self.account_repo.get_account(id).await?.ok_or(LoginError::InvalidCredentials)?;
        if !self.verify_password(old_password, &dev.password_hash) {
            Err(LoginError::InvalidCredentials)?;
        }

        self.set_developer_password(dev.id, new_password, false).await?;

        Ok(())
    }

    fn argon() -> Argon2<'static> {
        Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(32_768, 2, 1, None).unwrap(),
        )
    }

    fn verify_password(&self, password: &str, hash: &str) -> bool {
        let argon = Self::argon();
        let Ok(parsed_hash) = PasswordHash::new(hash) else {
            return false;
        };

        argon.verify_password(password.as_bytes(), &parsed_hash).is_ok()
    }

    fn hash_password(&self, password: &str) -> Result<String, DevError> {
        if password.len() < 8 || password.len() > 256 {
            return Err(DevError::PasswordLength);
        }

        let argon = Self::argon();
        let hash = argon.hash_password(password.as_bytes()).map_err(|_| DevError::PwHashFailed)?;
        Ok(hash.to_string())
    }

    pub async fn get_developer(&self, id: i64) -> Result<Option<Developer>, sea_orm::DbErr> {
        let developer = self.account_repo.get_account(id).await?;
        Ok(developer.map(|d| d.into()))
    }

    pub async fn create_developer(&self, username: &str, password: &str) -> Result<Developer, DevError> {
        if username.len() < 3 || username.len() > 64 {
            return Err(DevError::UsernameLength);
        }

        if self.account_repo.get_by_username(username).await?.is_some() {
            return Err(DevError::UsernameTaken);
        }

        let pw_hash = self.hash_password(password)?;

        let model = dev_account::ActiveModel {
            username: Set(username.to_owned()),
            password_hash: Set(pw_hash),
            setup_complete: Set(false),
            is_admin: Set(false),
            ..Default::default()
        };

        let dev = self.account_repo.save(model).await?;
        Ok(dev.into())
    }

    pub async fn create_admin(&self, username: &str, password: &str) -> Result<Developer, DevError> {
        let pw_hash = self.hash_password(password)?;

        let model = dev_account::ActiveModel {
            username: Set(username.to_owned()),
            password_hash: Set(pw_hash),
            setup_complete: Set(true),
            is_admin: Set(true),
            ..Default::default()
        };
        let dev = self.account_repo.save(model).await?;
        Ok(dev.into())
    }

    pub async fn delete_developer(&self, id: i64) -> Result<(), DevError> {
        self.api_key_repo.delete_by_developer_id(id).await?;

        if !self.account_repo.delete(id).await? {
            return Err(DevError::NotFound);
        }

        // invalidate all sessions for this user
        self.session_repo.delete_all_for_account(id).await?;

        Ok(())
    }

    pub async fn set_developer_password(
        &self,
        id: i64,
        password: &str,
        temporary: bool,
    ) -> Result<(), DevError> {
        let Some(dev) = self.account_repo.get_account(id).await? else {
            return Err(DevError::NotFound);
        };

        let mut dev = dev.into_active_model();
        dev.password_hash = Set(self.hash_password(password)?);
        dev.setup_complete = Set(!temporary);
        self.account_repo.update(dev).await?;

        // invalidate all sessions for this user
        self.session_repo.delete_all_for_account(id).await?;

        Ok(())
    }

    pub async fn get_developers(&self) -> Result<Vec<Developer>, DevError> {
        let developers = self.account_repo.get_all().await?;
        Ok(developers.into_iter().map(Into::into).collect())
    }

    // Key management

    pub async fn create_key(
        &self,
        dev_id: i64,
        name: &str,
        description: &str,
        request_reload_ns: u64,
    ) -> Result<DevApiKey, DevError> {
        let model = dev_api_key::ActiveModel {
            name: Set(name.to_owned()),
            description: Set(description.to_owned()),
            // Note: the repository ensures that a key with no secret isn't considered valid, the user will rotate the secret themselves later
            secret: Set(String::new()),
            owner: Set(dev_id),
            request_reload_ns: Set(request_reload_ns.max(1) as i64),
            created_at: Set(chrono::Utc::now().naive_utc()),
            ..Default::default()
        };

        let key = self.api_key_repo.save(model).await?;
        Ok(key.into())
    }

    pub async fn edit_key(
        &self,
        key_id: i64,
        name: &str,
        description: &str,
        request_reload_ns: u64,
    ) -> Result<DevApiKey, DevError> {
        let mut key = self.api_key_repo.get_key(key_id).await?.ok_or(DevError::NotFound)?.into_active_model();
        key.name = Set(name.to_owned());
        key.description = Set(description.to_owned());
        key.request_reload_ns = Set(request_reload_ns.max(1) as i64);

        let key = self.api_key_repo.update(key).await?;
        Ok(key.into())
    }

    pub async fn delete_key(&self, key_id: i64) -> Result<(), DevError> {
        if !self.api_key_repo.delete(key_id).await? {
            return Err(DevError::NotFound);
        }

        Ok(())
    }

    /// Rotates the key's secret and returns the new, encoded API key
    pub async fn rotate_key(&self, dev_id: i64, key_id: i64, new_secret: &str) -> Result<String, DevError> {
        let mut key = self
            .api_key_repo
            .get_key(key_id)
            .await?
            .filter(|k| k.owner == dev_id)
            .ok_or(DevError::NotFound)?
            .into_active_model();

        key.secret = Set(new_secret.to_owned());
        self.api_key_repo.update(key).await?;
        Ok(self.encode_key(key_id, new_secret))
    }

    pub async fn get_developer_keys(&self, dev_id: i64) -> Result<Vec<DevApiKey>, DevError> {
        let keys = self.api_key_repo.get_all_by_developer_id(dev_id).await?;
        Ok(keys.into_iter().map(DevApiKey::from_model).collect())
    }

    pub async fn get_developer_key(&self, dev_id: i64, key_id: i64) -> Result<Option<DevApiKey>, DevError> {
        let key = self.api_key_repo.get_key(key_id).await?.filter(|k| k.owner == dev_id);
        Ok(key.map(DevApiKey::from_model))
    }
}
