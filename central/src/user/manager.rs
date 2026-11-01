use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use chrono::Utc;
use dashmap::DashMap;
use sea_orm::{ActiveValue::Set, IntoActiveModel};
use shared::message::GDAccountData;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    db::{
        Database,
        entity::{discord_user, user},
        repository::{DiscordUserRepository, UserRepository, UserSessionRepository},
    },
    discord::{
        client::{DiscordClient, DiscordUserData, DiscordUserDataFull},
        error::Error as DiscordError,
    },
    routes::api::{ApiError, ApiResult},
    token::{AccessToken, RefreshToken, Scope, TokenClaims, TokenIssuer},
    user::{TokenValidationError, User},
};

struct WebAccessCodeData {
    account_data: GDAccountData,
    expires_at: Instant,
}

pub struct UserManager {
    user_repository: UserRepository,
    discord_user_repository: DiscordUserRepository,
    discord_client: Option<Arc<DiscordClient>>,
    token_issuer: TokenIssuer,
    session_repo: UserSessionRepository,

    web_access_codes: DashMap<String, WebAccessCodeData>,
}

pub struct RefreshedTokenPair {
    pub refresh_token: RefreshToken,
    pub refresh_token_valid_until: u64,
    pub access_token: AccessToken,
    pub access_token_valid_until: u64,
}

#[derive(Debug, Error)]
pub enum UserManagerError {
    #[error("database error: {0}")]
    Database(sea_orm::DbErr),
    #[error("discord error: {0}")]
    Discord(#[from] DiscordError),
    #[error("user does not have advanced auth enabled")]
    AdvancedAuthNotEnabled,
    #[error("user not found")]
    UserNotFound,
}

impl From<sea_orm::DbErr> for UserManagerError {
    fn from(e: sea_orm::DbErr) -> Self {
        match e {
            sea_orm::DbErr::RecordNotFound(_) => Self::UserNotFound,
            _ => Self::Database(e),
        }
    }
}

type Result<T> = std::result::Result<T, UserManagerError>;

impl UserManager {
    pub fn new(
        database: &Database,
        discord_client: Option<Arc<DiscordClient>>,
        token_issuer: TokenIssuer,
    ) -> Self {
        Self {
            user_repository: database.user_repository.clone(),
            discord_user_repository: database.discord_user_repository.clone(),
            discord_client,
            token_issuer,
            session_repo: database.user_session_repository.clone(),
            web_access_codes: DashMap::new(),
        }
    }

    pub fn token_issuer(&self) -> &TokenIssuer {
        &self.token_issuer
    }

    pub fn discord_client(&self) -> Option<&Arc<DiscordClient>> {
        self.discord_client.as_ref()
    }

    pub async fn run_cleanup(&self) {
        if let Some(dc) = &self.discord_client {
            dc.run_cleanup();
        }

        // cleanup sessions
        let _ = self.session_repo.delete_expired(chrono::Utc::now().naive_utc()).await;

        // cleanup access codes
        let now = Instant::now();
        self.web_access_codes.retain(|_, v| v.expires_at > now);
    }

    pub async fn on_challenge_completed(&self, account_data: &GDAccountData) -> Result<RefreshedTokenPair> {
        self.generate_new_token_pair(account_data).await
    }

    pub async fn on_legacy_challenge_completed(&self, account_data: &GDAccountData) -> String {
        self.token_issuer.generate_legacy_token(account_data)
    }

    pub async fn generate_new_token_pair(&self, account_data: &GDAccountData) -> Result<RefreshedTokenPair> {
        let account_id = account_data.account_id;
        let user = self.user_repository.get_user(account_id).await?;

        match user {
            Some(user) => {
                if user.advanced_auth {
                    self.generate_token_with_next_epoch(user, account_data).await
                } else {
                    // use simple auth
                    Ok(self.generate_new_tokens(account_data, 0))
                }
            }

            _ => {
                // user not in db, use simple auth
                Ok(self.generate_new_tokens(account_data, 0))
            }
        }
    }

    pub fn generate_web_access_code(&self, account_data: &GDAccountData) -> String {
        let code = Uuid::new_v4().simple().to_string();
        self.web_access_codes.insert(
            code.clone(),
            WebAccessCodeData {
                account_data: account_data.clone(),
                expires_at: Instant::now() + Duration::from_mins(3),
            },
        );

        code
    }

    pub fn verify_web_access_code(&self, code: &str) -> Option<GDAccountData> {
        let (_, data) = self.web_access_codes.remove(code)?;
        if data.expires_at > Instant::now() {
            Some(data.account_data)
        } else {
            None
        }
    }

    /// called for advanced auth
    async fn generate_token_with_next_epoch(
        &self,
        user: user::Model,
        account_data: &GDAccountData,
    ) -> Result<RefreshedTokenPair> {
        let user = self.increment_epoch_and_update(user, Some(account_data)).await?;

        // generate pair
        Ok(self.generate_new_tokens(account_data, user.token_epoch as u64))
    }

    async fn increment_epoch_and_update(
        &self,
        user: user::Model,
        account_data: Option<&GDAccountData>,
    ) -> Result<user::Model> {
        // increment the epoch
        let new_epoch = user.token_epoch as u64 + 1;

        // set the epoch and other fields and save to database
        let mut model = user.into_active_model();
        model.token_epoch = Set(new_epoch as i64);
        if let Some(account_data) = account_data {
            model.gd_user_id = Set(Some(account_data.user_id as i64));
            model.username = Set(Some(account_data.username.clone()));
        }

        Ok(self.user_repository.update(model).await?)
    }

    fn generate_new_tokens(&self, account_data: &GDAccountData, epoch: u64) -> RefreshedTokenPair {
        let (refresh, refresh_exp) = self.token_issuer.generate_refresh_token(account_data, epoch);
        let (access, access_exp) = self.token_issuer.generate_access_token(account_data);

        RefreshedTokenPair {
            refresh_token: refresh,
            refresh_token_valid_until: refresh_exp,
            access_token: access,
            access_token_valid_until: access_exp,
        }
    }

    pub async fn validate_refresh_token(
        &self,
        token: &str,
    ) -> std::result::Result<TokenClaims, TokenValidationError> {
        self.validate_token(token, Scope::Refresh).await
    }

    /// Validates that the token either is a v2 access token or a v1 legacy token.
    /// For legacy tokens, since they usually have a much longer expiry window,
    /// this will make a DB lookup to confirm advanced auth isn't enabled for the user
    pub async fn validate_access_token(
        &self,
        token: &str,
    ) -> std::result::Result<TokenClaims, TokenValidationError> {
        self.validate_token(token, Scope::Access).await
    }

    pub async fn validate_token(
        &self,
        token: &str,
        scope: Scope,
    ) -> std::result::Result<TokenClaims, TokenValidationError> {
        let claims = self.token_issuer.validate_token(token)?;
        claims.must_scope(scope)?;

        // check the epoch if this is a refresh token
        if claims.has_scope(Scope::Refresh)
            && let Some(user) = self.user_repository.get_user(claims.account_id()).await?
            && user.advanced_auth
            && user.token_epoch as u64 != claims.epoch()
        {
            return Err(TokenValidationError::RefreshTokenExpired);
        }
        // check if it's a legacy token
        else if claims.has_scope(Scope::Legacy) {
            let user = self.user_repository.get_user(claims.account_id()).await?;
            if user.is_some_and(|u| u.advanced_auth) {
                // we cannot grant this token access, legacy tokens are unsafe when advanced auth is enabled
                return Err(TokenValidationError::LegacyTokenNotAllowed);
            }
        }

        Ok(claims)
    }

    /// Gets a user from the database or creates one lazily. Does not insert into database eagerly.
    /// If the user existed in the database, this does however eagerly update the username & user ID in the database if they are not present or oudated.
    pub async fn get_or_create_user(&self, account_data: &GDAccountData) -> Result<User> {
        let model = self.user_repository.get_user(account_data.account_id).await?;

        match model {
            Some(mut model) => {
                if model.username.as_deref().is_none_or(|u| u != account_data.username)
                    || model.gd_user_id.is_none_or(|id| id != account_data.user_id as i64)
                {
                    // update the user in the database
                    let mut active = model.into_active_model();
                    active.username = Set(Some(account_data.username.clone()));
                    active.gd_user_id = Set(Some(account_data.user_id as i64));
                    model = self.user_repository.update(active).await?;
                }

                Ok(model.into())
            }

            None => Ok(User::new(account_data)),
        }
    }

    /// Performs an upsert, updating the existing user or creating a new one.
    pub async fn update_user(&self, user: User) -> Result<()> {
        let model: user::Model = user.into();
        self.user_repository.upsert_all(model.into_active_model()).await?;
        Ok(())
    }

    pub async fn enable_advanced_auth(&self, account_id: i32) -> Result<()> {
        self.user_repository.update_advanced_auth(account_id, true).await?;
        self.reset_tokens_and_sessions_for(account_id).await?;

        Ok(())
    }

    /// Rotates the refresh token epoch and deletes all web sessions for the given user. Fails if advanced auth is not enabled for them.
    pub async fn reset_tokens_and_sessions_for(&self, account_id: i32) -> Result<()> {
        let Some(user) = self.user_repository.get_user(account_id).await? else {
            return Err(UserManagerError::UserNotFound);
        };

        if !user.advanced_auth {
            return Err(UserManagerError::AdvancedAuthNotEnabled);
        }

        self.increment_epoch_and_update(user, None).await?;
        self.session_repo.delete_all_for_account(account_id).await?;

        Ok(())
    }

    //

    pub async fn get_discord_data(&self, account_id: i32) -> Result<Option<DiscordUserData>> {
        Ok(self.get_discord_data_ext(account_id).await?.map(DiscordUserData::from))
    }

    pub async fn get_discord_data_ext(&self, account_id: i32) -> Result<Option<DiscordUserDataFull>> {
        if !self.discord_enabled() {
            return Ok(None);
        }

        let model = self.discord_user_repository.get_by_user_id(account_id).await?;
        Ok(model.map(Into::into))
    }

    /// Unlinks a user, returns whether the user was actually linked
    pub async fn unlink_discord_user(&self, account_id: i32) -> Result<bool> {
        let Some(user) = self.user_repository.get_user(account_id).await? else {
            return Ok(false);
        };

        let Some(discord_id) = user.discord_id else {
            return Ok(false);
        };

        let mut model = user.into_active_model();
        model.discord_id = Set(None);
        self.user_repository.update(model).await?;
        self.discord_user_repository.delete(discord_id).await?;

        Ok(true)
    }

    pub async fn link_discord_account(&self, account_id: i32, data: DiscordUserData) -> ApiResult<()> {
        let discord_id = data.id;
        let mut user = match self.user_repository.get_user(account_id).await? {
            Some(user) => user.into_active_model(),
            None => user::ActiveModel {
                id: Set(account_id as i64),
                ..Default::default()
            },
        };

        if user.discord_id.is_set_and(|v| v.is_some()) {
            return Err(ApiError::Discord(DiscordError::DiscordAlreadyLinked));
        }

        if self.discord_user_repository.get_user(discord_id).await?.is_some() {
            return Err(ApiError::Discord(DiscordError::DiscordLinkedToAnotherAccount));
        }

        user.discord_id = Set(Some(discord_id));
        self.user_repository.upsert(user, [user::Column::DiscordId]).await?;

        let duser = discord_user::ActiveModel {
            discord_id: Set(discord_id),
            avatar_url: Set(data.avatar_url),
            user_id: Set(account_id as i64),
            username: Set(data.username),
            last_sync_time: Set(Utc::now().naive_utc()),
        };
        self.discord_user_repository.save(duser).await?;

        Ok(())
    }

    /// Refreshes fields such as username and avatar URL in the given discord user
    pub async fn sync_discord_account(&self, account_id: i32, data: DiscordUserData) -> ApiResult<()> {
        if !self.discord_user_repository.sync_details(account_id, data).await? {
            return Err(ApiError::Discord(DiscordError::DiscordLinkedToAnotherAccount));
        }

        Ok(())
    }

    fn discord_enabled(&self) -> bool {
        self.discord_client.is_some()
    }
}
