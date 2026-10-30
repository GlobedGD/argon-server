use std::sync::Arc;

use chrono::Utc;
use sea_orm::{ActiveValue::Set, IntoActiveModel};
use shared::message::GDAccountData;

use crate::{
    db::{
        Database, Result,
        entity::{discord_user, user},
        repository::{DiscordUserRepository, UserRepository},
    },
    discord::{
        client::{DiscordClient, DiscordUserData, DiscordUserDataFull},
        error::Error as DiscordError,
    },
    routes::api::{ApiError, ApiResult},
    token::{AccessToken, RefreshToken, Scope, TokenClaims, TokenIssuer},
    user::TokenValidationError,
};

pub struct UserManager {
    user_repository: UserRepository,
    discord_user_repository: DiscordUserRepository,
    discord_client: Option<Arc<DiscordClient>>,
    token_issuer: TokenIssuer,
}

pub struct RefreshedTokenPair {
    pub refresh_token: RefreshToken,
    pub refresh_token_valid_until: u64,
    pub access_token: AccessToken,
    pub access_token_valid_until: u64,
}

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
        }
    }

    pub fn token_issuer(&self) -> &TokenIssuer {
        &self.token_issuer
    }

    pub fn discord_client(&self) -> Option<&Arc<DiscordClient>> {
        self.discord_client.as_ref()
    }

    pub fn run_cleanup(&self) {
        if let Some(dc) = &self.discord_client {
            dc.run_cleanup();
        }
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

    /// called for advanced auth
    async fn generate_token_with_next_epoch(
        &self,
        user: user::Model,
        account_data: &GDAccountData,
    ) -> Result<RefreshedTokenPair> {
        // increment the epoch
        let new_epoch = user.token_epoch as u32 + 1;

        // set the epoch and other fields and save to database
        let mut model = user.into_active_model();
        model.token_epoch = Set(new_epoch as i64);
        model.gd_user_id = Set(Some(account_data.user_id as i64));
        model.username = Set(Some(account_data.username.clone()));

        self.user_repository.update(model).await?;

        // generate pair
        Ok(self.generate_new_tokens(account_data, new_epoch))
    }

    fn generate_new_tokens(&self, account_data: &GDAccountData, epoch: u32) -> RefreshedTokenPair {
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
            && user.token_epoch as u32 != claims.epoch()
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

        user.discord_id = Set(Some(data.account_id));
        self.user_repository.upsert(user, [user::Column::DiscordId]).await?;

        let duser = discord_user::ActiveModel {
            discord_id: Set(data.account_id),
            avatar_url: Set(data.avatar_url),
            user_id: Set(data.account_id),
            username: Set(data.username),
            last_sync_time: Set(Utc::now().naive_utc()),
        };
        self.discord_user_repository.save(duser).await?;

        Ok(())
    }

    /// Refreshes fields such as username and avatar URL in the given discord user
    pub async fn sync_discord_account(&self, data: DiscordUserData) -> ApiResult<()> {
        self.discord_user_repository.sync_details(data).await?;
        Ok(())
    }

    fn discord_enabled(&self) -> bool {
        self.discord_client.is_some()
    }
}
