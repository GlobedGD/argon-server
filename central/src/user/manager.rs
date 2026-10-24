use sea_orm::{ActiveValue::Set, IntoActiveModel};
use shared::message::GDAccountData;

use crate::{
    db::{Result, entity::user, repository::UserRepository},
    token::{AccessToken, RefreshToken, TokenClaims, TokenIssuer},
    user::TokenValidationError,
};

pub struct UserManager {
    user_repository: UserRepository,
    token_issuer: TokenIssuer,
}

pub struct RefreshedTokenPair {
    pub refresh_token: RefreshToken,
    pub refresh_token_valid_until: u64,
    pub access_token: AccessToken,
    pub access_token_valid_until: u64,
}

impl UserManager {
    pub fn new(user_repository: UserRepository, token_issuer: TokenIssuer) -> Self {
        Self {
            user_repository,
            token_issuer,
        }
    }

    pub fn token_issuer(&self) -> &TokenIssuer {
        &self.token_issuer
    }

    pub async fn on_challenge_completed(&self, account_data: &GDAccountData) -> Result<RefreshedTokenPair> {
        self.generate_new_token_pair(account_data).await
    }

    pub async fn generate_new_token_pair(&self, account_data: &GDAccountData) -> Result<RefreshedTokenPair> {
        let account_id = account_data.account_id;
        let user = self.user_repository.get_user(account_id).await?;

        match user {
            Some(user) if user.advanced_auth => self.generate_token_with_next_epoch(account_id, user).await,

            _ => {
                // user not in db or uses simple auth mode: just generate new refresh + access token pair
                Ok(self.generate_new_tokens(account_data, 0))
            }
        }
    }

    /// called for advanced auth
    async fn generate_token_with_next_epoch(
        &self,
        account_id: i32,
        user: user::Model,
    ) -> Result<RefreshedTokenPair> {
        // increment the epoch and save to database
        let new_epoch = user.token_epoch as u32 + 1;
        let account_data = GDAccountData {
            account_id,
            user_id: user.gd_user_id as i32,
            username: user.username.clone(),
        };

        let mut model = user.into_active_model();
        model.token_epoch = Set(new_epoch as i64);
        self.user_repository.save(model).await?;

        // generate pair
        Ok(self.generate_new_tokens(&account_data, new_epoch))
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
        let claims = self.token_issuer.validate_token(token)?;
        if claims.scope != "refresh" {
            return Err(TokenValidationError::NotRefreshToken);
        }

        // check the epoch
        if let Some(user) = self.user_repository.get_user(claims.account_id()).await?
            && user.advanced_auth
            && user.token_epoch as u32 != claims.epoch
        {
            return Err(TokenValidationError::RefreshTokenExpired);
        }

        Ok(claims)
    }

    pub async fn validate_access_token(
        &self,
        token: &str,
    ) -> std::result::Result<TokenClaims, TokenValidationError> {
        let claims = self.token_issuer.validate_token(token)?;
        if claims.scope != "access" {
            return Err(TokenValidationError::NotAccessToken);
        }

        Ok(claims)
    }
}
