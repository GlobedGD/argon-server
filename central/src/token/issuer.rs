use std::time::Duration;

use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use shared::message::GDAccountData;

use crate::{
    config::AppConfig,
    token::{AccessToken, RefreshToken, TokenClaims},
};

pub struct TokenIssuer {
    key: EncodingKey,
    dec_key: DecodingKey,
    refresh_expiry: Duration,
    access_expiry: Duration,
}

impl TokenIssuer {
    pub fn new(config: &AppConfig) -> Self {
        let secret = hex::decode(&config.auth.secret_key).unwrap();
        Self {
            key: EncodingKey::from_secret(&secret),
            dec_key: DecodingKey::from_secret(&secret),
            refresh_expiry: config.auth.refresh_token_expiry,
            access_expiry: config.auth.access_token_expiry,
        }
    }

    pub fn generate_refresh_token(&self, account_data: &GDAccountData, epoch: u32) -> (RefreshToken, u64) {
        let (token, exp) = self.generate_jwt(account_data, epoch, "refresh", self.refresh_expiry);
        (RefreshToken(token), exp)
    }

    pub fn generate_access_token(&self, account_data: &GDAccountData) -> (AccessToken, u64) {
        let (token, exp) = self.generate_jwt(account_data, 0, "access", self.access_expiry);
        (AccessToken(token), exp)
    }

    fn generate_jwt(
        &self,
        account_data: &GDAccountData,
        epoch: u32,
        scope: &str,
        expires_in: Duration,
    ) -> (String, u64) {
        let claims = TokenClaims::new_expires_in(account_data, epoch, scope.to_owned(), expires_in);
        let token = jsonwebtoken::encode(&Header::default(), &claims, &self.key).unwrap();
        (token, claims.exp)
    }

    pub fn validate_token(&self, token: &str) -> Result<TokenClaims, jsonwebtoken::errors::Error> {
        jsonwebtoken::decode(token, &self.dec_key, &Validation::default()).map(|data| data.claims)
    }
}
