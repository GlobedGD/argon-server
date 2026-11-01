use std::time::Duration;

use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use shared::message::GDAccountData;

use crate::{
    config::AppConfig,
    token::{AccessToken, RefreshToken, Scope, TokenBuilder, TokenClaims},
};

pub struct TokenIssuer {
    key: EncodingKey,
    dec_key: DecodingKey,
    refresh_expiry: Duration,
    access_expiry: Duration,
    legacy_expiry: Duration,
}

impl TokenIssuer {
    pub fn new(config: &AppConfig) -> Self {
        let secret = hex::decode(&config.auth.secret_key).unwrap();
        Self {
            key: EncodingKey::from_secret(&secret),
            dec_key: DecodingKey::from_secret(&secret),
            refresh_expiry: config.auth.refresh_token_expiry,
            access_expiry: config.auth.access_token_expiry,
            legacy_expiry: config.legacy.token_expiry,
        }
    }

    pub fn generate_refresh_token(&self, account_data: &GDAccountData, epoch: u32) -> (RefreshToken, u64) {
        let claims = TokenBuilder::new()
            .account_data(account_data)
            .epoch(epoch)
            .scopes([Scope::Refresh, Scope::AccountManagement])
            .expiry(self.refresh_expiry)
            .build();

        let (token, exp) = self.generate_jwt(claims);
        (RefreshToken(token), exp)
    }

    pub fn generate_access_token(&self, account_data: &GDAccountData) -> (AccessToken, u64) {
        let claims = TokenBuilder::new()
            .account_data(account_data)
            .scope(Scope::Access)
            .expiry(self.access_expiry)
            .build();

        let (token, exp) = self.generate_jwt(claims);
        (AccessToken(token), exp)
    }

    pub fn generate_legacy_token(&self, account_data: &GDAccountData) -> String {
        let claims = TokenBuilder::new()
            .account_data(account_data)
            .scopes([Scope::Legacy, Scope::Access])
            .expiry(self.legacy_expiry)
            .build();

        let (token, _) = self.generate_jwt(claims);
        token
    }

    fn generate_jwt(&self, claims: TokenClaims) -> (String, u64) {
        let token = jsonwebtoken::encode(&Header::default(), &claims, &self.key).unwrap();
        (token, claims.exp)
    }

    pub fn validate_token(&self, token: &str) -> Result<TokenClaims, jsonwebtoken::errors::Error> {
        jsonwebtoken::decode(
            token,
            &self.dec_key,
            &Validation {
                leeway: 5,
                ..Default::default()
            },
        )
        .map(|data| data.claims)
    }
}
