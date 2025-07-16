use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as b64e};
use bytebuffer::ByteReader;
use parking_lot::Mutex as SyncMutex;
use std::{fmt::Display, sync::Arc};
use thiserror::Error;

use crate::{
    database::{ApiToken, ArgonDb, ArgonDbError, NewApiToken},
    rate_limiter::RateLimiter,
};

pub struct ApiTokenManager {
    secret_key: [u8; 32],
    ident: String,
    rate_limiter: Arc<SyncMutex<RateLimiter>>,
}

#[derive(Error, Debug)]
pub enum TokenFetchError {
    #[error("mismatched ident (token was made with a different Argon server)")]
    MismatchedIdent,
    #[error("malformed token structure")]
    MalformedToken,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("database error: {0}")]
    Database(#[from] ArgonDbError),
    #[error("database pool error")]
    DatabasePoolError,
}

impl From<std::io::Error> for TokenFetchError {
    fn from(_: std::io::Error) -> Self {
        Self::MalformedToken
    }
}

impl ApiTokenManager {
    pub fn new(
        secret_key: &str,
        ident: String,
        rate_limiter: Arc<SyncMutex<RateLimiter>>,
    ) -> Result<Self, &'static str> {
        let mut authtoken_secret_key = [0u8; 32];
        hex::decode_to_slice(secret_key, &mut authtoken_secret_key)
            .map_err(|_| "invalid secret key format, expected a 256-bit hex string")?;

        Ok(Self {
            rate_limiter,
            secret_key: authtoken_secret_key,
            ident,
        })
    }

    pub async fn validate_tokens(
        &self,
        token: &str,
        db: &ArgonDb,
        count: usize,
    ) -> Result<bool, TokenFetchError> {
        let token_id = self.validate_api_token(token)?;

        self.validate_tokens_session(token_id, async || Ok(db), count)
            .await
    }

    /// Like `validate_tokens`, but a token ID is passed instead of the token
    /// Also the database is queried lazily
    pub async fn validate_tokens_session<'f, F: AsyncFnOnce() -> Result<&'f ArgonDb, &'static str>>(
        &self,
        token_id: i32,
        db_fn: F,
        count: usize,
    ) -> Result<bool, TokenFetchError> {
        {
            let mut rl = self.rate_limiter.lock();

            // if this succeeds, this means the token was already added to the ratelimiter,
            // no need to fetch it from the database
            if let Ok(x) = rl.validate_tokens_registered(count, token_id) {
                return Ok(x);
            }
        }

        let api_token = self
            .get_token_data_by_id(
                db_fn().await.map_err(|_| TokenFetchError::DatabasePoolError)?,
                token_id,
            )
            .await?;

        let mut rl = self.rate_limiter.lock();
        rl.add_registered_token(&api_token);

        Ok(rl
            .validate_tokens_registered(count, token_id)
            .expect("validate_tokens_registered must succeed after the token was added"))
    }

    pub async fn generate_token<'a>(
        &self,
        db: &ArgonDb,
        data: NewApiToken<'a>,
    ) -> Result<String, ArgonDbError> {
        let token = db.insert_token(data).await?;

        Ok(self.encode_api_token(&token))
    }

    async fn get_token_data_by_id(&self, db: &ArgonDb, token_id: i32) -> Result<ApiToken, TokenFetchError> {
        db.get_token(token_id).await.map_err(TokenFetchError::Database)
    }

    pub async fn get_all_tokens(&self, db: &ArgonDb) -> Result<Vec<ApiToken>, TokenFetchError> {
        db.get_all_tokens().await.map_err(TokenFetchError::Database)
    }

    fn encode_api_token(&self, token: &ApiToken) -> String {
        let token_body = token.id.to_be_bytes();

        // sign the token
        let signature = b64e.encode(blake3::keyed_hash(&self.secret_key, &token_body).as_bytes());

        let encoded_body = b64e.encode(token_body);

        format!("{}.{encoded_body}.{signature}", self.ident)
    }

    // returns token ID if token is valid
    pub fn validate_api_token(&self, token: &str) -> Result<i32, TokenFetchError> {
        let (token_ident, rest) = token.split_once('.').ok_or(TokenFetchError::MalformedToken)?;

        if token_ident != self.ident {
            return Err(TokenFetchError::MismatchedIdent);
        }

        let (data_enc, sig_enc) = rest.split_once('.').ok_or(TokenFetchError::MalformedToken)?;

        let data = b64e
            .decode(data_enc)
            .map_err(|_| TokenFetchError::MalformedToken)?;

        if data.len() != 4 {
            return Err(TokenFetchError::MalformedToken);
        }

        let mut sig = [0u8; 32];
        let sig_size = b64e
            .decode_slice(sig_enc, &mut sig)
            .map_err(|_| TokenFetchError::MalformedToken)?;

        if sig_size < 32 {
            return Err(TokenFetchError::InvalidSignature);
        }

        // validate the signature
        let valid = blake3::keyed_hash(&self.secret_key, &data) == blake3::Hash::from_bytes(sig);
        if !valid {
            return Err(TokenFetchError::InvalidSignature);
        }

        // decode the data in the token
        let mut buf = ByteReader::from_bytes(&data);

        Ok(buf.read_i32()?)
    }
}
