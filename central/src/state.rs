use std::{
    collections::HashMap,
    fmt::Display,
    net::IpAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::bail;
use argon_shared::{WorkerAuthMessage, logger::*};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as b64e};
use bytebuffer::{ByteBuffer, ByteReader};
use nohash_hasher::IntMap;
use rand::Rng;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::{config::ServerConfig, node_handler::NodeHandler};

const AUTHTOKEN_VERSION: u8 = 1;

pub struct AuthChallenge {
    pub challenge_id: u32,
    pub account_id: i32,
    pub user_id: i32,
    pub username: String,
    pub actual_username: String,
    pub challenge_value: i32,
    pub challenge_answer: i32,
    pub started_at: SystemTime,
    pub force_strong: bool,
    pub validated: bool,
    pub validated_strong: bool,
    pub user_comment_id: i32,
}

pub enum ChallengeValidationError {
    NoChallenge,
    WrongSolution,
    WrongAccount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthtokenValidationError {
    InvalidFormat,
    MismatchedIdent,
    InvalidBase64,
    InvalidVersion(u8),
    InvalidSignature,
    InvalidData,
    Expired,
}

impl Display for AuthtokenValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "invalid format (missing separator)"),
            Self::MismatchedIdent => write!(
                f,
                "mismatched ident (token was made with a different Argon server)"
            ),
            Self::InvalidBase64 => write!(f, "invalid format (invalid base64)"),
            Self::InvalidVersion(v) => write!(f, "invalid token version {v}"),
            Self::InvalidSignature => write!(f, "signature invalid or mismatched"),
            Self::InvalidData => write!(f, "invalid data stored in the token"),
            Self::Expired => write!(f, "token expired"),
        }
    }
}

impl From<std::io::Error> for AuthtokenValidationError {
    fn from(_: std::io::Error) -> Self {
        Self::InvalidData
    }
}

pub struct AuthtokenData {
    pub account_id: i32,
    pub user_id: i32,
    pub username: String,
    pub strong_validation: bool,
    pub issued_at: u64,
}

fn compute_server_ident(secret_key: &str) -> String {
    // the server ident is a truncated hash of our secret key hexstring
    let mut res = blake3::hash(secret_key.as_bytes()).to_hex().to_string();

    res.truncate(16);

    res
}

pub struct ServerStateData {
    pub config_path: PathBuf,
    pub config: ServerConfig,
    active_challenges: IntMap<u32, AuthChallenge>,

    // node handler stuff
    pub node_handler: Option<Arc<NodeHandler>>,
    pub node_count: usize,
    pub active_node_count: usize,
    pub server_ident: String,
    pub authtoken_secret_key: [u8; 32],
}

impl ServerStateData {
    pub fn new(config_path: PathBuf, config: ServerConfig) -> Self {
        let server_ident = compute_server_ident(&config.secret_key);
        let mut authtoken_secret_key = [0u8; 32];
        hex::decode_to_slice(&config.secret_key, &mut authtoken_secret_key)
            .expect("invalid secret key format");

        Self {
            config,
            config_path,
            active_challenges: IntMap::default(),
            node_handler: None,
            node_count: 0,
            active_node_count: 0,
            server_ident,
            authtoken_secret_key,
        }
    }

    /// creates a new challenge, returns the challenge id and value to the user.
    pub fn create_challenge(
        &mut self,
        account_id: i32,
        user_id: i32,
        account_name: String,
        force_strong: bool,
    ) -> anyhow::Result<(u32, i32)> {
        let challenge_value = rand::rng().random::<i32>();
        let challenge_id = rand::rng().random::<u32>();
        let answer = Self::make_challenge_answer(challenge_value);

        let challenge = AuthChallenge {
            challenge_id,
            account_id,
            user_id,
            username: account_name,
            actual_username: String::new(),
            challenge_value,
            challenge_answer: answer,
            started_at: SystemTime::now(),
            force_strong,
            validated: false,
            validated_strong: false,
            user_comment_id: 0,
        };

        self.active_challenges.insert(challenge_id, challenge);

        Ok((challenge_id, challenge_value))
    }

    /// Returns whether the challenge has been validated, first bool is validated, second is strong validation.
    /// Returns an error if no challenge exists for the given challenge ID, or other errors have occurred.
    pub fn is_challenge_validated(
        &self,
        challenge_id: u32,
        account_id: i32,
        solution: i32,
    ) -> Result<(bool, bool), ChallengeValidationError> {
        let challenge = self.active_challenges.get(&challenge_id);

        if let Some(c) = challenge {
            if c.account_id != account_id {
                return Err(ChallengeValidationError::WrongAccount);
            }

            if c.challenge_answer != solution {
                return Err(ChallengeValidationError::WrongSolution);
            }

            Ok((c.validated, c.validated_strong))
        } else {
            Err(ChallengeValidationError::NoChallenge)
        }
    }

    pub async fn pick_id_for_message_challenge(&self) -> Option<i32> {
        let node_handler = self.node_handler.as_ref().unwrap();
        node_handler.pick_challenge_account_id().await
    }

    pub fn erase_challenge(&mut self, challenge_id: u32) -> Option<AuthChallenge> {
        self.active_challenges.remove(&challenge_id)
    }

    pub async fn validate_challenges(&mut self, messages: Vec<WorkerAuthMessage>) {
        // this is pretty inefficient as it has n*m time complexity but what can we do :p

        self.active_challenges.values_mut().for_each(|challenge| {
            for message in &messages {
                if message.account_id != challenge.account_id
                    || message.user_id != challenge.user_id
                    || message.challenge_answer != challenge.challenge_answer
                {
                    continue;
                }

                // we found a matching message

                challenge.user_comment_id = message.message_id;
                challenge.validated = true;
                challenge.actual_username = message.username.clone();

                // validate username for strong integrity
                challenge.validated_strong = message
                    .username
                    .trim()
                    .eq_ignore_ascii_case(challenge.username.trim());

                break;
            }
        });
    }

    pub fn make_challenge_answer(challenge: i32) -> i32 {
        challenge ^ 0x5F3759DF
    }

    pub fn generate_authtoken(&self, challenge: &AuthChallenge) -> String {
        let mut buf = ByteBuffer::from_vec(Vec::with_capacity(64));

        // push version
        buf.write_u8(b'v');
        buf.write_u8(AUTHTOKEN_VERSION);

        // push metadata (issued at)
        buf.write_u64(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );

        // version 1 authtoken - account id, user id, user name, strong validation
        buf.write_i32(challenge.account_id);
        buf.write_i32(challenge.user_id);
        buf.write_string(&challenge.actual_username);
        buf.write_u8(challenge.validated_strong as u8);
        buf.write_u32(0); // reserved for future use

        // sign the token
        let signature =
            b64e.encode(blake3::keyed_hash(&self.authtoken_secret_key, buf.as_bytes()).as_bytes());

        let part1 = b64e.encode(buf.as_bytes());

        format!("{}.{part1}.{signature}", self.server_ident)
    }

    pub fn validate_authtoken(&self, token: &str) -> Result<AuthtokenData, AuthtokenValidationError> {
        let (token_ident, rest) = token
            .split_once('.')
            .ok_or(AuthtokenValidationError::InvalidFormat)?;

        if token_ident != self.server_ident {
            return Err(AuthtokenValidationError::MismatchedIdent);
        }

        let (data_enc, sig_enc) = rest
            .split_once('.')
            .ok_or(AuthtokenValidationError::InvalidFormat)?;

        let data = b64e
            .decode(data_enc)
            .map_err(|_| AuthtokenValidationError::InvalidBase64)?;

        // decode the data in the token
        let mut buf = ByteReader::from_bytes(&data);
        buf.read_u8()?; // 'v'
        let version = buf.read_u8()?;
        if version != AUTHTOKEN_VERSION {
            return Err(AuthtokenValidationError::InvalidVersion(version));
        }

        let mut sig = [0u8; 32];
        let sig_size = b64e
            .decode_slice(sig_enc, &mut sig)
            .map_err(|_| AuthtokenValidationError::InvalidBase64)?;

        if sig_size < 32 {
            return Err(AuthtokenValidationError::InvalidSignature);
        }

        // validate the signature
        let valid = blake3::keyed_hash(&self.authtoken_secret_key, &data) == blake3::Hash::from_bytes(sig);
        if !valid {
            return Err(AuthtokenValidationError::InvalidSignature);
        }

        // decode the rest of the data in the authtoken
        let issued_at = buf.read_u64()?;
        // let issued_at = SystemTime::UNIX_EPOCH + Duration::from_secs(issued_at);
        let account_id = buf.read_i32()?;
        let user_id = buf.read_i32()?;
        let username = buf.read_string()?;
        let strong_validation = buf.read_u8()? != 0;
        let _reserved = buf.read_u32()?; // reserved for future use

        Ok(AuthtokenData {
            account_id,
            user_id,
            username,
            strong_validation,
            issued_at,
        })
    }

    pub async fn notify_config_change(&mut self) {
        // recompute the secret key
        self.server_ident = compute_server_ident(&self.config.secret_key);

        if self.config.secret_key.len() != 64
            || hex::decode_to_slice(&self.config.secret_key, &mut self.authtoken_secret_key).is_err()
        {
            error!("failed to decode the secret key in the config file");
            warn!("hint: the key should be a hex-encoded 32-byte key");
            warn!("hint: one can be generated using `openssl rand -hex 32`");
            error!("shutting down server for security reasons");

            std::process::exit(1);
        }
    }
}

#[derive(Clone)]
pub struct ServerState {
    pub inner: Arc<RwLock<ServerStateData>>,
}

impl ServerState {
    pub fn new(ssd: ServerStateData) -> Self {
        Self {
            inner: Arc::new(RwLock::new(ssd)),
        }
    }

    pub async fn state_read(&self) -> RwLockReadGuard<'_, ServerStateData> {
        self.inner.read().await
    }

    pub async fn state_write(&self) -> RwLockWriteGuard<'_, ServerStateData> {
        self.inner.write().await
    }

    pub async fn node_handler(&self) -> Arc<NodeHandler> {
        self.state_read()
            .await
            .node_handler
            .clone()
            .expect("NodeHandler must be initialized by now")
    }
}
