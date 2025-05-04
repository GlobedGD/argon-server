use std::{fmt::Display, time::SystemTime};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as b64e};
use bytebuffer::{ByteBuffer, ByteReader};

use crate::state::AuthChallenge;

const AUTHTOKEN_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthtokenValidationError {
    InvalidFormat,
    MismatchedIdent,
    InvalidBase64,
    InvalidVersion(u8),
    InvalidSignature,
    InvalidData,
    // Expired,
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
            // Self::Expired => write!(f, "token expired"),
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
    pub _strong_validation: bool,
    pub _issued_at: u64,
}

pub struct TokenIssuer {
    secret_key: [u8; 32],
    ident: String,
}

impl TokenIssuer {
    pub fn new(secret_key: &str, ident: String) -> Result<Self, &'static str> {
        let mut authtoken_secret_key = [0u8; 32];
        hex::decode_to_slice(secret_key, &mut authtoken_secret_key)
            .map_err(|_| "invalid secret key format, expected a 256-bit hex string")?;

        Ok(Self {
            secret_key: authtoken_secret_key,
            ident,
        })
    }

    pub fn generate(&self, challenge: &AuthChallenge) -> String {
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
        let signature = b64e.encode(blake3::keyed_hash(&self.secret_key, buf.as_bytes()).as_bytes());

        let part1 = b64e.encode(buf.as_bytes());

        format!("{}.{part1}.{signature}", self.ident)
    }

    pub fn validate(&self, token: &str) -> Result<AuthtokenData, AuthtokenValidationError> {
        let (token_ident, rest) = token
            .split_once('.')
            .ok_or(AuthtokenValidationError::InvalidFormat)?;

        if token_ident != self.ident {
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
        let valid = blake3::keyed_hash(&self.secret_key, &data) == blake3::Hash::from_bytes(sig);
        if !valid {
            return Err(AuthtokenValidationError::InvalidSignature);
        }

        // decode the rest of the data in the authtoken
        let _issued_at = buf.read_u64()?;
        // let issued_at = SystemTime::UNIX_EPOCH + Duration::from_secs(issued_at);
        let account_id = buf.read_i32()?;
        let user_id = buf.read_i32()?;
        let username = buf.read_string()?;
        let _strong_validation = buf.read_u8()? != 0;
        let _reserved = buf.read_u32()?; // reserved for future use

        Ok(AuthtokenData {
            account_id,
            user_id,
            username,
            _strong_validation,
            _issued_at,
        })
    }
}
