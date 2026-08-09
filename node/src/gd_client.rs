use std::{str::FromStr, time::Duration};

use argon_shared::logger::*;
use base64::{
    Engine as _,
    alphabet::URL_SAFE,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use parking_lot::Mutex;
use reqwest::Response;
use thiserror::Error;

#[allow(non_upper_case_globals)]
pub const b64e: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

pub struct GDMessage {
    pub id: i32,
    pub title: String,
    pub author_name: String,
    pub author_id: i32,
    pub author_user_id: i32,
    pub age: Duration,
}

#[derive(Clone, Default)]
pub struct GDUser {
    pub id: i32,
    pub username: String,
    pub custom: String,
}

struct ClientConfig {
    account_id: i32,
    account_gjp: String,
    base_url: String,
}

impl ClientConfig {
    pub fn new(account_id: i32, account_gjp: String, mut base_url: String) -> Self {
        while base_url.ends_with('/') {
            base_url.pop();
        }

        Self {
            account_id,
            account_gjp,
            base_url,
        }
    }
}

pub struct GDClient {
    config: Mutex<ClientConfig>,
    client: reqwest::Client,
}

#[derive(Error, Debug)]
pub enum GDClientError {
    #[error("request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),
    #[error("invalid server response: {0}")]
    InvalidServerResponse(#[from] ResponseParseError),
    #[error("generic API error (likely invalid credentials?)")]
    GenericAPIError, // -1 by boomlings
    #[error("API error: code {0}")]
    UnknownAPIError(i32), // other boomlings error than -1
    #[error("error code 1006 returned, this IP address has been blocked")]
    BlockedIP, // CF error 1006, IP is blocked
    #[error("error code 1005 returned, your internet provider (or VPS host) has been blocked")]
    BlockedProvider, // CF error 1005, the entire provider is blocked
    #[error("error code {0} returned by Cloudflare")]
    BlockedGeneric(i32), // other CF error
    #[error("account improperly configured, account ID was not a positive number")]
    NoAccountConfigured,
}

impl GDClient {
    pub fn new(account_id: i32, account_gjp: String, base_url: String) -> Self {
        let invalid_certs = std::env::var("ARGON_NODE_ALLOW_INVALID_CERTS").is_ok_and(|x| x != "0");

        let http_client = reqwest::ClientBuilder::new()
            .use_rustls_tls()
            .danger_accept_invalid_certs(invalid_certs)
            .user_agent("")
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        let config = ClientConfig::new(account_id, account_gjp, base_url);

        Self {
            client: http_client,
            config: Mutex::new(config),
        }
    }

    pub fn update_config(&self, account_id: i32, account_gjp: String, base_url: String) {
        let mut config = self.config.lock();
        *config = ClientConfig::new(account_id, account_gjp, base_url);
    }

    pub fn has_account(&self) -> bool {
        self.config.lock().account_id > 0
    }

    pub async fn fetch_messages(&self) -> Result<Vec<GDMessage>, GDClientError> {
        let req = {
            let config = self.config.lock();

            if config.account_id <= 0 {
                return Err(GDClientError::NoAccountConfigured);
            }

            self.client
                .post(format!("{}/getGJMessages20.php", config.base_url))
                .form(&[
                    ("accountID", config.account_id.to_string().as_str()),
                    ("gjp2", config.account_gjp.as_str()),
                    ("secret", "Wmfd2893gb7"),
                    ("page", "0"),
                ])
        };

        let response = req.send().await?.error_for_status()?;

        let text = match Self::_handle_response(response).await {
            Ok(x) => x,
            Err(GDClientError::UnknownAPIError(-2)) => return Ok(vec![]), // -2 is ok, it just means no messages
            Err(e) => return Err(e),
        };

        let mut response: &str = &text;
        if let Some(sharp) = response.find('#') {
            response = response.split_at(sharp).0;
            // data after # is formatted like number:number:number
            // first number i'm not sure about, i think total amount of messages (sent + received)?,
            // because it was slightly more than the actual amount of received messages i had
            // second number is the offset (so page * pageSize), third number is either page size or the amount of entries in response (?)
        }

        let mut output = Vec::new();

        for message_str in response.split('|') {
            if message_str.is_empty() {
                continue;
            }

            let message = message_str.parse::<GDMessage>();

            match message {
                Ok(m) => output.push(m),
                Err(e) => {
                    warn!("Failed to parse GD message: {e} (raw content: {message_str})");
                }
            }
        }

        Ok(output)
    }

    pub async fn delete_messages(&self, message_ids: &[i32]) -> Result<(), GDClientError> {
        self.delete_messages_str(&itertools::join(message_ids.iter(), ","))
            .await
    }

    pub async fn delete_messages_str(&self, message_str: &str) -> Result<(), GDClientError> {
        let req = {
            let config = self.config.lock();

            self.client
                .post(format!("{}/deleteGJMessages20.php", config.base_url))
                .form(&[
                    ("accountID", config.account_id.to_string().as_str()),
                    ("gjp2", config.account_gjp.as_str()),
                    ("secret", "Wmfd2893gb7"),
                    ("messages", message_str),
                ])
        };

        let response = req.send().await?.error_for_status()?;
        Self::_handle_response(response).await?;

        Ok(())
    }

    pub async fn fetch_user_profile(&self, account_id: i32) -> Result<GDUser, GDClientError> {
        let req = {
            let config = self.config.lock();

            self.client
                .post(format!("{}/getGJUserInfo20.php", config.base_url))
                .header("X-No-Cache", "1") // header for gdproxy, ignored by official boomlings
                .form(&[
                    ("targetAccountID", account_id.to_string().as_str()),
                    ("secret", "Wmfd2893gb7"),
                ])
        };

        let response = req.send().await?.error_for_status()?;
        let resp = Self::_handle_response(response).await?;

        Ok(resp.parse::<GDUser>()?)
    }

    async fn _handle_response(resp: Response) -> Result<String, GDClientError> {
        let text = resp.text().await?;

        if text.starts_with("error code: ") {
            let code = text
                .strip_prefix("error code: ")
                .unwrap()
                .parse::<i32>()
                .unwrap_or(0);

            Err(match code {
                1005 => GDClientError::BlockedProvider,
                1006 => GDClientError::BlockedIP,
                x => GDClientError::BlockedGeneric(x),
            })
        } else if text.starts_with("-")
            && let Ok(num) = text.parse::<i32>()
        {
            Err(match num {
                -1 => GDClientError::GenericAPIError,
                x => GDClientError::UnknownAPIError(x),
            })
        } else {
            Ok(text)
        }
    }
}

#[derive(Error, Debug)]
pub enum ResponseParseError {
    #[error("failed to parse message/account/user ID")]
    InvalidId,
    #[error("failed to find important fields in the message string")]
    IncompleteMessage,
    #[error("failed to decode the message title")]
    InvalidTitle,
    #[error("failed to parse age string: {0}")]
    InvalidAge(AgeParseError),
}

impl FromStr for GDMessage {
    type Err = ResponseParseError;
    fn from_str(s: &str) -> Result<Self, ResponseParseError> {
        let mut id = -1;
        let mut title = String::new();
        let mut author_name = String::new();
        let mut author_id = -1;
        let mut author_user_id = -1;
        let mut age: Option<Duration> = None;

        let mut is_key = true;
        let mut cur_key = "";

        for part in s.split(':') {
            // this is very silly
            if is_key {
                cur_key = part;
            } else {
                match cur_key {
                    "1" => {
                        id = part.parse::<i32>().map_err(|_| ResponseParseError::InvalidId)?;
                    }

                    "2" => {
                        author_id = part.parse::<i32>().map_err(|_| ResponseParseError::InvalidId)?;
                    }

                    "3" => {
                        author_user_id = part.parse::<i32>().map_err(|_| ResponseParseError::InvalidId)?;
                    }

                    "4" => {
                        title = b64e
                            .decode(part)
                            .map_err(|_| ResponseParseError::InvalidTitle)
                            .and_then(|v| {
                                String::from_utf8(v).map_err(|_| ResponseParseError::InvalidTitle)
                            })?;
                    }

                    "6" => {
                        author_name = part.to_owned();
                    }

                    "7" => {
                        age = Some(rob_age_to_duration(part).map_err(ResponseParseError::InvalidAge)?);
                    }

                    _ => {}
                }
            }

            is_key = !is_key;
        }

        if id != -1
            && !author_name.is_empty()
            && author_id != -1
            && author_user_id != -1
            && let Some(age) = age
        {
            Ok(GDMessage {
                id,
                title,
                author_name,
                author_id,
                author_user_id,
                age,
            })
        } else {
            Err(ResponseParseError::IncompleteMessage)
        }
    }
}

impl FromStr for GDUser {
    type Err = ResponseParseError;
    fn from_str(s: &str) -> Result<Self, ResponseParseError> {
        let mut this = Self::default();

        for [k, v] in s.split(":").array_chunks::<2>() {
            match k {
                "16" => this.id = v.parse::<i32>().map_err(|_| ResponseParseError::InvalidId)?,
                "1" => this.username = v.to_owned(),
                "61" => this.custom = v.to_owned(),
                _ => {}
            }
        }

        Ok(this)
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug)]
pub enum AgeParseError {
    #[error("invalid format")]
    InvalidFormat,
    #[error("invalid number")]
    InvalidNumber,
    #[error("invalid time unit")]
    InvalidUnit,
}

/// Converts a string in format like "3 seconds ago", "1 hour ago" to a duration
pub fn rob_age_to_duration(mut age_str: &str) -> Result<Duration, AgeParseError> {
    age_str = age_str.strip_suffix(" ago").unwrap_or(age_str);

    let (num, unit) = age_str.split_once(' ').ok_or(AgeParseError::InvalidFormat)?;
    let num = num.parse::<u64>().map_err(|_| AgeParseError::InvalidNumber)?;

    // Now the funny part :)
    // done like that for optimization
    if unit.eq_ignore_ascii_case("second") || unit.eq_ignore_ascii_case("seconds") {
        Ok(Duration::from_secs(num))
    } else if unit.eq_ignore_ascii_case("minute") || unit.eq_ignore_ascii_case("minutes") {
        Ok(Duration::from_mins(num))
    } else if unit.eq_ignore_ascii_case("hour") || unit.eq_ignore_ascii_case("hours") {
        Ok(Duration::from_hours(num))
    } else if unit.eq_ignore_ascii_case("day") || unit.eq_ignore_ascii_case("days") {
        Ok(Duration::from_days(num))
    } else if unit.eq_ignore_ascii_case("week") || unit.eq_ignore_ascii_case("weeks") {
        Ok(Duration::from_weeks(num))
    } else if unit.eq_ignore_ascii_case("month") || unit.eq_ignore_ascii_case("months") {
        Ok(Duration::from_days(num * 30))
    } else if unit.eq_ignore_ascii_case("year") || unit.eq_ignore_ascii_case("years") {
        Ok(Duration::from_days(num * 365))
    } else {
        Err(AgeParseError::InvalidUnit)
    }
}
