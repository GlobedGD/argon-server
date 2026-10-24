use std::time::Duration;

use reqwest::header::HeaderMap;
use serde::Serialize;
use thiserror::Error;

use crate::gd::{LevelComment, Parseable, UserInfo, parseable::ParseError};

pub struct Client {
    client: reqwest::Client,
    base_url: String,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to send request: {0}")]
    Request(#[from] reqwest::Error),
    #[error("failed to parse response: {0}")]
    Parse(#[from] ParseError),
    #[error("ASN blocked by cloudflare")]
    AsnBlocked,
    #[error("IP blocked by cloudflare")]
    IpBlocked,
    #[error("rate limited by cloudflare")]
    RateLimited,
    #[error("cloudflare error code {0}")]
    Cloudflare(i32),
    #[error("website returned unparsable error")]
    Unknown,
}

impl Client {
    pub fn new(mut base_url: String, auth_token: Option<String>) -> Self {
        while base_url.ends_with('/') {
            base_url.pop();
        }

        let mut headers = HeaderMap::new();
        // add X-No-Cache header for gdproxy, ignored by official gd server
        headers.insert("X-No-Cache", "1".parse().unwrap());

        if let Some(token) = auth_token {
            headers.insert("Authorization", token.parse().unwrap());
        }

        Self {
            client: reqwest::Client::builder()
                .user_agent("")
                .connect_timeout(Duration::from_secs(5))
                .default_headers(headers)
                .build()
                .expect("failed to build http client"),

            base_url,
        }
    }

    pub async fn get_user_info(&self, account_id: i32) -> Result<UserInfo, Error> {
        #[derive(Serialize)]
        struct Payload<'a> {
            #[serde(rename = "targetAccountID")]
            id: i32,
            secret: &'a str,
        }

        self.send_request(
            "getGJUserInfo20.php",
            &Payload {
                id: account_id,
                secret: "Wmfd2893gb7",
            },
        )
        .await
    }

    pub async fn get_level_comments(&self, level_id: i32) -> Result<Vec<LevelComment>, Error> {
        #[derive(Serialize)]
        struct Payload<'a> {
            #[serde(rename = "levelID")]
            id: i32,
            page: u32,
            count: u32,
            mode: u32,
            secret: &'a str,
        }

        self.send_request(
            "getGJComments21.php",
            &Payload {
                id: level_id,
                page: 0,
                mode: 0,
                count: 100, // TODO: determine real max count
                secret: "Wmfd2893gb7",
            },
        )
        .await
    }

    async fn send_request<T: Parseable>(&self, suffix: &str, payload: &impl Serialize) -> Result<T, Error> {
        let url = format!("{}/{}", self.base_url, suffix);

        let req = self.client.post(&url).form(payload);

        let response = req.send().await?;
        let status = response.status();
        let text = response.text().await?;

        if !status.is_success()
            && let Some(text) = text.strip_prefix("error code:").map(|x| x.trim())
        {
            match text.parse::<i32>() {
                Ok(1005) => return Err(Error::AsnBlocked),
                Ok(1006) => return Err(Error::IpBlocked),
                Ok(1015) => return Err(Error::RateLimited),
                Ok(code) => return Err(Error::Cloudflare(code)),
                Err(_) => return Err(Error::Unknown),
            }
        }

        Ok(T::parse(&text)?)
    }
}
