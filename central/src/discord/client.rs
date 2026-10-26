use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};

use crate::{config::AppConfig, db::entity::discord_user, discord::error::Error};

type Result<T> = std::result::Result<T, Error>;

pub enum OauthFlowType {
    Link,
    Sync,
}

struct LinkAttempt {
    account_id: i32,
    return_to: Option<String>,
    flow_type: OauthFlowType,
    started_at: Instant,
}

pub struct DiscordClient {
    client: reqwest::Client,
    client_id: String,
    client_secret: String,
    redirect_uri: String,

    link_attempts: DashMap<u64, LinkAttempt>,
}

#[derive(Serialize)]
pub struct DiscordUserData {
    pub account_id: i64,
    pub username: String,
    pub avatar_url: String,
}

#[derive(Serialize)]
pub struct DiscordUserDataFull {
    pub account_id: i64,
    pub username: String,
    pub avatar_url: String,
    pub last_sync_time: chrono::NaiveDateTime,
}

impl From<discord_user::Model> for DiscordUserDataFull {
    fn from(model: discord_user::Model) -> Self {
        Self {
            account_id: model.user_id,
            username: model.username,
            avatar_url: model.avatar_url,
            last_sync_time: model.last_sync_time,
        }
    }
}

impl From<DiscordUserDataFull> for DiscordUserData {
    fn from(full: DiscordUserDataFull) -> Self {
        Self {
            account_id: full.account_id,
            username: full.username,
            avatar_url: full.avatar_url,
        }
    }
}

pub struct SuccessfulOauthFlow {
    pub account_id: i32,
    pub access_token: String,
    pub return_to: Option<String>,
    pub flow_type: OauthFlowType,
}

#[derive(Deserialize)]
struct ApiUserObject {
    #[serde(deserialize_with = "deserialize_i64_str")]
    id: i64,
    username: String,
    avatar: Option<String>,
}

impl DiscordClient {
    pub fn new(config: &AppConfig) -> Self {
        let client = reqwest::ClientBuilder::new().build().expect("failed to build http client");

        Self {
            client,
            client_id: config.discord.client_id.clone(),
            client_secret: config.discord.client_secret.clone(),
            redirect_uri: config.discord.redirect_uri.clone(),
            link_attempts: DashMap::new(),
        }
    }

    pub fn run_cleanup(&self) {
        self.link_attempts.retain(|_, v| v.started_at.elapsed() < Duration::from_mins(5));
    }

    pub fn begin_oauth_flow(
        &self,
        account_id: i32,
        flow_type: OauthFlowType,
        return_to: Option<String>,
    ) -> String {
        let secret: u64 = rand::random();

        self.link_attempts.insert(
            secret,
            LinkAttempt {
                account_id,
                return_to,
                flow_type,
                started_at: Instant::now(),
            },
        );

        format!(
            "https://discord.com/api/oauth2/authorize?client_id={}&redirect_uri={}&response_type=code&scope=identify&state={}-{}",
            self.client_id, self.redirect_uri, account_id, secret
        )
    }

    pub async fn try_finish_oauth_flow(&self, code: &str, state: &str) -> Result<SuccessfulOauthFlow> {
        let (account_id_str, secret_str) = state.split_once('-').ok_or(Error::MalformedCallback)?;
        let account_id = account_id_str.parse::<i32>()?;
        let secret = secret_str.parse::<u64>()?;

        let (_, attempt) = self.link_attempts.remove(&secret).ok_or(Error::MismatchedState)?;
        if attempt.account_id != account_id {
            return Err(Error::MismatchedState);
        }

        let token = self.get_oauth2_token(code).await?;
        Ok(SuccessfulOauthFlow {
            account_id,
            access_token: token,
            return_to: attempt.return_to,
            flow_type: attempt.flow_type,
        })
    }

    pub async fn get_oauth2_token(&self, code: &str) -> Result<String> {
        #[derive(Deserialize)]
        struct Response {
            access_token: String,
        }

        let payload = [
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("code", code),
        ];

        let r = self.post_form::<Response, _>("oauth/token", &payload, None).await?;
        Ok(r.access_token)
    }

    pub async fn get_self_user(&self, access_token: &str) -> Result<DiscordUserData> {
        let user = self.get::<ApiUserObject>("users/@me", format!("Bearer {access_token}")).await?;

        Ok(DiscordUserData {
            account_id: user.id,
            username: user.username,
            avatar_url: self.avatar_url(user.id, user.avatar.as_deref()),
        })
    }

    fn avatar_url(&self, id: i64, hash: Option<&str>) -> String {
        if let Some(hash) = hash {
            format!("https://cdn.discordapp.com/avatars/{id}/{hash}.webp?size=1024")
        } else {
            // default avatars with discord logo
            let index = (id >> 22) % 6;
            format!("https://cdn.discordapp.com/embed/avatars/{index}.png")
        }
    }

    fn url(&self, suffix: impl AsRef<str>) -> String {
        format!("https://discord.com/api/v10/{}", suffix.as_ref())
    }

    async fn get<T: DeserializeOwned>(
        &self,
        suffix: impl AsRef<str>,
        auth: impl Into<Option<String>>,
    ) -> Result<T> {
        let url = self.url(suffix);
        let auth = auth.into();

        let mut req = self.client.get(url);
        if let Some(auth) = auth {
            req = req.header("Authorization", auth);
        }

        let response = req.send().await?.error_for_status()?;
        Ok(response.json().await?)
    }

    async fn post_form<T: DeserializeOwned, S: Serialize>(
        &self,
        suffix: impl AsRef<str>,
        body: &S,
        auth: impl Into<Option<String>>,
    ) -> Result<T> {
        let url = self.url(suffix);
        let auth = auth.into();

        let mut req = self.client.post(url).form(body);
        if let Some(auth) = auth {
            req = req.header("Authorization", auth);
        }

        let response = req.send().await?.error_for_status()?;
        Ok(response.json().await?)
    }
}

fn deserialize_i64_str<'de, D: Deserializer<'de>>(deserializer: D) -> std::result::Result<i64, D::Error> {
    let s = String::deserialize(deserializer)?;
    s.parse::<i64>().map_err(serde::de::Error::custom)
}
