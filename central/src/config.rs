use std::{net::SocketAddr, path::PathBuf, time::Duration};

use config::{Config, Environment, File};
use serde::Deserialize;
use shared::{DOCKER_CONFIG_BASE_NAME, logging::LoggingConfig, resource::ResourceType};
use thiserror::Error;
use validator::Validate;

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct AppConfig {
    #[serde(default)]
    pub http: HttpConfig,
    #[serde(default)]
    pub node_handler: NodeHandlerConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub legacy: LegacyConfig,
    #[serde(default)]
    pub discord: DiscordConfig,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to load configuration: {0}")]
    Load(#[from] config::ConfigError),

    #[error("Failed to validate configuration: {0}")]
    Validation(#[from] validator::ValidationErrors),
}

impl AppConfig {
    pub fn load() -> Result<Self, ConfigError> {
        let cfg: AppConfig = Config::builder()
            .add_source(File::with_name(DOCKER_CONFIG_BASE_NAME).required(false))
            .add_source(File::with_name("config.toml").required(false))
            .add_source(Environment::with_prefix("ARGON").separator("_").try_parsing(true))
            .build()?
            .try_deserialize()?;

        cfg.validate()?;

        Ok(cfg)
    }
}

// Sub config structs

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpConfig {
    pub bind: SocketAddr,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8000".parse().unwrap(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeHandlerConfig {
    pub bind: SocketAddr,
    pub secret_key: String,
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
}

impl Default for NodeHandlerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8001".parse().unwrap(),
            secret_key: "".to_owned(),
            tls_cert: PathBuf::new(),
            tls_key: PathBuf::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(default, deny_unknown_fields)]
pub struct DatabaseConfig {
    #[validate(length(min = 1))]
    pub url: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "sqlite://db.sqlite?mode=rwc".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(default, deny_unknown_fields)]
pub struct AuthResourceConfig {
    pub r#type: ResourceType,
    #[serde(default)]
    pub id: i32,
    /// Whether the resource can be claimed by multiple worker nodes. When only 1 node is used, nothing changes.
    /// If multiple nodes are used, `reusable = false` will mean only 1 node can claim that resource, and others will have to try another resource.
    #[serde(default = "default_reusable")]
    pub reusable: bool,
}

impl Default for AuthResourceConfig {
    fn default() -> Self {
        Self {
            r#type: ResourceType::ProfileField,
            id: 0,
            reusable: true,
        }
    }
}

fn default_reusable() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    pub resources: Vec<AuthResourceConfig>,
    #[validate(custom(function = "validate_secret_key"))]
    pub secret_key: String,
    #[serde(with = "humantime_serde", default = "default_refresh_token_expiry")]
    pub refresh_token_expiry: Duration,
    #[serde(with = "humantime_serde", default = "default_access_token_expiry")]
    pub access_token_expiry: Duration,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            resources: vec![AuthResourceConfig::default()],
            secret_key: String::new(),
            refresh_token_expiry: default_refresh_token_expiry(),
            access_token_expiry: default_access_token_expiry(),
        }
    }
}

fn validate_secret_key(key: &str) -> Result<(), validator::ValidationError> {
    if key.len() != 64 || !key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(validator::ValidationError::new(
            "invalid secret key, must be a 256-bit hex-encoded string",
        ));
    }
    Ok(())
}

fn default_refresh_token_expiry() -> Duration {
    Duration::from_days(30)
}

fn default_access_token_expiry() -> Duration {
    Duration::from_mins(15)
}

#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(default, deny_unknown_fields)]
pub struct LegacyConfig {
    pub enabled: bool,
    pub ident: Option<String>,
    #[serde(with = "humantime_serde", default = "default_legacy_token_expiry")]
    pub token_expiry: Duration,
}

impl Default for LegacyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ident: None,
            token_expiry: default_legacy_token_expiry(),
        }
    }
}

fn default_legacy_token_expiry() -> Duration {
    Duration::from_days(7)
}

#[derive(Default, Debug, Clone, Deserialize, Validate)]
#[serde(default, deny_unknown_fields)]
pub struct DiscordConfig {
    pub enabled: bool,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}
