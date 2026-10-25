use std::path::PathBuf;

use config::{Config, Environment, File};
use serde::Deserialize;
use shared::{CONFIG_BASE_NAME, logging::LoggingConfig};
use thiserror::Error;
use validator::Validate;

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct NodeConfig {
    #[serde(default)]
    pub central: CentralConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub gd: GDConfig,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to load configuration: {0}")]
    Load(#[from] config::ConfigError),

    #[error("Failed to validate configuration: {0}")]
    Validation(#[from] validator::ValidationErrors),
}

impl NodeConfig {
    pub fn load() -> Result<Self, ConfigError> {
        let cfg: NodeConfig = Config::builder()
            .add_source(File::with_name(CONFIG_BASE_NAME).required(false))
            .add_source(Environment::with_prefix("ARGON_NODE").separator("_").try_parsing(true))
            .build()?
            .try_deserialize()?;

        cfg.validate()?;

        Ok(cfg)
    }
}

// Sub config structs

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CentralConfig {
    /// This can be ip or domain name with an optional port. If this is an IP and not a domain,
    /// the hostname must be set in the `hostname` setting for TLS to work.
    #[serde(default)]
    pub address: Option<String>,
    pub certificate: PathBuf,
    #[serde(default)]
    pub hostname: Option<String>,
    pub secret_key: String,
}

impl Default for CentralConfig {
    fn default() -> Self {
        Self {
            address: None,
            certificate: PathBuf::new(),
            hostname: None,
            secret_key: String::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GDConfig {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub auth_token: Option<String>,
}

impl Default for GDConfig {
    fn default() -> Self {
        Self {
            url: "https://www.boomlings.com/database".to_owned(),
            auth_token: None,
        }
    }
}
