use std::{
    fs::{File, OpenOptions},
    path::Path,
};

use argon_shared::generate_keypair;
use json_comments::StripComments;
use rand::{Rng, distr::Alphanumeric};
use serde::{Deserialize, Serialize};
use serde_json::{Serializer, ser::PrettyFormatter};

fn default_false() -> bool {
    false
}

fn default_accounts() -> Vec<GDAccountCreds> {
    Vec::new()
}

fn default_base_url() -> String {
    "https://www.boomlings.com/database".to_owned()
}

fn default_msg_check_interval() -> u32 {
    4000 // 4 seconds
}

fn default_handler_address() -> String {
    "0.0.0.0:4340".to_owned()
}

fn default_password() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

fn default_string() -> String {
    String::new()
}

fn gen_secret_key() -> String {
    hex::encode(generate_keypair().0.to_bytes())
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GDAccountCreds {
    pub id: i32,
    pub gjp: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RateLimitConfig {
    // all of those are per hour
    pub max_accounts_per_ip: usize,
    pub max_tokens_per_ip: usize,
    pub max_failures_per_ip: usize,
    pub max_attempts_per_ip: usize,

    pub validations_per_day: usize,
    pub validations_per_hour: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_accounts_per_ip: 10,
            max_tokens_per_ip: 20,
            max_failures_per_ip: 30,
            max_attempts_per_ip: 120,
            validations_per_day: 10000,
            validations_per_hour: 750,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ServerConfig {
    #[serde(default = "default_false")]
    pub distributed_mode: bool,
    #[serde(default = "default_accounts")]
    pub accounts: Vec<GDAccountCreds>,
    #[serde(default = "default_base_url")]
    pub base_url: String,
    #[serde(default = "default_msg_check_interval")]
    pub msg_check_interval: u32,
    #[serde(default = "default_handler_address")]
    pub handler_address: String,
    #[serde(default = "default_password")]
    pub password: String,
    #[serde(default = "default_string")]
    pub secret_key: String,
    #[serde(default = "default_false")]
    pub cloudflare_protection: bool,

    // rate limit stuff
    #[serde(default)]
    pub rate_limits: RateLimitConfig,
}

impl ServerConfig {
    pub fn load(source: &Path) -> anyhow::Result<Self> {
        let file = File::open(source)?;
        let stripped = StripComments::new(file);
        let config: ServerConfig = serde_json::from_reader(stripped)?;

        Ok(config)
    }

    pub fn save(&self, dest: &Path) -> anyhow::Result<()> {
        let writer = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(dest)?;

        let formatter = PrettyFormatter::with_indent(b"    ");
        let mut serializer = Serializer::with_formatter(writer, formatter);
        self.serialize(&mut serializer)?;

        Ok(())
    }

    pub fn reload_in_place(&mut self, source: &Path) -> anyhow::Result<()> {
        let conf = Self::load(source)?;

        self.clone_from(&conf);
        Ok(())
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        let mut val: ServerConfig = serde_json::from_str("{}").unwrap();
        val.secret_key = gen_secret_key();

        val
    }
}
