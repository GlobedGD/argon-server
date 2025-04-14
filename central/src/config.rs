use std::{
    fs::{File, OpenOptions},
    path::Path,
};

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
    rand::rng().sample_iter(&Alphanumeric).take(32).map(char::from).collect()
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GDAccountCreds {
    pub id: i32,
    pub gjp: String,
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
    #[serde(default = "default_false")]
    pub cloudflare_protection: bool,
}

impl ServerConfig {
    pub fn load(source: &Path) -> anyhow::Result<Self> {
        let file = File::open(source)?;
        let stripped = StripComments::new(file);

        Ok(serde_json::from_reader(stripped)?)
    }

    pub fn save(&self, dest: &Path) -> anyhow::Result<()> {
        let writer = OpenOptions::new().write(true).create(true).truncate(true).open(dest)?;

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
        serde_json::from_str("{}").unwrap()
    }
}
