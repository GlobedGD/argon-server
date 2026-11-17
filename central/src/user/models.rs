use serde::Serialize;
use shared::message::GDAccountData;

use crate::db::entity::user;

#[derive(Clone, Debug, Serialize)]
pub struct User {
    pub account_id: i32,
    pub gd_user_id: Option<i32>,
    pub username: Option<String>,
    pub advanced_auth: bool,
    pub token_epoch: i64,
    pub discord_id: Option<i64>,
}

impl User {
    pub fn new(account_data: &GDAccountData) -> Self {
        Self {
            account_id: account_data.account_id,
            gd_user_id: Some(account_data.user_id),
            username: Some(account_data.username.clone()),
            advanced_auth: false,
            token_epoch: 0,
            discord_id: None,
        }
    }

    pub fn username(&self) -> &str {
        self.username.as_deref().unwrap_or("Player")
    }
}

impl From<user::Model> for User {
    fn from(model: user::Model) -> Self {
        Self {
            account_id: model.id as i32,
            gd_user_id: model.gd_user_id.map(|x| x as i32),
            username: model.username,
            advanced_auth: model.advanced_auth,
            token_epoch: model.token_epoch,
            discord_id: model.discord_id,
        }
    }
}

impl From<User> for user::Model {
    fn from(value: User) -> Self {
        Self {
            id: value.account_id as i64,
            gd_user_id: value.gd_user_id.map(|x| x as i64),
            username: value.username,
            advanced_auth: value.advanced_auth,
            token_epoch: value.token_epoch,
            discord_id: value.discord_id,
        }
    }
}
