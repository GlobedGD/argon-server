use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::db::entity::{dev_account, dev_api_key};

#[derive(Clone, Debug, Serialize)]
pub struct Developer {
    pub id: i64,
    pub username: String,
    pub setup_complete: bool,
    pub is_admin: bool,
}

impl From<dev_account::Model> for Developer {
    fn from(model: dev_account::Model) -> Self {
        Self {
            id: model.id,
            username: model.username,
            setup_complete: model.setup_complete,
            is_admin: model.is_admin,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct DevApiKey {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub scope: String,
    pub created_at: DateTime<Utc>,
    pub request_reload_ns: u64,
    pub owner: i64,
}

impl DevApiKey {
    pub fn rate_limit_summary(&self) -> String {
        let per_second = Duration::from_secs(1).as_nanos() as f64 / self.request_reload_ns as f64;
        let mut number_fmt = format!("{:.1}", per_second);
        if number_fmt.ends_with(".0") {
            number_fmt.truncate(number_fmt.len() - 2);
        }

        format!("{number_fmt} requests per second")
    }

    pub fn created_at_str(&self) -> String {
        self.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    }

    pub fn from_model(model: dev_api_key::Model) -> Self {
        Self {
            id: model.id,
            name: model.name,
            description: model.description,
            scope: model.scope,
            created_at: model.created_at.and_utc(),
            request_reload_ns: model.request_reload_ns as u64,
            owner: model.owner,
        }
    }
}

impl From<dev_api_key::Model> for DevApiKey {
    fn from(model: dev_api_key::Model) -> Self {
        Self::from_model(model)
    }
}
