use std::sync::Arc;

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use shared::message::GDAccountData;

use crate::user::{DiscordUserData, UserManager};

use super::ApiResult;

#[derive(Deserialize)]
pub struct CheckData {
    token: String,
    #[serde(default)]
    include_discord: bool,
}

#[derive(Serialize)]
pub struct CheckResponse {
    pub valid: bool,
    #[serde(flatten)]
    pub account_data: Option<GDAccountData>,
    pub discord_user: Option<DiscordUserData>,
}

pub async fn check(
    State(user_manager): State<Arc<UserManager>>,
    Json(body): Json<CheckData>,
) -> ApiResult<Json<CheckResponse>> {
    let account_data = match user_manager.validate_access_token(&body.token).await {
        Ok(data) => Some(data.account_data()),
        Err(e) if e.is_token_issue() => None,
        Err(e) => return Err(e.into()),
    };

    let discord_user = if let Some(data) = &account_data
        && body.include_discord
    {
        user_manager.get_discord_data(data.account_id).await?
    } else {
        None
    };

    Ok(Json(CheckResponse {
        valid: account_data.is_some(),
        account_data,
        discord_user,
    }))
}
