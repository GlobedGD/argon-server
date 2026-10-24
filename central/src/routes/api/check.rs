use std::sync::Arc;

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use shared::message::GDAccountData;

use crate::user::UserManager;

use super::ApiResult;

#[derive(Deserialize)]
pub struct CheckData {
    token: String,
}

#[derive(Serialize)]
pub struct CheckResponse {
    pub valid: bool,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub account_data: Option<GDAccountData>,
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

    Ok(Json(CheckResponse {
        valid: account_data.is_some(),
        account_data,
    }))
}
