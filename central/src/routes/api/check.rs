use std::sync::Arc;

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use shared::message::GDAccountData;

use crate::{discord::client::DiscordUserData, routes::util::extractors::ApiKeyRateLimit, user::UserManager};

use super::{ApiResult, error::ErrorBody};

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CheckData {
    /// User's access token that should be validated
    token: String,
    /// Whether to also return the user's Discord account, if one is linked.
    #[serde(default)]
    include_discord: bool,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct CheckResponse {
    pub valid: bool,
    /// Only present when `valid` is `true`, the data of the GD account that the token belongs to.
    /// This is not guaranteed to be 100% up to date, but it is the best available data we have.
    /// This can be used to derive the user's username without needing to make a request to GD servers.
    pub account_data: Option<GDAccountData>,
    /// Linked Discord account, only present if requested and linked.
    pub discord_user: Option<DiscordUserData>,
}

/// Validates an access token and optionally returns the account and Discord data it belongs to
///
/// This requires no authentication, but has rate limits based on your IP address.
/// An API key allows you to get a custom, higher rate limit.
#[utoipa::path(
    post,
    path = "/v2/token/validate",
    tag = "token",
    security((), ("api_key" = [])),
    request_body = CheckData,
    responses(
        (status = 200, body = CheckResponse),
        (status = 401, body = ErrorBody, description = "The provided API key is invalid. Note: this concerns specifically the API key in authorization header, not the access token being verified."),
        (status = 429, body = ErrorBody, description = "Rate limited"),
        (status = 500, body = ErrorBody),
    ),
)]
pub async fn check(
    State(user_manager): State<Arc<UserManager>>,
    ApiKeyRateLimit: ApiKeyRateLimit,
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
