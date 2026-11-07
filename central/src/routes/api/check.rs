use std::sync::Arc;

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use shared::message::GDAccountData;

use crate::{
    developer::DevScope,
    discord::client::DiscordUserData,
    routes::{api::ApiError, util::extractors::ApiKeyRateLimit},
    user::UserManager,
};

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
    ApiKeyRateLimit: ApiKeyRateLimit<{ DevScope::TokenValidation }, false>,
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

#[derive(Deserialize, utoipa::ToSchema)]
pub struct DiscordLookupData {
    /// GD account ID to look up. If both are provided, this takes precedence.
    #[serde(default)]
    account_id: Option<i32>,
    /// Discord user ID to look up. If both are provided, this is ignored.
    #[serde(default)]
    discord_id: Option<u64>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct DiscordLookupResponse {
    /// The user's GD account ID
    pub account_id: i32,
    /// The linked discord account
    pub discord_user: DiscordUserData,
}

/// Looks up a relation between a Discord account and a GD account (bidirectional)
///
/// Provided the API key is correct and no other errors happen, the response is determined as such:
/// * If `account_id` is provided AND the user is linked to a Discord account, the response is a 200 with the link details
/// * If `discord_id` is provided AND the user is linked to a GD account, the response is a 200 with the link details
/// * If neither are provided, the response is a 400
/// * Otherwise, the response is a 404, meaning the user is not linked
///
/// This requires an API key with an appropriate scope (Discord)
#[utoipa::path(
    post,
    path = "/v2/discord/lookup",
    tag = "discord",
    security(("api_key" = [])),
    request_body = DiscordLookupData,
    responses(
        (status = 200, body = DiscordLookupResponse),
        (status = 400, body = ErrorBody, description = "Invalid parameters were provided"),
        (status = 401, body = ErrorBody, description = "The provided API key is invalid"),
        (status = 404, body = ErrorBody, description = "User was not found"),
        (status = 429, body = ErrorBody, description = "Rate limited"),
        (status = 500, body = ErrorBody),
    ),
)]
pub async fn discord_lookup(
    State(user_manager): State<Arc<UserManager>>,
    ApiKeyRateLimit: ApiKeyRateLimit<{ DevScope::Discord }>,
    Json(body): Json<DiscordLookupData>,
) -> ApiResult<Json<DiscordLookupResponse>> {
    if let Some(account_id) = body.account_id {
        if let Some(discord_user) = user_manager.get_discord_data(account_id).await? {
            return Ok(Json(DiscordLookupResponse {
                account_id,
                discord_user,
            }));
        }
    } else if let Some(discord_id) = body.discord_id {
        if let Some((account_id, discord_user)) =
            user_manager.get_user_data_by_discord_id(discord_id as i64).await?
        {
            return Ok(Json(DiscordLookupResponse {
                account_id,
                discord_user,
            }));
        }
    } else {
        return Err(ApiError::BadRequest("missing both `account_id` and `discord_id` fields".to_owned()));
    }

    Err(ApiError::NotFound)
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct DiscordLookupAllResponse {
    pub users: Vec<DiscordLookupResponse>,
}

/// Looks up every account that's linked to a Discord account and returns all of them.
///
/// This requires an API key with an appropriate scope (DiscordLookupAll)
#[utoipa::path(
    post,
    path = "/v2/discord/lookup-all",
    tag = "discord",
    security(("api_key" = [])),
    request_body = DiscordLookupData,
    responses(
        (status = 200, body = DiscordLookupAllResponse),
        (status = 401, body = ErrorBody, description = "The provided API key is invalid"),
        (status = 429, body = ErrorBody, description = "Rate limited"),
        (status = 500, body = ErrorBody),
    ),
)]
pub async fn discord_lookup_all(
    State(user_manager): State<Arc<UserManager>>,
    ApiKeyRateLimit: ApiKeyRateLimit<{ DevScope::DiscordLookupAll }>,
) -> ApiResult<Json<DiscordLookupAllResponse>> {
    let users = user_manager.get_all_linked_users().await?;

    Ok(Json(DiscordLookupAllResponse {
        users: users
            .into_iter()
            .map(|(account_id, discord_user)| DiscordLookupResponse {
                account_id,
                discord_user,
            })
            .collect(),
    }))
}
