use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State},
    response::Redirect,
};
use serde::{Deserialize, Serialize};

use crate::{
    discord::{
        client::{DiscordClient, DiscordUserData, SuccessfulOauthFlow},
        error::Error as DiscordError,
    },
    routes::{
        api::{ApiError, ApiResult},
        util::{
            extractors::ExtractRefreshToken,
            responders::{Either, NoCache},
        },
    },
    user::UserManager,
};

#[derive(Serialize)]
pub struct DiscordLinkStateResponse {
    pub linked: bool,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub user: Option<DiscordUserData>,
}

pub async fn get_link_state(
    State(user_manager): State<Arc<UserManager>>,
    ExtractRefreshToken(claims): ExtractRefreshToken,
) -> ApiResult<Json<DiscordLinkStateResponse>> {
    let user = user_manager.get_discord_data(claims.account_id()).await?;

    Ok(Json(DiscordLinkStateResponse {
        linked: user.is_some(),
        user,
    }))
}

#[derive(Deserialize)]
pub struct LinkQuery {
    return_to: Option<String>,
}

pub async fn link(
    State(discord_client): State<Arc<DiscordClient>>,
    ExtractRefreshToken(claims): ExtractRefreshToken,
    Query(query): Query<LinkQuery>,
) -> NoCache<Redirect> {
    let redirect_url = discord_client.begin_oauth_flow(claims.account_id(), query.return_to);
    NoCache(Redirect::to(&redirect_url))
}

pub async fn unlink(
    State(user_manager): State<Arc<UserManager>>,
    ExtractRefreshToken(claims): ExtractRefreshToken,
) -> ApiResult<()> {
    let unlinked = user_manager.unlink_discord_user(claims.account_id()).await?;
    if unlinked {
        Ok(())
    } else {
        Err(ApiError::Discord(DiscordError::DiscordNotLinked))
    }
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: String,
    state: String,
}

pub async fn link_callback(
    State(user_manager): State<Arc<UserManager>>,
    State(discord_client): State<Arc<DiscordClient>>,
    Query(CallbackQuery { code, state }): Query<CallbackQuery>,
) -> ApiResult<Either<Redirect, String>> {
    let SuccessfulOauthFlow {
        account_id,
        access_token,
        return_to,
    } = discord_client.try_finish_oauth_flow(&code, &state).await?;

    // get user details
    let data = discord_client.get_self_user(&access_token).await?;

    // store in database
    user_manager.link_discord_account(account_id, data).await?;

    Ok(if let Some(uri) = return_to {
        Either::First(Redirect::to(&uri))
    } else {
        Either::Second("Link successful, you can close this tab now.".to_owned())
    })
}
