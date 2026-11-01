use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State},
    response::Redirect,
};
use serde::{Deserialize, Serialize};

use crate::{
    discord::{
        client::{DiscordClient, DiscordUserData, DiscordUserDataFull, OauthFlowType, SuccessfulOauthFlow},
        error::Error as DiscordError,
    },
    routes::{
        api::{ApiError, ApiResult, error::ErrorBody},
        util::{
            extractors::{ExtractAccManagementToken, ExtractAccessToken},
            responders::{Either, NoCache},
        },
    },
    user::UserManager,
};

#[derive(Serialize, utoipa::ToSchema)]
pub struct DiscordLinkStateResponse {
    pub linked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = DiscordUserDataFull)]
    pub discord_user: Option<DiscordUserDataFull>,
}

#[utoipa::path(
    get,
    path = "/v2/account/discord",
    tag = "discord",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = DiscordLinkStateResponse),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ),
)]
pub async fn get_link_state(
    State(user_manager): State<Arc<UserManager>>,
    ExtractAccessToken { claims }: ExtractAccessToken,
) -> ApiResult<Json<DiscordLinkStateResponse>> {
    let user = user_manager.get_discord_data_ext(claims.account_id()).await?;

    Ok(Json(DiscordLinkStateResponse {
        linked: user.is_some(),
        discord_user: user,
    }))
}

#[derive(Deserialize, utoipa::IntoParams)]
pub struct LinkQuery {
    return_to: Option<String>,
}

fn is_safe_redirect(url: &str) -> bool {
    url.starts_with('/') && !url.starts_with("//") && !url.starts_with("/\\")
}

#[utoipa::path(
    post,
    path = "/v2/account/discord/link",
    tag = "discord",
    security(("bearer_auth" = [])),
    params(LinkQuery),
    responses(
        (status = 302, description = "Redirect to the Discord authorization page"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ),
)]
pub async fn link(
    State(discord_client): State<Arc<DiscordClient>>,
    ExtractAccManagementToken { claims }: ExtractAccManagementToken,
    Query(query): Query<LinkQuery>,
) -> ApiResult<NoCache<Redirect>> {
    if query.return_to.as_deref().is_some_and(|url| !is_safe_redirect(url)) {
        return Err(ApiError::BadRedirectUrl);
    }

    let redirect_url =
        discord_client.begin_oauth_flow(claims.account_id(), OauthFlowType::Link, query.return_to);

    Ok(NoCache(Redirect::to(&redirect_url)))
}

#[utoipa::path(
    post,
    path = "/v2/account/discord/sync",
    tag = "discord",
    security(("bearer_auth" = [])),
    params(LinkQuery),
    responses(
        (status = 302, description = "Redirect to the Discord authorization page"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ),
)]
pub async fn sync(
    State(discord_client): State<Arc<DiscordClient>>,
    ExtractAccManagementToken { claims }: ExtractAccManagementToken,
    Query(query): Query<LinkQuery>,
) -> ApiResult<NoCache<Redirect>> {
    if query.return_to.as_deref().is_some_and(|url| !is_safe_redirect(url)) {
        return Err(ApiError::BadRedirectUrl);
    }

    let redirect_url =
        discord_client.begin_oauth_flow(claims.account_id(), OauthFlowType::Sync, query.return_to);
    Ok(NoCache(Redirect::to(&redirect_url)))
}

#[utoipa::path(
    delete,
    path = "/v2/account/discord",
    tag = "discord",
    security(("bearer_auth" = [])),
    responses(
        (status = 200),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ),
)]
pub async fn unlink(
    State(user_manager): State<Arc<UserManager>>,
    ExtractAccManagementToken { claims }: ExtractAccManagementToken,
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
        flow_type,
    } = discord_client.try_finish_oauth_flow(&code, &state).await?;

    // get user details
    let data = discord_client.get_self_user(&access_token).await?;

    // handle the result
    callback_followup(&user_manager, account_id, data, flow_type).await?;

    Ok(if let Some(uri) = return_to {
        Either::First(Redirect::to(&uri))
    } else {
        Either::Second("Link successful, you can close this tab now.".to_owned())
    })
}

async fn callback_followup(
    user_manager: &UserManager,
    account_id: i32,
    discord_data: DiscordUserData,
    flow_type: OauthFlowType,
) -> ApiResult<()> {
    match flow_type {
        OauthFlowType::Link => {
            // store in database
            user_manager.link_discord_account(account_id, discord_data).await?;
        }

        OauthFlowType::Sync => {
            // refresh some fields using the fetched data
            user_manager.sync_discord_account(account_id, discord_data).await?;
        }
    }
    Ok(())
}
