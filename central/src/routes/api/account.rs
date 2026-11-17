use std::sync::Arc;

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use super::{ApiResult, error::ErrorBody};
use crate::{
    challenge::{ChallengeController, ChallengeData, ChallengeType},
    routes::util::extractors::{ExtractRefreshToken, VerifiedIpAddr},
    user::{RefreshedTokenPair, UserManager},
    util::ApiTime,
};

#[derive(Deserialize, utoipa::ToSchema)]
pub struct LoginData {
    account_id: i32,
    supported_challenges: Vec<ChallengeType>,
    requesting_mod: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct ChallengeResponse {
    #[serde(flatten)]
    pub challenge: ChallengeData,
}

/// Requests an auth challenge
#[utoipa::path(
    post,
    path = "/v2/account/login",
    tag = "account",
    request_body = LoginData,
    responses(
        (status = 200, body = ChallengeResponse),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ),
)]
pub async fn login(
    State(controller): State<Arc<ChallengeController>>,
    VerifiedIpAddr(addr): VerifiedIpAddr,
    Json(data): Json<LoginData>,
) -> ApiResult<Json<ChallengeResponse>> {
    // TODO: analytics
    let _ = data.requesting_mod;

    let ctype = controller.pick_supported_challenge_type(&data.supported_challenges)?;
    let data = controller.start_challenge(data.account_id, ctype, addr)?;

    Ok(Json(ChallengeResponse { challenge: data }))
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct SuccessfulLoginResponse {
    refresh_token: String,
    #[schema(value_type = i64)]
    refresh_token_valid_until: ApiTime,
    access_token: String,
    #[schema(value_type = i64)]
    access_token_valid_until: ApiTime,
}

impl From<RefreshedTokenPair> for SuccessfulLoginResponse {
    fn from(pair: RefreshedTokenPair) -> Self {
        Self {
            refresh_token: pair.refresh_token.0,
            refresh_token_valid_until: ApiTime::from_timestamp(pair.refresh_token_valid_until),
            access_token: pair.access_token.0,
            access_token_valid_until: ApiTime::from_timestamp(pair.access_token_valid_until),
        }
    }
}

/// Refreshes the user tokens using a refresh token
///
/// Depending on the user's security level this does either of the two things:
/// 1. Standard security -> refreshes both tokens and returns them
/// 2. Advanced security -> invalidates all other refresh tokens by incrementing epoch, then refreshes both tokens
#[utoipa::path(
    post,
    path = "/v2/account/refresh",
    tag = "account",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = SuccessfulLoginResponse),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ),
)]
pub async fn refresh(
    State(user_manager): State<Arc<UserManager>>,
    ExtractRefreshToken { claims }: ExtractRefreshToken,
) -> ApiResult<Json<SuccessfulLoginResponse>> {
    let pair = user_manager.generate_new_token_pair(&claims.account_data()).await?;
    Ok(Json(pair.into()))
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct VerifyData {
    challenge_id: u32,
    account_id: i32,
    answer: u32,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct VerifyResponse {
    completed: bool,
    #[serde(flatten)]
    #[schema(value_type = SuccessfulLoginResponse)]
    tokens: Option<SuccessfulLoginResponse>,
}

/// Attempts to complete a pending auth challenge
#[utoipa::path(
    post,
    path = "/v2/account/login/verify",
    tag = "account",
    request_body = VerifyData,
    responses(
        (status = 200, body = VerifyResponse),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ),
)]
pub async fn verify(
    State(controller): State<Arc<ChallengeController>>,
    State(user_manager): State<Arc<UserManager>>,
    Json(data): Json<VerifyData>,
) -> ApiResult<Json<VerifyResponse>> {
    let account_data = controller.poll_challenge(data.challenge_id, data.account_id, data.answer)?;

    let Some(account_data) = account_data else {
        // still not complete
        return Ok(Json(VerifyResponse {
            completed: false,
            tokens: None,
        }));
    };

    let pair = user_manager.on_challenge_completed(&account_data).await?;

    Ok(Json(VerifyResponse {
        completed: true,
        tokens: Some(pair.into()),
    }))
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct WebTokenResponse {
    pub token: String,
}

/// Generates an access code that can be passed to /login endpoint to automatically log into the user-facing part of the website.
#[utoipa::path(
    post,
    path = "/v2/account/webtoken",
    tag = "account",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = WebTokenResponse),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ),
)]
pub async fn generate_web_token(
    State(user_manager): State<Arc<UserManager>>,
    ExtractRefreshToken { claims }: ExtractRefreshToken,
) -> ApiResult<Json<WebTokenResponse>> {
    let code = user_manager.generate_web_access_code(&claims.account_data());
    Ok(Json(WebTokenResponse { token: code }))
}
