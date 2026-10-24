use std::{net::SocketAddr, sync::Arc};

use axum::{
    Json,
    extract::{ConnectInfo, State},
};
use serde::{Deserialize, Serialize};

use super::ApiResult;
use crate::{
    challenge::{ChallengeController, ChallengeData, ChallengeType},
    routes::extractors::ExtractRefreshToken,
    user::{RefreshedTokenPair, UserManager},
    util::ApiTime,
};

/// Start authenticating a GD user and return a challenge

#[derive(Deserialize)]
pub struct LoginData {
    account_id: i32,
    supported_challenges: Vec<ChallengeType>,
}

#[derive(Serialize)]
pub struct ChallengeResponse {
    #[serde(flatten)]
    pub challenge: ChallengeData,
}

/// Requests an auth challenge
pub async fn login(
    State(controller): State<Arc<ChallengeController>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(data): Json<LoginData>,
) -> ApiResult<Json<ChallengeResponse>> {
    let ctype = controller.pick_supported_challenge_type(&data.supported_challenges)?;
    let data = controller.start_challenge(data.account_id, ctype)?;

    Ok(Json(ChallengeResponse { challenge: data }))
}

#[derive(Serialize)]
pub struct SuccessfulLoginResponse {
    refresh_token: String,
    refresh_token_valid_until: ApiTime,
    access_token: String,
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

/// Refreshes the user tokens. Requires a valid refresh token, and depending on the user's security level does either of the two things:
/// 1. Standard security -> refreshes both tokens and returns them
/// 2. Advanced security -> invalidates all other refresh tokens by incrementing epoch, then refreshes both tokens
pub async fn refresh(
    State(user_manager): State<Arc<UserManager>>,
    ExtractRefreshToken(claims): ExtractRefreshToken,
) -> ApiResult<Json<SuccessfulLoginResponse>> {
    let pair = user_manager.generate_new_token_pair(&claims.account_data()).await?;
    Ok(Json(pair.into()))
}

#[derive(Deserialize)]
pub struct VerifyData {
    challenge_id: u32,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    completed: bool,
    #[serde(flatten)]
    tokens: Option<SuccessfulLoginResponse>,
}

/// Attempts to complete a pending auth challenge
pub async fn verify(
    State(controller): State<Arc<ChallengeController>>,
    State(user_manager): State<Arc<UserManager>>,
    Json(data): Json<VerifyData>,
) -> ApiResult<Json<VerifyResponse>> {
    let account_data = controller.poll_challenge(data.challenge_id)?;

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
