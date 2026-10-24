use std::sync::Arc;

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::{
    challenge::ChallengeController,
    routes::api_legacy::{LegacyApiError, LegacyApiResponse, LegacyApiResult},
    user::UserManager,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(unused)]
pub struct ChallengeStartData {
    account_id: i32,
    user_id: i32,
    username: String,
    force_strong: bool,
    req_mod: String,
    preferred: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeStartResponse {
    method: String,
    id: i32,
    challenge_id: u32,
    challenge: i32,
    ident: String,
}

pub async fn start(
    State(controller): State<Arc<ChallengeController>>,
    Json(data): Json<ChallengeStartData>,
) -> LegacyApiResult<Json<LegacyApiResponse<ChallengeStartResponse>>> {
    // v1 argon client did not care about returned method and always assumed that the actual used method is whatever it prefers.
    // and some older versions did not even support profile field auth to begin with, so to alleviate both issues,
    // simply return an error if preferred type is not profile field
    if data.preferred != "profile_field" {
        return Err(LegacyApiError::UnsupportedChallengeType);
    }

    let data = controller.start_legacy_challenge(data.account_id)?;

    Ok(Json(LegacyApiResponse::success(ChallengeStartResponse {
        method: "profile_field".to_owned(),
        id: data.resource_id,
        challenge_id: data.challenge_id,
        challenge: data.secret as i32,
        ident: controller.get_legacy_ident().unwrap().to_owned(),
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(unused)]
pub struct ChallengeVerifyData {
    challenge_id: u32,
    account_id: i32,
    solution: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeVerifyResponse {
    verified: bool,
    authtoken: Option<String>,
    comment_id: Option<i32>,
    poll_after: Option<u32>,
}

pub async fn poll(
    State(controller): State<Arc<ChallengeController>>,
    State(user_manager): State<Arc<UserManager>>,
    Json(data): Json<ChallengeVerifyData>,
) -> LegacyApiResult<Json<LegacyApiResponse<ChallengeVerifyResponse>>> {
    let account_data = controller.poll_challenge(data.challenge_id)?;

    let response = match account_data {
        Some(data) => {
            let token = user_manager.on_legacy_challenge_completed(&data).await;
            ChallengeVerifyResponse {
                verified: true,
                authtoken: Some(token),
                comment_id: Some(0), // doesn't matter
                poll_after: None,
            }
        }

        // still not complete
        None => ChallengeVerifyResponse {
            verified: false,
            authtoken: None,
            comment_id: None,
            poll_after: Some(2000), // 2 seconds
        },
    };

    Ok(Json(LegacyApiResponse::success(response)))
}
