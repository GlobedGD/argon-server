use std::sync::Arc;

use argon_shared::{format_duration, logger::*};
use parking_lot::Mutex as SyncMutex;
use rocket::{State, post, serde::json::Json};
use serde::{Deserialize, Serialize};

use crate::{
    rate_limiter::RateLimiter,
    routes::{
        api_error::{ApiError, ApiResult},
        routes_util::*,
    },
    state::{ChallengeValidationError, ServerState},
    token_issuer::TokenIssuer,
};

pub fn default_preferred_auth_method() -> String {
    "message".to_owned()
}

/* Helper types for client endpoints */

#[derive(Serialize)]
pub struct GenericResponse<T: Serialize> {
    success: bool,
    error: Option<String>,
    data: Option<T>,
}

impl<T: Serialize> GenericResponse<T> {
    pub fn make(data: T) -> Json<Self> {
        Json(Self {
            success: true,
            error: None,
            data: Some(data),
        })
    }

    #[allow(unused)]
    pub fn make_error(error: String) -> Json<Self> {
        Json(Self {
            success: false,
            error: Some(error),
            data: None,
        })
    }
}

pub type ClientApiResult<T> = ApiResult<Json<GenericResponse<T>>, true>;

#[derive(Deserialize)]
pub struct ChallengeStartData {
    #[serde(rename = "accountId")]
    pub account_id: i32,
    #[serde(rename = "userId")]
    pub user_id: i32,
    pub username: String,
    #[serde(rename = "forceStrong", default = "default_false")]
    pub force_strong: bool,
    #[serde(rename = "reqMod", default = "default_empty_string")]
    pub req_mod: String,
    #[serde(default = "default_preferred_auth_method")]
    pub preferred: String,
}

#[derive(Serialize)]
pub struct ChallengeStartResponse {
    pub method: &'static str,
    pub id: i32,
    #[serde(rename = "challengeId")]
    pub challenge_id: u32,
    pub challenge: i32,
    pub ident: String,
}

#[post("/challenge/start", data = "<data>")]
pub async fn challenge_start(
    rate_limiter: &State<Arc<SyncMutex<RateLimiter>>>,
    state_: &State<ServerState>,
    data: Json<ChallengeStartData>,
    ip: CloudflareIPGuard,
) -> ClientApiResult<ChallengeStartResponse> {
    if data.account_id <= 0 || data.user_id <= 0 || !(1usize..=16usize).contains(&data.username.trim().len())
    {
        return Err(ApiError::bad_request("invalid account data"));
    }

    let user_ip = ip.0;

    if !rate_limiter.lock().start_challenge(user_ip, data.account_id) {
        warn!(
            "[{} @ {user_ip}] disallowing challenge start, rate limit exceeded",
            data.account_id
        );
        return Err(ApiError::too_many_requests("rate limit exceeded"));
    }

    let state = state_.state_read().await;

    // Currently, only message auth is supported
    let auth_method = "message";

    let (challenge_id, challenge) = match state.create_challenge(
        data.account_id,
        data.user_id,
        data.username.clone(),
        data.force_strong,
    ) {
        Ok(c) => c,
        Err(err) => return Err(ApiError::bad_request(err.to_string())),
    };

    let id = match state.pick_id_for_message_challenge().await {
        Some(x) => x,
        None => {
            warn!(
                "[{} @ {}] Cannot create challenge, no available nodes",
                data.account_id, user_ip
            );

            return Err(ApiError::internal_server_error(
                "no node is currently available to process this auth request",
            ));
        }
    };

    debug!(
        "[{} @ {}] Created challenge (method: {}, cid: {}, mod: {})",
        data.account_id, user_ip, auth_method, challenge_id, data.req_mod
    );

    Ok(GenericResponse::make(ChallengeStartResponse {
        challenge,
        challenge_id,
        method: auth_method,
        id,
        ident: state.ident().to_owned(),
    }))
}

#[post("/challenge/restart", data = "<data>")]
pub async fn challenge_restart(
    rate_limiter: &State<Arc<SyncMutex<RateLimiter>>>,
    state: &State<ServerState>,
    data: Json<ChallengeStartData>,
    ip: CloudflareIPGuard,
) -> ClientApiResult<ChallengeStartResponse> {
    challenge_start(rate_limiter, state, data, ip).await
}

#[derive(Deserialize)]
pub struct ChallengeVerifyData {
    #[serde(rename = "challengeId")]
    challenge_id: u32,

    #[serde(rename = "accountId")]
    account_id: i32,
    solution: String,
}

#[derive(Serialize)]
pub struct ChallengeVerifyResponse {
    verified: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    authtoken: Option<String>,

    #[serde(rename = "commentId", skip_serializing_if = "Option::is_none")]
    comment_id: Option<i32>,

    #[serde(rename = "pollAfter", skip_serializing_if = "Option::is_none")]
    poll_after: Option<u32>,
}

#[post("/challenge/verify", data = "<data>")]
pub async fn challenge_verify(
    rate_limiter: &State<Arc<SyncMutex<RateLimiter>>>,
    issuer: &State<Arc<TokenIssuer>>,
    state: &State<ServerState>,
    data: Json<ChallengeVerifyData>,
    ip: CloudflareIPGuard,
) -> ClientApiResult<ChallengeVerifyResponse> {
    let user_ip = ip.0;

    let state = state.state_read().await;

    let mut rate_limiter = rate_limiter.lock();

    if !rate_limiter.can_verify_poll(user_ip, data.account_id) {
        warn!(
            "[{} @ {user_ip}] disallowing challenge verify, rate limit exceeded",
            data.account_id
        );
        return Err(ApiError::too_many_requests("rate limit exceeded"));
    }

    let strong = match state.is_challenge_validated(
        data.challenge_id,
        data.account_id,
        data.solution.parse::<i32>().unwrap_or_default(),
    ) {
        Ok((true, strong)) => strong,

        Ok((false, _)) => {
            // tell them to poll again
            return Ok(GenericResponse::make(ChallengeVerifyResponse {
                verified: false,
                authtoken: None,
                comment_id: None,
                poll_after: Some(state.config.msg_check_interval / 2),
            }));
        }

        Err(ChallengeValidationError::NoChallenge) => {
            rate_limiter.record_challenge_fail(user_ip, data.account_id);
            warn!(
                "[{} @ {user_ip}] attempting to verify inexisting challenge",
                data.account_id
            );

            return Err(ApiError::bad_request(
                "no auth challenge exists for this challenge ID, try again",
            ));
        }

        Err(ChallengeValidationError::WrongAccount) => {
            rate_limiter.record_challenge_fail(user_ip, data.account_id);
            warn!(
                "[{} @ {user_ip}] attempting to verify challenge for the wrong account",
                data.account_id
            );

            return Err(ApiError::bad_request(
                "challenge was started for a different account",
            ));
        }

        Err(ChallengeValidationError::WrongSolution) => {
            rate_limiter.record_challenge_fail(user_ip, data.account_id);
            warn!(
                "[{} @ {user_ip}] attempting to verify challenge with incorrect solution",
                data.account_id
            );

            return Err(ApiError::bad_request("challenge solution is incorrect"));
        }
    };

    // the challenge was verified! delete it and generate the authtoken
    let challenge = state.erase_challenge(data.challenge_id);
    assert!(challenge.is_some(), "challenge should exist after being verified");

    rate_limiter.record_challenge_success(user_ip, data.account_id);
    drop(rate_limiter);

    let challenge = challenge.unwrap();

    // if we wanted to force strong integrity but failed, return an error
    if challenge.force_strong && !strong {
        debug!(
            "[{} @ {user_ip}] strong verification failed and forceStrong is enabled",
            data.account_id
        );

        return Err(ApiError::bad_request(
            "username validation failed, please try to refresh login in GD account settings",
        ));
    }

    let token = issuer.generate(&challenge);

    if strong {
        info!(
            "[{} @ {user_ip}] Created strong token for {} (auth flow took {})",
            challenge.account_id,
            challenge.actual_username,
            format_duration(&challenge.started_at.elapsed().unwrap_or_default(), false)
        );
    } else {
        info!(
            "[{} @ {user_ip}] Created *weak* token for {} (actual name: {}) (auth flow took {})",
            challenge.account_id,
            challenge.username,
            challenge.actual_username,
            format_duration(&challenge.started_at.elapsed().unwrap_or_default(), false)
        );
    }

    Ok(GenericResponse::make(ChallengeVerifyResponse {
        verified: true,
        authtoken: Some(token),
        comment_id: Some(challenge.user_comment_id),
        poll_after: None,
    }))
}

#[post("/challenge/verifypoll", data = "<data>")]
pub async fn challenge_verify_poll(
    rate_limiter: &State<Arc<SyncMutex<RateLimiter>>>,
    issuer: &State<Arc<TokenIssuer>>,
    state: &State<ServerState>,
    data: Json<ChallengeVerifyData>,
    ip: CloudflareIPGuard,
) -> ClientApiResult<ChallengeVerifyResponse> {
    challenge_verify(rate_limiter, issuer, state, data, ip).await
}
