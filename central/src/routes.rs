use std::{net::IpAddr, time::Duration};

use argon_shared::logger::*;
use rocket::{Route, State, get, post, routes, serde::json::Json};
use serde::{Deserialize, Serialize};

use crate::{
    api_error::{ApiError, ApiResult},
    routes_util::*,
    state::{ChallengeValidationError, ServerState},
};

#[derive(Serialize)]
pub struct StatusResponse {
    pub active: bool,
    pub total_nodes: usize,
    pub active_nodes: usize,
    pub ident: String,
}

#[get("/status")]
pub async fn status(state: &State<ServerState>) -> Json<StatusResponse> {
    let state = state.state_read().await;

    Json(StatusResponse {
        total_nodes: state.node_count,
        active_nodes: state.active_node_count,
        active: state.active_node_count > 0,
        ident: state.server_ident.clone(),
    })
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

pub type ClientApiResult<T> = ApiResult<Json<GenericResponse<T>>>;

fn format_duration(dur: &Duration, long: bool) -> String {
    if dur.as_secs() > 60 * 60 * 24 {
        let days = dur.as_secs_f64() / 60.0 / 60.0 / 24.0;
        format!("{days:.1}{}", if long { " days" } else { "d" })
    } else if dur.as_secs() > 60 * 60 {
        let hrs = dur.as_secs_f64() / 60.0 / 60.0;
        format!("{hrs:.1}{}", if long { " hours" } else { "h" })
    } else if dur.as_secs() > 60 {
        let mins = dur.as_secs_f64() / 60.0;
        format!("{mins:.1}{}", if long { " minutes" } else { "m" })
    } else if dur.as_secs() > 0 {
        let secs = dur.as_secs_f64();
        format!("{secs:.3}{}", if long { " seconds" } else { "s" })
    } else {
        let ms = dur.as_millis_f64();
        format!("{ms:.3}{}", if long { " milliseconds" } else { "ms" })
    }
}

/* Challenges */

fn default_false() -> bool {
    false
}

fn default_empty_string() -> String {
    String::new()
}

fn default_preferred_auth_method() -> String {
    "message".to_owned()
}

#[derive(Deserialize)]
struct ChallengeStartData {
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
async fn challenge_start(
    state: &State<ServerState>,
    data: Json<ChallengeStartData>,
    ip: IpAddr,
    cfip: CloudflareIPGuard,
) -> ClientApiResult<ChallengeStartResponse> {
    if data.account_id <= 0 || data.user_id <= 0 || !(1usize..=16usize).contains(&data.username.trim().len())
    {
        return Err(ApiError::bad_request("invalid account data"));
    }

    let mut state = state.state_write().await;

    let user_ip = check_ip(ip, &cfip, state.config.cloudflare_protection)?;

    if !state.rate_limiter.can_start_challenge(user_ip, data.account_id) {
        warn!(
            "[{} @ {user_ip}] disallowing challenge start, rate limit exceeded",
            data.account_id
        );
        return Err(ApiError::too_many_requests("rate limit exceeded"));
    }

    state
        .rate_limiter
        .record_challenge_start(user_ip, data.account_id);

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
        ident: state.server_ident.clone(),
    }))
}

#[post("/challenge/restart", data = "<data>")]
async fn challenge_restart(
    state: &State<ServerState>,
    data: Json<ChallengeStartData>,
    ip: IpAddr,
    cfip: CloudflareIPGuard,
) -> ClientApiResult<ChallengeStartResponse> {
    challenge_start(state, data, ip, cfip).await
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
    state: &State<ServerState>,
    data: Json<ChallengeVerifyData>,
    ip: IpAddr,
    cfip: CloudflareIPGuard,
) -> ClientApiResult<ChallengeVerifyResponse> {
    let mut state = state.state_write().await;
    let user_ip = check_ip(ip, &cfip, state.config.cloudflare_protection)?;

    if !state.rate_limiter.can_verify_poll(user_ip, data.account_id) {
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
            state.rate_limiter.record_challenge_fail(user_ip, data.account_id);
            warn!(
                "[{} @ {user_ip}] attempting to verify inexisting challenge",
                data.account_id
            );

            return Err(ApiError::bad_request(
                "no auth challenge exists for this challenge ID, try again",
            ));
        }

        Err(ChallengeValidationError::WrongAccount) => {
            state.rate_limiter.record_challenge_fail(user_ip, data.account_id);
            warn!(
                "[{} @ {user_ip}] attempting to verify challenge for the wrong account",
                data.account_id
            );

            return Err(ApiError::bad_request(
                "challenge was started for a different account",
            ));
        }

        Err(ChallengeValidationError::WrongSolution) => {
            state.rate_limiter.record_challenge_fail(user_ip, data.account_id);
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

    state
        .rate_limiter
        .record_challenge_success(user_ip, data.account_id);

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

    let token = state.generate_authtoken(&challenge);

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
    state: &State<ServerState>,
    data: Json<ChallengeVerifyData>,
    ip: IpAddr,
    cfip: CloudflareIPGuard,
) -> ClientApiResult<ChallengeVerifyResponse> {
    challenge_verify(state, data, ip, cfip).await
}

/* Validation */

#[derive(Serialize)]
pub struct ValidationResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
}

#[derive(Serialize)]
pub struct StrongValidationResponse {
    pub valid: bool,
    pub valid_weak: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

#[get("/validation/check?<account_id>&<authtoken>")]
pub async fn validation_check(
    state: &State<ServerState>,
    account_id: i32,
    authtoken: &str,
    ip: IpAddr,
    cfip: CloudflareIPGuard,
) -> ApiResult<Json<ValidationResponse>> {
    let state = state.state_read().await;

    let user_ip = check_ip(ip, &cfip, state.config.cloudflare_protection)?;

    if !state.rate_limiter.can_validate(user_ip) {
        warn!("[{user_ip}] disallowing token validation, rate limit exceeded");

        return Err(ApiError::too_many_requests("rate limit exceeded"));
    }

    let result = state.validate_authtoken(authtoken);

    Ok(match result {
        Ok(data) if data.account_id == account_id => {
            debug!(
                "[{user_ip}] (Weak) token for {} ({account_id}) validated",
                data.username
            );

            Json(ValidationResponse {
                valid: true,
                cause: None,
            })
        }

        Ok(data) => {
            debug!(
                "[{user_ip}] (Weak) token for {account_id} not valid, reason: mismatched account ID (token was for {})",
                data.account_id
            );

            Json(ValidationResponse {
                valid: false,
                cause: Some(format!(
                    "token was not generated for this account (account ID {}, but expected {})",
                    data.account_id, account_id
                )),
            })
        }

        Err(err) => {
            debug!("[{user_ip}] (Weak) token for {account_id} not valid, reason: {err:?}");

            Json(ValidationResponse {
                valid: false,
                cause: Some(format!("validation failure: {err}")),
            })
        }
    })
}

#[get("/validation/check_strong?<account_id>&<user_id>&<username>&<authtoken>")]
pub async fn validation_check_strong(
    state: &State<ServerState>,
    account_id: i32,
    user_id: Option<i32>,
    username: Option<&str>,
    authtoken: &str,
    ip: IpAddr,
    cfip: CloudflareIPGuard,
) -> ApiResult<Json<StrongValidationResponse>> {
    let state = state.state_read().await;

    let user_ip = check_ip(ip, &cfip, state.config.cloudflare_protection)?;

    if !state.rate_limiter.can_validate(user_ip) {
        warn!("[{user_ip}] disallowing token validation, rate limit exceeded");

        return Err(ApiError::too_many_requests("rate limit exceeded"));
    }

    let result = state.validate_authtoken(authtoken);

    Ok(match result {
        Ok(data) => {
            let _fail = |msg| StrongValidationResponse {
                valid: false,
                valid_weak: false,
                cause: Some(msg),
                username: None,
            };

            let _fail_strong = || StrongValidationResponse {
                valid: false,
                valid_weak: true,
                cause: None,
                username: Some(data.username.clone()),
            };

            let username = username.unwrap_or_default().trim();

            if account_id != data.account_id {
                debug!(
                    "[{user_ip}] (Strong) token for {account_id} not valid, reason: mismatched account ID (token was for {})",
                    data.account_id
                );

                Json(_fail(format!(
                    "token was not generated for this account (account ID {}, but expected {})",
                    data.account_id, account_id
                )))
            } else if user_id.is_some_and(|x| x != data.user_id) {
                debug!(
                    "[{user_ip}] (Strong) token for {account_id} not valid, reason: mismatched user ID (token was for {})",
                    data.user_id
                );

                Json(_fail(format!(
                    "token was not generated for this account (user ID {}, but expected {})",
                    data.account_id, account_id
                )))
            } else if !username.eq_ignore_ascii_case(data.username.trim()) {
                debug!(
                    "[{user_ip}] (Strong) token for {account_id} weakly validated, reason: mismatched username (in token: '{}', from user: '{}')",
                    data.username, username
                );

                Json(_fail_strong())
            } else {
                debug!(
                    "[{user_ip}] (Strong) token for {} ({account_id}) strongly validated",
                    data.username
                );

                Json(StrongValidationResponse {
                    valid: true,
                    valid_weak: true,
                    cause: None,
                    username: Some(data.username.clone()),
                })
            }
        }

        Err(err) => Json(StrongValidationResponse {
            valid: false,
            valid_weak: false,
            cause: Some(format!("validation failure: {err}")),
            username: None,
        }),
    })
}

#[get("/")]
pub async fn index() -> &'static str {
    "There is nothing interesting here. Not yet, at least."
}

pub fn build_routes() -> Vec<Route> {
    routes![
        status,
        challenge_start,
        challenge_restart,
        challenge_verify,
        challenge_verify_poll,
        validation_check,
        validation_check_strong
    ]
}
