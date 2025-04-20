use std::net::IpAddr;

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
    // TODO: rate limit checks

    let mut state = state.state_write().await;

    let _user_ip = check_ip(ip, &cfip, state.config.cloudflare_protection)?;

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
            return Err(ApiError::internal_server_error(
                "no node is currently available to process this auth request",
            ));
        }
    };

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
    let _user_ip = check_ip(ip, &cfip, state.config.cloudflare_protection)?;

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
            return Err(ApiError::bad_request(
                "no auth challenge exists for this IP address",
            ));
        }

        Err(ChallengeValidationError::WrongAccount) => {
            return Err(ApiError::bad_request(
                "challenge was started for a different account, if you are using a VPN please turn it off of try again in a minute",
            ));
        }

        Err(ChallengeValidationError::WrongSolution) => {
            return Err(ApiError::bad_request("challenge solution is incorrect"));
        }
    };

    // the challenge was verified! delete it and generate the authtoken
    let challenge = state.erase_challenge(data.challenge_id);
    assert!(challenge.is_some(), "challenge should exist after being verified");

    let challenge = challenge.unwrap();

    // if we wanted to force strong integrity but failed, return an error
    if challenge.force_strong && !strong {
        return Err(ApiError::bad_request(
            "username validation failed, please try to refresh login in GD account settings",
        ));
    }

    let token = state.generate_authtoken(&challenge);

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
) -> Json<ValidationResponse> {
    let state = state.state_read().await;

    let result = state.validate_authtoken(authtoken);

    match result {
        Ok(data) if data.account_id == account_id => Json(ValidationResponse {
            valid: true,
            cause: None,
        }),

        Ok(data) => Json(ValidationResponse {
            valid: false,
            cause: Some(format!(
                "token was not generated for this account (account ID {}, but expected {})",
                data.account_id, account_id
            )),
        }),

        Err(err) => Json(ValidationResponse {
            valid: false,
            cause: Some(format!("validation failure: {err}")),
        }),
    }
}

#[get("/validation/check_strong?<account_id>&<user_id>&<username>&<authtoken>")]
pub async fn validation_check_strong(
    state: &State<ServerState>,
    account_id: i32,
    user_id: Option<i32>,
    username: Option<&str>,
    authtoken: &str,
) -> Json<StrongValidationResponse> {
    let state = state.state_read().await;

    let result = state.validate_authtoken(authtoken);

    match result {
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

            if account_id != data.account_id {
                Json(_fail(format!(
                    "token was not generated for this account (account ID {}, but expected {})",
                    data.account_id, account_id
                )))
            } else if user_id.is_some_and(|x| x != data.user_id) {
                Json(_fail(format!(
                    "token was not generated for this account (user ID {}, but expected {})",
                    data.account_id, account_id
                )))
            } else if !username
                .unwrap_or_default()
                .trim()
                .eq_ignore_ascii_case(data.username.trim())
            {
                Json(_fail_strong())
            } else {
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
    }
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
