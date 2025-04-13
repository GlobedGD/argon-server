use std::net::IpAddr;

use rocket::{Route, State, get, post, routes, serde::json::Json};
use serde::{Deserialize, Serialize};

use crate::{
    api_error::{ApiError, ApiResult},
    routes_util::*,
    state::ServerState,
};

#[derive(Serialize)]
pub struct StatusResponse {
    pub active: bool,
    pub total_nodes: usize,
    pub active_nodes: usize,
}

#[get("/status")]
pub async fn status(state: &State<ServerState>) -> Json<StatusResponse> {
    let state = state.state_read().await;

    Json(StatusResponse {
        total_nodes: state.node_count,
        active_nodes: state.active_node_count,
        active: state.active_node_count > 0,
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
    #[serde(rename = "reqMod", default = "default_empty_string")]
    pub req_mod: String,
    #[serde(default = "default_preferred_auth_method")]
    pub preferred: String,
}

#[derive(Serialize)]
pub struct ChallengeStartResponse {
    pub method: String,
    pub id: i32,
    pub challenge: i32,
}

#[post("/challenge/start", data = "<data>")]
pub async fn challenge_start(
    state: &State<ServerState>,
    data: Json<ChallengeStartData>,
    ip: IpAddr,
    cfip: CloudflareIPGuard,
) -> ClientApiResult<ChallengeStartResponse> {
    // TODO: rate limit checks

    let mut state = state.state_write().await;

    let user_ip = check_ip(ip, &cfip, state.config.cloudflare_protection)?;

    // Currently, only message auth is supported
    let auth_method = "message";

    let challenge = match state.create_challenge(
        data.account_id,
        data.user_id,
        data.username.clone(),
        user_ip,
        true,
    ) {
        Ok(c) => c,
        Err(err) => return Err(ApiError::bad_request(err.to_string())),
    };

    Ok(GenericResponse::make(ChallengeStartResponse {
        challenge,
        method: auth_method.to_owned(),
        id: state.config.account_id,
    }))
}

#[post("/challenge/restart", data = "<data>")]
pub async fn challenge_restart(
    state: &State<ServerState>,
    data: Json<ChallengeStartData>,
    ip: IpAddr,
    cfip: CloudflareIPGuard,
) -> ClientApiResult<ChallengeStartResponse> {
    {
        let mut state = state.state_write().await;
        let user_ip = check_ip(ip, &cfip, state.config.cloudflare_protection)?;

        state.erase_challenge(user_ip);
    }

    challenge_start(state, data, ip, cfip).await
}

#[derive(Deserialize)]
pub struct ChallengeVerifyData {
    solution: String,
}

#[derive(Serialize)]
pub struct ChallengeVerifyResponse {
    verified: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    authtoken: Option<String>,

    #[serde(rename = "pollAfter", skip_serializing_if = "Option::is_none")]
    poll_after: Option<u32>,
}

// #[post("/challenge/verify", data = "<data>")]
// pub async fn challenge_verify(
//     state: &State<ServerState>,
//     data: Json<ChallengeVerifyData>,
//     ip: IpAddr,
//     cfip: CloudflareIPGuard,
// ) -> ClientApiResult<ChallengeVerifyResponse> {
//     let mut state = state.state_write().await;
//     let user_ip = check_ip(ip, &cfip, state.config.cloudflare_protection)?;

//     state.
// }

/* Validation */

#[derive(Serialize)]
pub struct ValidationResponse {
    pub valid: bool,
}

#[get("/validation/check?<account_id>&<authtoken>")]
pub async fn validation_check(
    state: &State<ServerState>,
    account_id: i32,
    authtoken: &str,
) -> Json<ValidationResponse> {
    let state = state.state_read().await;

    Json(ValidationResponse { valid: false })
}

pub fn build_routes() -> Vec<Route> {
    routes![status]
}
