use std::net::IpAddr;

use argon_shared::logger::*;
use rocket::{State, get, post, serde::json::Json};
use serde::{Deserialize, Serialize};

use crate::{
    api_error::{ApiError, ApiResult},
    routes_util::*,
    state::{ServerState, ServerStateData},
};

const MAX_USERS_IN_REQUEST: usize = 50;

#[derive(Serialize)]
pub struct WithId<T: Serialize> {
    pub id: i32,
    #[serde(flatten)]
    pub value: T,
}

#[derive(Serialize)]
pub struct ValidationResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
}

#[derive(Deserialize)]
pub struct UserAuthData {
    #[serde(rename = "id")]
    pub account_id: i32,
    pub token: String,
}

#[derive(Deserialize)]
pub struct ValidationManyData {
    pub users: Vec<UserAuthData>,
}

#[derive(Serialize)]
pub struct ValidationManyResponse {
    pub users: Vec<WithId<ValidationResponse>>,
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

#[derive(Deserialize)]
pub struct StrongUserAuthData {
    #[serde(rename = "id")]
    pub account_id: i32,
    pub user_id: Option<i32>,
    pub name: Option<String>,
    pub token: String,
}

#[derive(Deserialize)]
pub struct StrongValidationManyData {
    pub users: Vec<StrongUserAuthData>,
}

#[derive(Serialize)]
pub struct StrongValidationManyResponse {
    pub users: Vec<WithId<StrongValidationResponse>>,
}

fn validate_one_weak(
    state: &ServerStateData,
    user_ip: IpAddr,
    account_id: i32,
    token: &str,
) -> ValidationResponse {
    let result = state.validate_authtoken(token);

    match result {
        Ok(data) if data.account_id == account_id => {
            debug!(
                "[{user_ip}] (Weak) token for {} ({account_id}) validated",
                data.username
            );

            ValidationResponse {
                valid: true,
                cause: None,
            }
        }

        Ok(data) => {
            debug!(
                "[{user_ip}] (Weak) token for {account_id} not valid, reason: mismatched account ID (token was for {})",
                data.account_id
            );

            ValidationResponse {
                valid: false,
                cause: Some(format!(
                    "token was not generated for this account (account ID {}, but expected {})",
                    data.account_id, account_id
                )),
            }
        }

        Err(err) => {
            debug!("[{user_ip}] (Weak) token for {account_id} not valid, reason: {err:?}");

            ValidationResponse {
                valid: false,
                cause: Some(format!("validation failure: {err}")),
            }
        }
    }
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

    Ok(Json(validate_one_weak(&state, user_ip, account_id, authtoken)))
}

#[post("/validation/check-many", data = "<data>")]
pub async fn validation_check_many(
    state: &State<ServerState>,
    ip: IpAddr,
    cfip: CloudflareIPGuard,
    data: Json<ValidationManyData>,
) -> ApiResult<Json<ValidationManyResponse>> {
    let state = state.state_read().await;

    let user_ip = check_ip(ip, &cfip, state.config.cloudflare_protection)?;

    if data.users.len() > MAX_USERS_IN_REQUEST {
        debug!(
            "[{user_ip}] (Weak) tried validating {} tokens, rejecting",
            data.users.len()
        );
        return Err(ApiError::bad_request("too many users in the request"));
    }

    debug!("[{user_ip}] (Weak) validating {} tokens", data.users.len());

    if !state.rate_limiter.can_validate_n(data.users.len(), user_ip) {
        warn!("[{user_ip}] disallowing token validation, rate limit exceeded");

        return Err(ApiError::too_many_requests("rate limit exceeded"));
    }

    let mut response = ValidationManyResponse {
        users: Vec::with_capacity(data.users.len()),
    };

    for account in &data.users {
        let res = validate_one_weak(&state, user_ip, account.account_id, &account.token);

        response.users.push(WithId {
            id: account.account_id,
            value: res,
        });
    }

    Ok(Json(response))
}

fn validate_one_strong(
    state: &ServerStateData,
    user_ip: IpAddr,
    account_id: i32,
    user_id: Option<i32>,
    username: Option<&str>,
    token: &str,
) -> StrongValidationResponse {
    let result = state.validate_authtoken(token);

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

            let username = username.unwrap_or_default().trim();

            if account_id != data.account_id {
                debug!(
                    "[{user_ip}] (Strong) token for {account_id} not valid, reason: mismatched account ID (token was for {})",
                    data.account_id
                );

                _fail(format!(
                    "token was not generated for this account (account ID {}, but expected {})",
                    data.account_id, account_id
                ))
            } else if user_id.is_some_and(|x| x != data.user_id) {
                debug!(
                    "[{user_ip}] (Strong) token for {account_id} not valid, reason: mismatched user ID (token was for {})",
                    data.user_id
                );

                _fail(format!(
                    "token was not generated for this account (user ID {}, but expected {})",
                    data.user_id,
                    user_id.unwrap()
                ))
            } else if !username.eq_ignore_ascii_case(data.username.trim()) {
                debug!(
                    "[{user_ip}] (Strong) token for {account_id} weakly validated, reason: mismatched username (in token: '{}', from user: '{}')",
                    data.username, username
                );

                _fail_strong()
            } else {
                debug!(
                    "[{user_ip}] (Strong) token for {} ({account_id}) strongly validated",
                    data.username
                );

                StrongValidationResponse {
                    valid: true,
                    valid_weak: true,
                    cause: None,
                    username: Some(data.username.clone()),
                }
            }
        }

        Err(err) => StrongValidationResponse {
            valid: false,
            valid_weak: false,
            cause: Some(format!("validation failure: {err}")),
            username: None,
        },
    }
}

#[get("/validation/check-strong?<account_id>&<user_id>&<username>&<authtoken>")]
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

    Ok(Json(validate_one_strong(
        &state, user_ip, account_id, user_id, username, authtoken,
    )))
}

#[get("/validation/check_strong?<account_id>&<user_id>&<username>&<authtoken>")]
pub async fn validation_check_strong_alias(
    state: &State<ServerState>,
    account_id: i32,
    user_id: Option<i32>,
    username: Option<&str>,
    authtoken: &str,
    ip: IpAddr,
    cfip: CloudflareIPGuard,
) -> ApiResult<Json<StrongValidationResponse>> {
    validation_check_strong(state, account_id, user_id, username, authtoken, ip, cfip).await
}

#[post("/validation/check-strong-many", data = "<data>")]
pub async fn validation_check_strong_many(
    state: &State<ServerState>,
    ip: IpAddr,
    cfip: CloudflareIPGuard,
    data: Json<StrongValidationManyData>,
) -> ApiResult<Json<StrongValidationManyResponse>> {
    let state = state.state_read().await;

    let user_ip = check_ip(ip, &cfip, state.config.cloudflare_protection)?;

    if data.users.len() > MAX_USERS_IN_REQUEST {
        debug!(
            "[{user_ip}] (Strong) tried validating {} tokens, rejecting",
            data.users.len()
        );

        return Err(ApiError::bad_request("too many users in the request"));
    }

    debug!("[{user_ip}] (Strong) validating {} tokens", data.users.len());

    if !state.rate_limiter.can_validate_n(data.users.len(), user_ip) {
        warn!("[{user_ip}] disallowing token validation, rate limit exceeded");

        return Err(ApiError::too_many_requests("rate limit exceeded"));
    }

    let mut response = StrongValidationManyResponse {
        users: Vec::with_capacity(data.users.len()),
    };

    for account in &data.users {
        let res = validate_one_strong(
            &state,
            user_ip,
            account.account_id,
            account.user_id,
            account.name.as_deref(),
            &account.token,
        );

        response.users.push(WithId {
            id: account.account_id,
            value: res,
        });
    }

    Ok(Json(response))
}
