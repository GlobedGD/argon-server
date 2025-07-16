use std::{fmt::Debug, net::IpAddr, sync::Arc};

use argon_shared::logger::*;
use parking_lot::Mutex as SyncMutex;
use rocket::{State, get, post, serde::json::Json};
use serde::{Deserialize, Serialize};

use crate::{
    api_token_manager::{ApiTokenManager, TokenFetchError},
    database::ArgonDb,
    rate_limiter::RateLimiter,
    routes::api_error::{ApiError, ApiResult},
    token_issuer::TokenIssuer,
};

use super::routes_util::{ApiTokenGuard, CloudflareIPGuard};

type ServerApiResult<T> = ApiResult<T, false>;

pub const MAX_USERS_IN_REQUEST: usize = 50;

#[derive(Serialize, Debug, Clone)]
pub struct WithId<T: Serialize + Debug + Clone> {
    pub id: i32,
    #[serde(flatten)]
    pub value: T,
}

#[derive(Serialize, Debug, Clone)]
pub struct ValidationResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct UserAuthData {
    #[serde(rename = "id")]
    pub account_id: i32,
    pub token: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ValidationManyData {
    pub users: Vec<UserAuthData>,
}

#[derive(Serialize, Debug, Clone)]
pub struct ValidationManyResponse {
    pub users: Vec<WithId<ValidationResponse>>,
}

#[derive(Serialize, Debug, Clone)]
pub struct StrongValidationResponse {
    pub valid: bool,
    pub valid_weak: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct StrongUserAuthData {
    #[serde(rename = "id")]
    pub account_id: i32,
    pub user_id: Option<i32>,
    pub name: Option<String>,
    pub token: String,
}

#[derive(Deserialize, Debug)]
pub struct StrongValidationManyData {
    pub users: Vec<StrongUserAuthData>,
}

#[derive(Serialize, Debug)]
pub struct StrongValidationManyResponse {
    pub users: Vec<WithId<StrongValidationResponse>>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct CheckDataManyData {
    pub users: Vec<UserAuthData>,
}

// god this name sucks
#[derive(Serialize, Debug, Clone, Default)]
pub struct UserCheckResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
    pub user_id: Option<i32>,
    pub username: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct CheckDataManyResponse {
    pub users: Vec<WithId<UserCheckResponse>>,
}

async fn should_allow(
    limiter: &SyncMutex<RateLimiter>,
    token_manager: &ApiTokenManager,
    db: &ArgonDb,
    user_ip: IpAddr,
    api_token: ApiTokenGuard,
    count: usize,
) -> Result<bool, TokenFetchError> {
    match api_token.0 {
        None => Ok(limiter.lock().validate_tokens(count, user_ip)),

        Some(token) => token_manager.validate_tokens(&token, db, count).await,
    }
}

pub fn validate_one_weak(
    issuer: &TokenIssuer,
    user_ip: IpAddr,
    account_id: i32,
    token: &str,
) -> ValidationResponse {
    let result = issuer.validate(token);

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

#[allow(clippy::too_many_arguments)]
#[get("/validation/check?<account_id>&<authtoken>")]
pub async fn validation_check(
    issuer: &State<Arc<TokenIssuer>>,
    rate_limiter: &State<Arc<SyncMutex<RateLimiter>>>,
    token_manager: &State<Arc<ApiTokenManager>>,
    db: ArgonDb,
    account_id: i32,
    authtoken: &str,
    ip: CloudflareIPGuard,
    api_token: ApiTokenGuard,
) -> ServerApiResult<Json<ValidationResponse>> {
    let user_ip = ip.0;

    if !should_allow(rate_limiter, token_manager, &db, user_ip, api_token, 1).await? {
        warn!("[{user_ip}] disallowing token validation, rate limit exceeded");

        return Err(ApiError::too_many_requests("rate limit exceeded"));
    }

    Ok(Json(validate_one_weak(issuer, user_ip, account_id, authtoken)))
}

#[post("/validation/check-many", data = "<data>")]
pub async fn validation_check_many(
    issuer: &State<Arc<TokenIssuer>>,
    limiter: &State<Arc<SyncMutex<RateLimiter>>>,
    token_manager: &State<Arc<ApiTokenManager>>,
    db: ArgonDb,
    ip: CloudflareIPGuard,
    api_token: ApiTokenGuard,
    data: Json<ValidationManyData>,
) -> ServerApiResult<Json<ValidationManyResponse>> {
    let user_ip = ip.0;

    if data.users.len() > MAX_USERS_IN_REQUEST {
        debug!(
            "[{user_ip}] (Weak) tried validating {} tokens, rejecting",
            data.users.len()
        );
        return Err(ApiError::bad_request("too many users in the request"));
    }

    debug!("[{user_ip}] (Weak) validating {} tokens", data.users.len());

    if !should_allow(limiter, token_manager, &db, user_ip, api_token, data.users.len()).await? {
        warn!("[{user_ip}] disallowing token validation, rate limit exceeded");

        return Err(ApiError::too_many_requests("rate limit exceeded"));
    }

    let mut response = ValidationManyResponse {
        users: Vec::with_capacity(data.users.len()),
    };

    for account in &data.users {
        let res = validate_one_weak(issuer, user_ip, account.account_id, &account.token);

        response.users.push(WithId {
            id: account.account_id,
            value: res,
        });
    }

    Ok(Json(response))
}

pub fn validate_one_strong(
    issuer: &TokenIssuer,
    user_ip: IpAddr,
    account_id: i32,
    user_id: Option<i32>,
    username: Option<&str>,
    token: &str,
) -> StrongValidationResponse {
    let result = issuer.validate(token);

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

#[allow(clippy::too_many_arguments)]
#[get("/validation/check-strong?<account_id>&<user_id>&<username>&<authtoken>")]
pub async fn validation_check_strong(
    issuer: &State<Arc<TokenIssuer>>,
    limiter: &State<Arc<SyncMutex<RateLimiter>>>,
    token_manager: &State<Arc<ApiTokenManager>>,
    db: ArgonDb,
    account_id: i32,
    user_id: Option<i32>,
    username: Option<&str>,
    authtoken: &str,
    ip: CloudflareIPGuard,
    api_token: ApiTokenGuard,
) -> ServerApiResult<Json<StrongValidationResponse>> {
    let user_ip = ip.0;

    if !should_allow(limiter, token_manager, &db, user_ip, api_token, 1).await? {
        warn!("[{user_ip}] disallowing token validation, rate limit exceeded");

        return Err(ApiError::too_many_requests("rate limit exceeded"));
    }

    Ok(Json(validate_one_strong(
        issuer, user_ip, account_id, user_id, username, authtoken,
    )))
}

#[allow(clippy::too_many_arguments)]
#[get("/validation/check_strong?<account_id>&<user_id>&<username>&<authtoken>")]
pub async fn validation_check_strong_alias(
    issuer: &State<Arc<TokenIssuer>>,
    limiter: &State<Arc<SyncMutex<RateLimiter>>>,
    token_manager: &State<Arc<ApiTokenManager>>,
    db: ArgonDb,
    account_id: i32,
    user_id: Option<i32>,
    username: Option<&str>,
    authtoken: &str,
    ip: CloudflareIPGuard,
    api_token: ApiTokenGuard,
) -> ServerApiResult<Json<StrongValidationResponse>> {
    validation_check_strong(
        issuer,
        limiter,
        token_manager,
        db,
        account_id,
        user_id,
        username,
        authtoken,
        ip,
        api_token,
    )
    .await
}

#[post("/validation/check-strong-many", data = "<data>")]
pub async fn validation_check_strong_many(
    issuer: &State<Arc<TokenIssuer>>,
    limiter: &State<Arc<SyncMutex<RateLimiter>>>,
    token_manager: &State<Arc<ApiTokenManager>>,
    db: ArgonDb,
    ip: CloudflareIPGuard,
    data: Json<StrongValidationManyData>,
    api_token: ApiTokenGuard,
) -> ServerApiResult<Json<StrongValidationManyResponse>> {
    let user_ip = ip.0;

    if data.users.len() > MAX_USERS_IN_REQUEST {
        debug!(
            "[{user_ip}] (Strong) tried validating {} tokens, rejecting",
            data.users.len()
        );

        return Err(ApiError::bad_request("too many users in the request"));
    }

    debug!("[{user_ip}] (Strong) validating {} tokens", data.users.len());

    if !should_allow(limiter, token_manager, &db, user_ip, api_token, data.users.len()).await? {
        warn!("[{user_ip}] disallowing token validation, rate limit exceeded");

        return Err(ApiError::too_many_requests("rate limit exceeded"));
    }

    let mut response = StrongValidationManyResponse {
        users: Vec::with_capacity(data.users.len()),
    };

    for account in &data.users {
        let res = validate_one_strong(
            issuer,
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

pub fn validate_one_check(
    issuer: &TokenIssuer,
    user_ip: IpAddr,
    account_id: i32,
    token: &str,
) -> UserCheckResponse {
    match issuer.validate(token) {
        Ok(data) => {
            if data.account_id != account_id {
                debug!(
                    "[{user_ip}] (Check) token for {account_id} not valid, reason: mismatched account ID (token was for {})",
                    data.account_id,
                );

                UserCheckResponse {
                    valid: false,
                    cause: Some(format!(
                        "token was not generated for this account (account ID {}, but expected {account_id})",
                        data.account_id
                    )),
                    ..Default::default()
                }
            } else {
                debug!(
                    "[{user_ip}] (Check) token for {} ({}) validated",
                    data.username, data.account_id
                );

                UserCheckResponse {
                    valid: true,
                    cause: None,
                    user_id: Some(data.user_id),
                    username: Some(data.username),
                }
            }
        }

        Err(e) => UserCheckResponse {
            valid: false,
            cause: Some(format!("validation failure: {e}")),
            ..Default::default()
        },
    }
}

#[post("/validation/check-data-many", data = "<data>")]
pub async fn validation_check_data_many(
    issuer: &State<Arc<TokenIssuer>>,
    limiter: &State<Arc<SyncMutex<RateLimiter>>>,
    token_manager: &State<Arc<ApiTokenManager>>,
    db: ArgonDb,
    ip: CloudflareIPGuard,
    data: Json<CheckDataManyData>,
    api_token: ApiTokenGuard,
) -> ServerApiResult<Json<CheckDataManyResponse>> {
    let user_ip = ip.0;

    if data.users.len() > MAX_USERS_IN_REQUEST {
        debug!(
            "[{user_ip}] (Check) tried validating {} tokens, rejecting",
            data.users.len()
        );

        return Err(ApiError::bad_request("too many users in the request"));
    }

    debug!("[{user_ip}] (Check) validating {} tokens", data.users.len());

    if !should_allow(limiter, token_manager, &db, user_ip, api_token, data.users.len()).await? {
        warn!("[{user_ip}] disallowing token validation, rate limit exceeded");

        return Err(ApiError::too_many_requests("rate limit exceeded"));
    }

    let mut response = CheckDataManyResponse {
        users: Vec::with_capacity(data.users.len()),
    };

    for account in &data.users {
        let res = validate_one_check(issuer, user_ip, account.account_id, &account.token);

        response.users.push(WithId {
            id: account.account_id,
            value: res,
        });
    }

    Ok(Json(response))
}
