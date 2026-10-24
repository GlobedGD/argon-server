use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State},
};
use serde::{Deserialize, Serialize};

use crate::{
    routes::api_legacy::{LegacyApiError, LegacyApiResult},
    user::UserManager,
};

#[derive(Deserialize)]
pub struct CheckDataQuery {
    account_id: i32,
    authtoken: String,
}

#[derive(Serialize)]
pub struct CheckResponse {
    valid: bool,
    cause: Option<String>,
}

async fn check_inner(token: &str, account_id: i32, user_manager: &UserManager) -> CheckResponse {
    let result = match user_manager.validate_access_token(token).await {
        Ok(data) if data.account_id() == account_id => Ok(data.account_data()),
        Ok(_) => Err(LegacyApiError::IdentityMismatch),
        Err(e) => Err(e.into()),
    };

    CheckResponse {
        valid: result.is_ok(),
        cause: result.err().map(|e| e.to_string()),
    }
}

async fn check_strong_inner(
    token: &str,
    account_id: i32,
    user_id: Option<i32>,
    username: Option<String>,
    user_manager: &UserManager,
) -> CheckStrongResponse {
    let result = match user_manager.validate_access_token(token).await {
        Ok(data) => {
            if data.account_id() != account_id {
                Err(LegacyApiError::IdentityMismatch)
            } else {
                let strong = user_id.is_none_or(|id| data.user_id() == id)
                    && username.is_some_and(|name| names_equal(data.username(), &name));

                Ok((data.account_data(), strong))
            }
        }
        Err(e) => Err(e.into()),
    };

    match result {
        Ok((data, true)) => CheckStrongResponse {
            valid: true,
            valid_weak: true,
            cause: None,
            username: Some(data.username),
        },

        Ok((data, false)) => CheckStrongResponse {
            valid: false,
            valid_weak: true,
            cause: None,
            username: Some(data.username),
        },

        Err(e) => CheckStrongResponse {
            valid: false,
            valid_weak: false,
            cause: Some(e.to_string()),
            username: None,
        },
    }
}

pub async fn check(
    State(user_manager): State<Arc<UserManager>>,
    Query(data): Query<CheckDataQuery>,
) -> LegacyApiResult<Json<CheckResponse>> {
    let result = check_inner(&data.authtoken, data.account_id, &user_manager).await;
    Ok(Json(result))
}

#[derive(Deserialize)]
pub struct RequestedUser {
    id: i32,
    token: String,
}

#[derive(Deserialize)]
pub struct CheckManyData {
    users: Vec<RequestedUser>,
}

#[derive(Serialize)]
pub struct CheckResponseId {
    id: i32,
    #[serde(flatten)]
    response: CheckResponse,
}

#[derive(Serialize)]
pub struct CheckManyResponse {
    users: Vec<CheckResponseId>,
}

pub async fn check_many(
    State(user_manager): State<Arc<UserManager>>,
    Json(data): Json<CheckManyData>,
) -> LegacyApiResult<Json<CheckManyResponse>> {
    let mut out = Vec::new();

    for user in data.users {
        let response = check_inner(&user.token, user.id, &user_manager).await;
        out.push(CheckResponseId {
            id: user.id,
            response,
        });
    }

    Ok(Json(CheckManyResponse { users: out }))
}

#[derive(Deserialize)]
pub struct CheckStrongQuery {
    account_id: i32,
    user_id: Option<i32>,
    username: Option<String>,
    authtoken: String,
}

#[derive(Serialize)]
pub struct CheckStrongResponse {
    valid: bool,
    valid_weak: bool,
    cause: Option<String>,
    username: Option<String>,
}

pub async fn check_strong(
    State(user_manager): State<Arc<UserManager>>,
    Query(data): Query<CheckStrongQuery>,
) -> LegacyApiResult<Json<CheckStrongResponse>> {
    let result =
        check_strong_inner(&data.authtoken, data.account_id, data.user_id, data.username, &user_manager)
            .await;

    Ok(Json(result))
}

#[derive(Deserialize)]
pub struct RequestedStrongUser {
    id: i32,
    token: String,
    user_id: Option<i32>,
    name: Option<String>,
}

#[derive(Deserialize)]
pub struct CheckStrongManyData {
    users: Vec<RequestedStrongUser>,
}

#[derive(Serialize)]
pub struct CheckStrongResponseId {
    id: i32,
    #[serde(flatten)]
    response: CheckStrongResponse,
}

#[derive(Serialize)]
pub struct CheckStrongManyResponse {
    users: Vec<CheckStrongResponseId>,
}

pub async fn check_strong_many(
    State(user_manager): State<Arc<UserManager>>,
    Json(data): Json<CheckStrongManyData>,
) -> LegacyApiResult<Json<CheckStrongManyResponse>> {
    let mut out = Vec::new();

    for user in data.users {
        let response = check_strong_inner(&user.token, user.id, user.user_id, user.name, &user_manager).await;

        out.push(CheckStrongResponseId {
            id: user.id,
            response,
        });
    }

    Ok(Json(CheckStrongManyResponse { users: out }))
}

#[derive(Serialize)]
pub struct CheckDataResponse {
    id: i32,
    valid: bool,
    user_id: Option<i32>,
    username: Option<String>,
    cause: Option<String>,
}

#[derive(Serialize)]
pub struct CheckDataManyResponse {
    users: Vec<CheckDataResponse>,
}

pub async fn check_data_many(
    State(user_manager): State<Arc<UserManager>>,
    Json(data): Json<CheckManyData>,
) -> LegacyApiResult<Json<CheckDataManyResponse>> {
    let mut out = Vec::new();

    for user in data.users {
        let result = match user_manager.validate_access_token(&user.token).await {
            Ok(data) if data.account_id() == user.id => Ok(data.account_data()),
            Ok(_) => Err(LegacyApiError::IdentityMismatch),
            Err(e) => Err(e.into()),
        };

        let response = match result {
            Ok(data) => CheckDataResponse {
                id: user.id,
                valid: true,
                user_id: Some(data.user_id),
                username: Some(data.username),
                cause: None,
            },
            Err(e) => CheckDataResponse {
                id: user.id,
                valid: false,
                user_id: None,
                username: None,
                cause: Some(e.to_string()),
            },
        };

        out.push(response);
    }

    Ok(Json(CheckDataManyResponse { users: out }))
}

fn names_equal(mut name1: &str, mut name2: &str) -> bool {
    name1 = name1.trim();
    name2 = name2.trim();
    name1.eq_ignore_ascii_case(name2)
}
