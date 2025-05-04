use std::sync::Arc;

use rocket::{State, post};

use super::api_error::{ApiError, ApiResult};
use crate::api_token_manager::ApiTokenManager;
use crate::database::ArgonDb;
use crate::state::ServerState;

#[cfg(debug_assertions)]
#[post("/admin/create-token?<name>&<owner>&<description>&<perday>&<perhour>")]
pub async fn create_token(
    db: ArgonDb,
    token_manager: &State<Arc<ApiTokenManager>>,
    name: &str,
    owner: &str,
    description: &str,
    perday: i32,
    perhour: i32,
) -> ApiResult<String> {
    use crate::database::NewApiToken;

    token_manager
        .generate_token(
            &db,
            NewApiToken {
                name,
                owner,
                description,
                validations_per_day: perday,
                validations_per_hour: perhour,
            },
        )
        .await
        .map_err(|e| ApiError::internal_server_error(e.to_string()))
}

#[cfg(not(debug_assertions))]
#[post("/admin/create-token")]
async fn create_token() -> &'static str {
    "endpoint disabled in release builds"
}

#[post("/admin/login", data = "<data>")]
pub async fn login(state: &State<ServerState>, data: String) -> ApiResult<()> {
    if state.state_read().await.config.secret_key == data {
        Ok(())
    } else {
        Err(ApiError::unauthorized("invalid credentials"))
    }
}
