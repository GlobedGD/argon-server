use std::sync::Arc;

use rocket::{State, get, serde::json::Json};

use super::api_error::{ApiError, ApiResult};
use crate::health_state::{ServerHealthState, ServerStatusResponse};

#[get("/status?<errorifdead>")]
pub async fn status(
    health_state: &State<Arc<ServerHealthState>>,
    errorifdead: Option<i32>,
) -> ApiResult<Json<ServerStatusResponse>, false> {
    // if errorifdead is set and there are no active nodes, send an error instead
    if errorifdead.unwrap_or(0) != 0 && !health_state.is_active() {
        return Err(ApiError::not_acceptable(""));
    }

    Ok(Json(health_state.status()))
}
