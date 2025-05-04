use std::sync::Arc;

use rocket::{State, get, serde::json::Json};
use serde::Serialize;

use super::api_error::{ApiError, ApiResult};
use crate::health_state::ServerHealthState;

#[derive(Serialize)]
pub struct StatusResponse {
    pub active: bool,
    pub total_nodes: usize,
    pub active_nodes: usize,
    pub ident: String,
}

#[get("/status?<errorifdead>")]
pub async fn status(
    health_state: &State<Arc<ServerHealthState>>,
    errorifdead: Option<i32>,
) -> ApiResult<Json<StatusResponse>> {
    // if errorifdead is set and there are no active nodes, send an error instead
    if errorifdead.unwrap_or(0) != 0 && !health_state.is_active() {
        return Err(ApiError::not_acceptable(""));
    }

    Ok(Json(StatusResponse {
        total_nodes: health_state.node_count(),
        active_nodes: health_state.active_node_count(),
        active: health_state.is_active(),
        ident: health_state.ident.clone(),
    }))
}
