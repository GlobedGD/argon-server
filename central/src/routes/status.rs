use rocket::{State, get, serde::json::Json};
use serde::Serialize;

use crate::{
    api_error::{ApiError, ApiResult},
    state::ServerState,
};

#[derive(Serialize)]
pub struct StatusResponse {
    pub active: bool,
    pub total_nodes: usize,
    pub active_nodes: usize,
    pub ident: String,
}

#[get("/status?<errorifdead>")]
pub async fn status(state: &State<ServerState>, errorifdead: Option<i32>) -> ApiResult<Json<StatusResponse>> {
    let state = state.state_read().await;

    // if errorifdead is set and there are no active nodes, send an error instead
    if errorifdead.unwrap_or(0) != 0 && state.active_node_count == 0 {
        return Err(ApiError::not_acceptable(""));
    }

    Ok(Json(StatusResponse {
        total_nodes: state.node_count,
        active_nodes: state.active_node_count,
        active: state.active_node_count > 0,
        ident: state.server_ident.clone(),
    }))
}
