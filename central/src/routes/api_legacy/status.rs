use axum::{
    Json,
    extract::{Query, State},
};
use serde::{Deserialize, Serialize};

use crate::{
    routes::api_legacy::{LegacyApiError, LegacyApiResult},
    state::AppState,
};

#[derive(Serialize)]
pub struct StatusResponse {
    active: bool,
    total_nodes: u32,
    active_nodes: u32,
    ident: String,
}

#[derive(Deserialize)]
pub struct StatusQuery {
    #[serde(default)]
    errorifdead: Option<i32>,
}

pub async fn status(
    State(state): State<AppState>,
    Query(query): Query<StatusQuery>,
) -> LegacyApiResult<Json<StatusResponse>> {
    let node_count = state.node_manager.get_nodes().await.len();
    let error_if_dead = query.errorifdead.unwrap_or(0) != 0;

    if node_count == 0 && error_if_dead {
        return Err(LegacyApiError::StatusArgonDown);
    }

    Ok(Json(StatusResponse {
        active: node_count > 0,
        total_nodes: node_count as u32,
        active_nodes: node_count as u32,
        ident: state.challenge_controller.get_legacy_ident().unwrap().to_owned(),
    }))
}
