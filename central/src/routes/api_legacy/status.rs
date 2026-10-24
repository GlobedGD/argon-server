use axum::{Json, extract::State};
use serde::Serialize;

use crate::{routes::api_legacy::LegacyApiResult, state::AppState};

#[derive(Serialize)]
pub struct StatusResponse {
    active: bool,
    total_nodes: u32,
    active_nodes: u32,
    ident: String,
}

pub async fn status(State(state): State<AppState>) -> LegacyApiResult<Json<StatusResponse>> {
    let node_count = state.node_manager.get_nodes().await.len();

    Ok(Json(StatusResponse {
        active: node_count > 0,
        total_nodes: node_count as u32,
        active_nodes: node_count as u32,
        ident: state.challenge_controller.get_legacy_ident().unwrap().to_owned(),
    }))
}
