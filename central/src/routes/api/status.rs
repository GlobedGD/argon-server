use std::time::Duration;

use axum::{Json, extract::State};
use serde::Serialize;

use crate::{routes::util::responders::Cache, state::AppState};

use super::ApiResult;

#[derive(Serialize)]
pub struct NodeInfo {
    id: u64,
    success_rate_1m: f64,
    success_rate_10m: f64,
    challenges_verified: u32,
}

#[derive(Serialize)]
pub struct StatusResponse {
    status: String,
    nodes: Vec<NodeInfo>,
}

pub async fn status(State(state): State<AppState>) -> ApiResult<Cache<Json<StatusResponse>>> {
    let nodes = state
        .node_manager
        .get_nodes()
        .await
        .into_iter()
        .map(|node| NodeInfo {
            id: node.id,
            success_rate_1m: node.success_rate(Duration::from_mins(1)),
            success_rate_10m: node.success_rate(Duration::from_mins(10)),
            challenges_verified: node.challenges_completed(),
        })
        .collect::<Vec<_>>();

    let status = if !nodes.is_empty() && nodes.iter().all(|n| n.success_rate_1m > 0.8) {
        "ok"
    } else {
        "degraded"
    };

    Ok(Cache::new(
        Duration::from_secs(30),
        Json(StatusResponse {
            status: status.to_owned(),
            nodes,
        }),
    ))
}
