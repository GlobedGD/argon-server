use std::time::{Duration, Instant};

use axum::{Json, extract::State};
use parking_lot::Mutex;
use serde::Serialize;

use crate::{routes::util::responders::Cache, state::AppState};

use super::{ApiResult, error::ErrorBody};

#[derive(Clone, Serialize, utoipa::ToSchema)]
pub struct NodeInfo {
    id: u64,
    success_rate_1m: f64,
    success_rate_10m: f64,
    challenges_verified: u32,
}

#[derive(Clone, Serialize, utoipa::ToSchema)]
pub struct StatusResponse {
    /// `ok` if all nodes are healthy, `degraded` otherwise
    status: String,
    nodes: Vec<NodeInfo>,
}

#[derive(Clone)]
struct CachedResponse {
    response: StatusResponse,
    cached_at: Instant,
}

const CACHE_DURATION: Duration = Duration::from_secs(30);
static CACHED_RESPONSE: Mutex<Option<CachedResponse>> = Mutex::new(None);

fn get_cached_response() -> Option<StatusResponse> {
    let cached = CACHED_RESPONSE.lock();
    if let Some(cached_response) = &*cached
        && cached_response.cached_at.elapsed() < CACHE_DURATION
    {
        return Some(cached_response.response.clone());
    }

    None
}

/// Checks whether the server is up and returns the state of all nodes
#[utoipa::path(
    get,
    path = "/v2/status",
    tag = "misc",
    responses(
        (status = 200, body = StatusResponse),
        (status = 500, body = ErrorBody),
    ),
)]
pub async fn status(State(state): State<AppState>) -> ApiResult<Cache<Json<StatusResponse>>> {
    if let Some(cached) = get_cached_response() {
        return Ok(Cache::new(CACHE_DURATION, Json(cached)));
    }

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

    let response = StatusResponse {
        status: status.to_owned(),
        nodes: nodes.clone(),
    };
    CACHED_RESPONSE.lock().replace(CachedResponse {
        response: response.clone(),
        cached_at: Instant::now(),
    });

    Ok(Cache::new(CACHE_DURATION, Json(response)))
}
