use std::{net::IpAddr, num::NonZeroU32, sync::Arc, time::Duration};

use anyhow::anyhow;
use axum::{Router, extract::Request, middleware::Next, response::IntoResponse};

use crate::{
    routes::{api::ApiError, util::extractors::VerifiedIpAddr},
    state::AppState,
    util::{RateLimitOutcome, RateLimiter},
};

pub mod extractors;
pub mod responders;

pub fn rate_limited<S>(router: Router<S>, state: AppState, reqs_per_minute: u32, max_burst: u32) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let mut limiter = RateLimiter::<IpAddr>::new(Duration::from_hours(1), 65536);
    limiter.set_replenish_1_per(Duration::from_mins(1) / reqs_per_minute);
    limiter.set_max_burst(NonZeroU32::new(max_burst).unwrap());
    let limiter = Arc::new(limiter);

    router.layer(axum::middleware::from_fn_with_state(
        state,
        move |VerifiedIpAddr(ip): VerifiedIpAddr, request: Request, next: Next| {
            let limiter = limiter.clone();
            async move {
                match limiter.check(ip) {
                    RateLimitOutcome::Allowed => next.run(request).await,
                    RateLimitOutcome::RateLimited { until } => {
                        ApiError::RateLimited { until }.into_response()
                    }
                    e => ApiError::Internal(anyhow!("unexpected rate limiter error: {e:?}")).into_response(),
                }
            }
        },
    ))
}
