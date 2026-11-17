use std::{
    net::{IpAddr, Ipv6Addr},
    num::NonZeroU32,
    sync::Arc,
    time::Duration,
};

use axum::{Router, extract::Request, middleware::Next, response::IntoResponse};
use governor::{DefaultDirectRateLimiter, Quota};

use crate::{
    routes::{api::ApiError, util::extractors::VerifiedIpAddr},
    state::AppState,
    util::{RateLimitOutcome, RateLimiter},
};

pub mod extractors;
pub mod responders;

struct RState {
    limiter: RateLimiter<IpAddr>,
    global_limiter: DefaultDirectRateLimiter,
}

pub fn rate_limited<S>(router: Router<S>, state: AppState, reqs_per_minute: u32, max_burst: u32) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let mut limiter = RateLimiter::new(Duration::from_hours(1), 16384);
    limiter.set_replenish_1_per(Duration::from_mins(1) / reqs_per_minute);
    limiter.set_max_burst(NonZeroU32::new(max_burst).unwrap());

    let global_limiter = governor::RateLimiter::direct(
        Quota::per_second(NonZeroU32::new(200).unwrap()).allow_burst(NonZeroU32::new(10).unwrap()),
    );

    let rstate = Arc::new(RState {
        limiter,
        global_limiter,
    });

    router.layer(axum::middleware::from_fn_with_state(
        state,
        move |VerifiedIpAddr(ip): VerifiedIpAddr, request: Request, next: Next| {
            let rstate = rstate.clone();
            async move {
                // first check the global rate limiter, which limits how many requests from all sources may come to this route
                match rstate.global_limiter.check() {
                    // if that succeeds, check the per-ip limiter
                    Ok(()) => match rstate.limiter.check(to_ip_prefix(ip)) {
                        RateLimitOutcome::Allowed => next.run(request).await,
                        RateLimitOutcome::RateLimited { until } => {
                            ApiError::RateLimited { until }.into_response()
                        }
                    },
                    Err(e) => ApiError::RateLimited {
                        until: e.earliest_possible(),
                    }
                    .into_response(),
                }
            }
        },
    ))
}

fn to_ip_prefix(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(ipv4) => IpAddr::V4(ipv4),
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            let prefix_segments = [segments[0], segments[1], segments[2], segments[3], 0, 0, 0, 0];
            IpAddr::V6(Ipv6Addr::from(prefix_segments))
        }
    }
}
