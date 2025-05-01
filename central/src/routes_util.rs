use anyhow::anyhow;
use argon_shared::logger::*;
use rocket::{
    Request,
    http::Status,
    request::{FromRequest, Outcome},
};
use std::{net::IpAddr, time::Duration};

use crate::{
    api_error::{ApiError, ApiResult},
    ip_blocker::IpBlocker,
};

// client ip address
pub struct CloudflareIPGuard(pub Option<IpAddr>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for CloudflareIPGuard {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.headers().get_one("CF-Connecting-IP") {
            Some(x) => match x.parse::<IpAddr>() {
                Ok(a) => Outcome::Success(CloudflareIPGuard(Some(a))),
                Err(_) => Outcome::Error((
                    Status::Unauthorized,
                    "failed to parse the IP header from Cloudflare",
                )),
            },
            None => Outcome::Success(CloudflareIPGuard(None)),
        }
    }
}

pub fn check_ip(ip: IpAddr, cfip: &CloudflareIPGuard, cloudflare: bool) -> ApiResult<IpAddr> {
    let user_ip: anyhow::Result<IpAddr> = if cloudflare && !cfg!(debug_assertions) {
        // verify if the actual peer is cloudflare
        if !IpBlocker::instance().is_allowed(&ip) {
            warn!("blocking unknown non-cloudflare address: {}", ip);
            return Err(ApiError::forbidden("access is denied from this IP address"));
        }

        cfip.0
            .ok_or(anyhow!("failed to parse the IP header from Cloudflare"))
    } else {
        Ok(cfip.0.unwrap_or(ip))
    };

    match user_ip {
        Ok(x) => Ok(x),
        Err(err) => Err(ApiError::bad_request(err.to_string())),
    }
}

pub fn format_duration(dur: &Duration, long: bool) -> String {
    if dur.as_secs() > 60 * 60 * 24 {
        let days = dur.as_secs_f64() / 60.0 / 60.0 / 24.0;
        format!("{days:.1}{}", if long { " days" } else { "d" })
    } else if dur.as_secs() > 60 * 60 {
        let hrs = dur.as_secs_f64() / 60.0 / 60.0;
        format!("{hrs:.1}{}", if long { " hours" } else { "h" })
    } else if dur.as_secs() > 60 {
        let mins = dur.as_secs_f64() / 60.0;
        format!("{mins:.1}{}", if long { " minutes" } else { "m" })
    } else if dur.as_secs() > 0 {
        let secs = dur.as_secs_f64();
        format!("{secs:.3}{}", if long { " seconds" } else { "s" })
    } else {
        let ms = dur.as_millis_f64();
        format!("{ms:.3}{}", if long { " milliseconds" } else { "ms" })
    }
}

pub fn default_false() -> bool {
    false
}

pub fn default_empty_string() -> String {
    String::new()
}
