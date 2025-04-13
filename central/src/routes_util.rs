use anyhow::anyhow;
use argon_shared::logger::*;
use rocket::{
    Request,
    http::Status,
    request::{FromRequest, Outcome},
};
use std::net::IpAddr;

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
