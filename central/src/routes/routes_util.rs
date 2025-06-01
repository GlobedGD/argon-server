use argon_shared::logger::*;
use rocket::{
    Request,
    http::Status,
    request::{FromRequest, Outcome},
};
use std::{net::IpAddr, sync::Arc, time::Duration};

use crate::ip_blocker::IpBlocker;

// client ip address
pub struct CloudflareIPGuard(pub IpAddr);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for CloudflareIPGuard {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let Some(client_ip) = request.client_ip() else {
            return Outcome::Error((
                Status::InternalServerError,
                "failed to obtain client's IP address",
            ));
        };

        let ip_blocker = request.rocket().state::<Arc<IpBlocker>>().unwrap();

        if !ip_blocker.is_enabled() {
            return Outcome::Success(CloudflareIPGuard(client_ip));
        }

        // if cloudflare protection mode is enabled, check if the request comes from actual cloudflare
        if !ip_blocker.is_allowed(&client_ip) {
            warn!("blocking unknown non-cloudflare address: {client_ip}");
            return Outcome::Error((Status::Forbidden, "access is denied from this IP address"));
        }

        let cf_ip = request
            .headers()
            .get_one("CF-Connecting-IP")
            .and_then(|x| match x.parse::<IpAddr>() {
                Ok(a) => Some(a),
                Err(err) => {
                    warn!("failed to parse CF-Connecting-IP header: {err}");
                    None
                }
            });

        match cf_ip {
            Some(ip) => Outcome::Success(CloudflareIPGuard(ip)),
            None => Outcome::Error((
                Status::InternalServerError,
                "failed to parse cloudflare IP header",
            )),
        }
    }
}

// api token guard
pub struct ApiTokenGuard(pub Option<String>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ApiTokenGuard {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.headers().get_one("Authorization") {
            Some(x) => {
                if !x.starts_with("Bearer ") {
                    return Outcome::Error((
                        Status::Unauthorized,
                        "incorrect format for the API token in the Authorization header",
                    ));
                }

                let token = x.strip_prefix("Bearer ").unwrap().trim();

                Outcome::Success(ApiTokenGuard(Some(token.to_owned())))
            }
            None => Outcome::Success(ApiTokenGuard(None)),
        }
    }
}

pub fn default_false() -> bool {
    false
}

pub fn default_empty_string() -> String {
    String::new()
}
