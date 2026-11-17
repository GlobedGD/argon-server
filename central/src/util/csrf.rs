use std::time::Duration;

use constant_time_eq::constant_time_eq;
use tower_cookies::{Cookie, Cookies, Key, cookie::SameSite};
use uuid::Uuid;

/// Manager for signed csrf cookies. This should not be used for regular API, only for login.
pub struct CsrfCookieManager {
    key: Key,
    ttl: Duration,
}

impl CsrfCookieManager {
    pub fn new(ttl: Duration) -> Self {
        Self {
            key: Key::generate(),
            ttl,
        }
    }

    pub fn token(&self, cookies: &Cookies) -> String {
        if let Some(c) = cookies.signed(&self.key).get("argon-secure-csrf")
            && self.valid(c.value())
        {
            return c.value().to_owned();
        }

        let now_unix = chrono::Utc::now().timestamp() as u64;
        let random_id = Uuid::new_v4().simple().to_string();

        let token = format!("{}.{}", now_unix, random_id);
        let cookie = Cookie::build(("argon-secure-csrf", token.clone()))
            .path("/")
            .http_only(true)
            .secure(!cfg!(debug_assertions))
            .same_site(SameSite::Strict)
            .max_age(self.ttl.try_into().unwrap())
            .build();

        cookies.signed(&self.key).add(cookie);

        token
    }

    pub fn verify(&self, cookies: &Cookies, form_token: &str) -> bool {
        let Some(c) = cookies.signed(&self.key).get("argon-secure-csrf") else {
            return false;
        };

        constant_time_eq(c.value().as_bytes(), form_token.as_bytes()) && self.valid(c.value())
    }

    pub fn valid(&self, cookie: &str) -> bool {
        let Some((timestamp_str, _)) = cookie.split_once('.') else {
            return false;
        };

        let Ok(timestamp) = timestamp_str.parse::<u64>() else {
            return false;
        };

        let now_unix = chrono::Utc::now().timestamp() as u64;

        now_unix.saturating_sub(timestamp) <= self.ttl.as_secs()
    }
}
