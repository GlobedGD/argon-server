use std::time::Duration;

use axum::{
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};

pub struct NoCache<T>(pub T);

impl<T: IntoResponse> IntoResponse for NoCache<T> {
    fn into_response(self) -> Response {
        let mut response = self.0.into_response();
        let headers = response.headers_mut();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        response
    }
}

pub struct Cache<T> {
    inner: T,
    duration: Duration,
}

impl<T> Cache<T> {
    pub fn new(duration: Duration, inner: T) -> Self {
        Cache { inner, duration }
    }
}

impl<T: IntoResponse> IntoResponse for Cache<T> {
    fn into_response(self) -> Response {
        let mut response = self.inner.into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_str(&format!("max-age={}", self.duration.as_secs())).unwrap(),
        );
        response
    }
}

pub enum Either<T, Y> {
    First(pub T),
    Second(pub Y),
}

impl<T: IntoResponse, Y: IntoResponse> IntoResponse for Either<T, Y> {
    fn into_response(self) -> Response {
        match self {
            Self::First(x) => x.into_response(),
            Self::Second(y) => y.into_response(),
        }
    }
}
