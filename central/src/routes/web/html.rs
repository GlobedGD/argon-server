use askama::Template;
use axum::{
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use tracing::error;

pub struct Html<T: Template>(pub T);

impl<T: Template> IntoResponse for Html<T> {
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(body) => {
                let headers =
                    [(header::CONTENT_TYPE, "text/html; charset=utf-8"), (header::CACHE_CONTROL, "no-store")];
                (headers, body).into_response()
            }

            Err(e) => {
                error!("failed to render template: {e}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}
