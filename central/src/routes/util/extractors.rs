use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};

use crate::{routes::api::ApiError, state::AppState, token::TokenClaims};

pub struct ExtractRefreshToken(pub TokenClaims);

impl<S> FromRequestParts<S> for ExtractRefreshToken
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state: AppState = AppState::from_ref(state);

        let Some(token) = parts
            .headers
            .get("Authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
        else {
            return Err(ApiError::MissingAuth);
        };

        let claims = app_state.user_manager.validate_refresh_token(token).await?;
        Ok(ExtractRefreshToken(claims))
    }
}
