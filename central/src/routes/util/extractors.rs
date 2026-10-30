use std::net::SocketAddr;

use axum::{
    RequestPartsExt,
    extract::{ConnectInfo, FromRequestParts},
    http::{header, request::Parts},
};

use crate::{
    developer::ApiKeyClaims,
    routes::api::ApiError,
    state::AppState,
    token::{Scope, TokenClaims},
};

fn extract_bearer(req: &mut Parts) -> Result<Option<&str>, ApiError> {
    let Some(header) = req.headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };

    let auth = header.to_str().ok().and_then(|s| s.strip_prefix("Bearer ")).ok_or(ApiError::MalformedAuth)?;
    Ok(Some(auth))
}

pub struct ExtractToken<const S: Scope> {
    pub claims: TokenClaims,
}

impl<const S: Scope> FromRequestParts<AppState> for ExtractToken<S> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let token = extract_bearer(parts)?.ok_or(ApiError::MissingAuth)?;

        let claims = state.user_manager.validate_token(token, S).await?;
        Ok(ExtractToken { claims })
    }
}

pub type ExtractRefreshToken = ExtractToken<{ Scope::Refresh }>;
pub type ExtractAccessToken = ExtractToken<{ Scope::Access }>;
pub type ExtractAccManagementToken = ExtractToken<{ Scope::AccountManagement }>;

pub struct ExtractApiKey(pub Option<ApiKeyClaims>);

impl FromRequestParts<AppState> for ExtractApiKey {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let key = extract_bearer(parts)?;

        let claims = match key {
            Some(key) => Some(state.developer_manager.validate_api_key(key).await?),
            None => None,
        };

        // parts.extensions.insert(claims.clone());

        Ok(ExtractApiKey(claims))
    }
}

pub struct ApiKeyRateLimit;

impl FromRequestParts<AppState> for ApiKeyRateLimit {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let ExtractApiKey(claims) = ExtractApiKey::from_request_parts(parts, state).await?;
        let ConnectInfo(addr) =
            parts.extract::<ConnectInfo<SocketAddr>>().await.expect("Failed to extract connect info");

        state.developer_manager.check_rate_limit(claims.as_ref(), addr.ip()).await?;

        Ok(ApiKeyRateLimit)
    }
}
