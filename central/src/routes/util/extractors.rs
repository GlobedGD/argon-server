use std::net::{IpAddr, SocketAddr};

use axum::{
    RequestPartsExt,
    extract::{ConnectInfo, FromRequestParts},
    http::{header, request::Parts},
};

use crate::{
    developer::{ApiKeyClaims, DevScope},
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

// -- API keys --

pub struct ExtractApiKey<const S: DevScope>(pub Option<ApiKeyClaims>);

impl<const S: DevScope> FromRequestParts<AppState> for ExtractApiKey<S> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let key = extract_bearer(parts)?;

        let claims = match key {
            Some(key) => Some(state.developer_manager.validate_api_key(key).await?),
            None => None,
        };

        let claims = claims.filter(|claims| claims.has_scope(S));

        Ok(ExtractApiKey(claims))
    }
}

pub struct ApiKeyRateLimit<const S: DevScope, const KEY_REQUIRED: bool = true>;

impl<const S: DevScope, const KEY_REQUIRED: bool> FromRequestParts<AppState>
    for ApiKeyRateLimit<S, KEY_REQUIRED>
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let VerifiedIpAddr(ip) = VerifiedIpAddr::from_request_parts(parts, state).await?;
        let ExtractApiKey(claims) = ExtractApiKey::<S>::from_request_parts(parts, state).await?;

        if KEY_REQUIRED && claims.is_none() {
            return Err(ApiError::MissingAuth);
        }

        state.developer_manager.check_rate_limit(claims.as_ref(), ip).await?;

        Ok(ApiKeyRateLimit)
    }
}

pub struct VerifiedIpAddr(pub IpAddr);

impl FromRequestParts<AppState> for VerifiedIpAddr {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let ConnectInfo(raw_addr) =
            parts.extract::<ConnectInfo<SocketAddr>>().await.expect("Failed to extract connect info");

        let ip = if state.trusted_proxies.contains(&raw_addr.ip()) {
            find_ip_in_headers(parts).unwrap_or(raw_addr.ip())
        } else {
            raw_addr.ip()
        };

        Ok(VerifiedIpAddr(ip))
    }
}

fn find_ip_in_headers(parts: &mut Parts) -> Option<IpAddr> {
    if let Some(cf_ip) =
        parts.headers.get("CF-Connecting-IP").and_then(|h| h.to_str().ok()).and_then(|s| s.parse().ok())
    {
        return Some(cf_ip);
    }

    parts.headers.get("X-Forwarded-For")?.to_str().ok()?.split(',').next_back()?.trim().parse().ok()
}
