use axum::{extract::FromRequestParts, http::request::Parts};
use tower_sessions::Session;
use tracing::warn;

use super::error::WebError;
use crate::{db::repository::DEV_SESSION_ID_KEY, developer::Developer, state::AppState};

pub struct DevSession {
    pub dev: Developer,
    pub session: Session,
}

impl FromRequestParts<AppState> for DevSession {
    type Rejection = WebError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        dev_session(parts, state).await?.ok_or(WebError::NotLoggedIn)
    }
}

async fn dev_session(parts: &mut Parts, state: &AppState) -> Result<Option<DevSession>, WebError> {
    let session = Session::from_request_parts(parts, state).await.expect("session middleware unavailable");

    let Some(dev_id) = session.get::<i64>(DEV_SESSION_ID_KEY).await.map_err(|e| {
        warn!("error getting dev_id from session: {e:?}");
        WebError::NotLoggedIn
    })?
    else {
        return Ok(None);
    };

    let Some(dev) = state.developer_manager.get_developer(dev_id).await? else {
        let _ = session.flush().await;
        return Err(WebError::NotLoggedIn);
    };

    Ok(Some(DevSession { dev, session }))
}

// Session extractor for admin only pages

pub struct AdminSession {
    pub dev: Developer,
    pub session: Session,
}

impl FromRequestParts<AppState> for AdminSession {
    type Rejection = WebError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let DevSession { dev, session } = DevSession::from_request_parts(parts, state).await?;
        if !dev.is_admin {
            return Err(WebError::Forbidden);
        }
        Ok(AdminSession { dev, session })
    }
}
