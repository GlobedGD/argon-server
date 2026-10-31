use axum::{extract::FromRequestParts, http::request::Parts};
use shared::message::GDAccountData;
use tower_sessions::Session;
use tracing::warn;

use super::error::WebError;
use crate::{db::repository::USER_SESSION_DATA_KEY, state::AppState, user::User};

pub struct UserSession {
    pub user: User,
    pub session: Session,
}

impl FromRequestParts<AppState> for UserSession {
    type Rejection = WebError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        user_session(parts, state).await?.ok_or(WebError::NotLoggedIn)
    }
}

async fn user_session(parts: &mut Parts, state: &AppState) -> Result<Option<UserSession>, WebError> {
    let session = Session::from_request_parts(parts, state).await.expect("session middleware unavailable");

    let Some(account_data) = session.get::<GDAccountData>(USER_SESSION_DATA_KEY).await.map_err(|e| {
        warn!("error getting account_data from session: {e:?}");
        WebError::NotLoggedIn
    })?
    else {
        return Ok(None);
    };

    let user = state.user_manager.get_or_create_user(&account_data).await?;
    Ok(Some(UserSession { user, session }))
}
