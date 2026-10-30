use askama::Template;
use axum::{
    extract::FromRequestParts,
    http::{StatusCode, header, request::Parts},
    response::{IntoResponse, Redirect, Response},
};
use constant_time_eq::constant_time_eq;
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use tracing::{error, warn};

use crate::{
    developer::{DevError, Developer, LoginError},
    routes::web::error::{WebError, WebResult},
    state::AppState,
};

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

    let Some(dev_id) = session.get::<i64>("dev_id").await.map_err(|e| {
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

// Html responder

pub struct Html<T: Template>(pub T);

impl<T: Template> IntoResponse for Html<T> {
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(body) => {
                let headers = [(header::CONTENT_TYPE, "text/html; charset=utf-8")];
                (headers, body).into_response()
            }

            Err(e) => {
                error!("failed to render template: {e}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

// CSRF stuff

fn generate_token() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

pub async fn csrf_token(session: &Session) -> Result<String, WebError> {
    if let Some(token) = session.get::<String>("csrf_token").await? {
        Ok(token)
    } else {
        let token = generate_token();
        session.insert("csrf_token", &token).await?;
        Ok(token)
    }
}

pub async fn rotate_csrf_token(session: &Session) -> Result<String, WebError> {
    let token = generate_token();
    session.insert("csrf_token", &token).await?;
    Ok(token)
}

pub async fn verify_csrf_token(session: &Session, token: &str) -> Result<(), WebError> {
    match session.get::<String>("csrf_token").await? {
        Some(t) if constant_time_eq(t.as_bytes(), token.as_bytes()) => Ok(()),
        _ => Err(WebError::Csrf),
    }
}

// Flash

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Flash {
    pub kind: FlashKind,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlashKind {
    Success,
    Error,
}

impl Flash {
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            kind: FlashKind::Success,
            message: message.into(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            kind: FlashKind::Error,
            message: message.into(),
        }
    }

    pub fn from_dev_error(e: DevError) -> Result<Self, WebError> {
        match e {
            DevError::UsernameLength
            | DevError::PasswordLength
            | DevError::UsernameTaken
            | DevError::Login(LoginError::InvalidCredentials)
            | DevError::NotFound => Ok(Flash::error(e.to_string())),
            DevError::PwHashFailed | DevError::Database(_) | DevError::Login(_) => Err(e.into()),
        }
    }
}

impl FlashKind {
    pub fn class(self) -> &'static str {
        match self {
            FlashKind::Success => "success",
            FlashKind::Error => "error",
        }
    }

    pub fn role(self) -> &'static str {
        match self {
            FlashKind::Success => "status",
            FlashKind::Error => "alert",
        }
    }
}

pub async fn set_flash(session: &Session, flash: Flash) -> Result<(), WebError> {
    session.insert("flash", &flash).await?;
    Ok(())
}

pub async fn take_flash(session: &Session) -> Result<Option<Flash>, WebError> {
    let flash = session.get::<Flash>("flash").await?;
    if flash.is_some() {
        session.remove::<Flash>("flash").await?;
    }
    Ok(flash)
}

pub async fn redirect_with_flash(session: &Session, to: &str, flash: Flash) -> WebResult<Redirect> {
    set_flash(session, flash).await?;
    Ok(Redirect::to(to))
}
