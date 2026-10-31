use axum::response::Redirect;
use serde::{Deserialize, Serialize};
use tower_sessions::Session;

use super::session::SessionError;

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

pub async fn set_flash(session: &Session, flash: Flash) -> Result<(), SessionError> {
    session.insert("flash", &flash).await?;
    Ok(())
}

pub async fn take_flash(session: &Session) -> Result<Option<Flash>, SessionError> {
    let flash = session.get::<Flash>("flash").await?;
    if flash.is_some() {
        session.remove::<Flash>("flash").await?;
    }
    Ok(flash)
}

pub async fn redirect_with_flash<E>(session: &Session, to: &str, flash: Flash) -> Result<Redirect, E>
where
    E: From<SessionError>,
{
    set_flash(session, flash).await?;
    Ok(Redirect::to(to))
}
