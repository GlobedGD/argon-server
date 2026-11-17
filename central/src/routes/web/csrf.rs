use constant_time_eq::constant_time_eq;
use tower_sessions::Session;

use super::session::SessionError;

fn generate_token() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

pub async fn csrf_token(session: &Session) -> Result<String, SessionError> {
    if let Some(token) = session.get::<String>("csrf_token").await? {
        Ok(token)
    } else {
        let token = generate_token();
        session.insert("csrf_token", &token).await?;
        Ok(token)
    }
}

pub async fn rotate_csrf_token(session: &Session) -> Result<String, SessionError> {
    let token = generate_token();
    session.insert("csrf_token", &token).await?;
    Ok(token)
}

pub async fn verify_csrf_token(session: &Session, token: &str) -> Result<(), SessionError> {
    match session.get::<String>("csrf_token").await? {
        Some(t) if constant_time_eq(t.as_bytes(), token.as_bytes()) => Ok(()),
        _ => Err(SessionError::Csrf),
    }
}
