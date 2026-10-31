use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("session error: {0}")]
    Session(#[from] tower_sessions::session::Error),
    #[error("invalid CSRF token")]
    Csrf,
}
