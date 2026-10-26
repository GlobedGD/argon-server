use reqwest::StatusCode;
use std::num::ParseIntError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("mismatched secret or account ID")]
    MismatchedState,
    #[error("malformed data in link callback")]
    MalformedCallback,
    #[error("not linked to a Discord account")]
    DiscordNotLinked,
    #[error("already linked to a Discord account")]
    DiscordAlreadyLinked,
}

impl Error {
    pub fn error_code(&self) -> &'static str {
        match self {
            Error::Request(_) => "discord_client_request_failed",
            Error::MismatchedState => "discord_oauth_mismatched_state",
            Error::MalformedCallback => "discord_oauth_malformed_callback",
            Error::DiscordNotLinked => "discord_not_linked",
            Error::DiscordAlreadyLinked => "discord_already_linked",
        }
    }

    pub fn status_code(&self) -> StatusCode {
        match self {
            Error::Request(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::MismatchedState => StatusCode::BAD_REQUEST,
            Error::MalformedCallback => StatusCode::BAD_REQUEST,
            Error::DiscordNotLinked => StatusCode::NOT_FOUND,
            Error::DiscordAlreadyLinked => StatusCode::BAD_REQUEST,
        }
    }
}

impl From<ParseIntError> for Error {
    fn from(_: ParseIntError) -> Self {
        Self::MalformedCallback
    }
}
