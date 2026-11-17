use axum::http::StatusCode;
use shared::message::UserChallengeOutcome;
use thiserror::Error;

#[derive(Debug, Error)]
// Note: append errors at the end
pub enum ChallengeError {
    #[error("Rate limited, try again later")]
    RateLimited,
    #[error("No available node that can serve this type of authentication resource")]
    NoAvailableResource,
    #[error("Too many challenges are currently in progress, try again later")]
    TooManyChallengesInProgress,
    #[error("Challenge timed out or was not found by given ID")]
    ChallengeNotFound,
    #[error("Challenge timed out")]
    TimedOut,
    #[error("Incorrect challenge answer")]
    IncorrectAnswer,
    #[error("Argon node is failing to reach a verification resource")]
    ResourceFailing,
    #[error("Argon node ran into an unexpected error")]
    OtherNodeError,
    #[error("Server does not support any of the challenge types requested by the client")]
    ChallengeTypeNotSupported,
}

impl ChallengeError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            ChallengeError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ChallengeError::NoAvailableResource => StatusCode::SERVICE_UNAVAILABLE,
            ChallengeError::TooManyChallengesInProgress => StatusCode::TOO_MANY_REQUESTS,
            ChallengeError::ChallengeNotFound => StatusCode::NOT_FOUND,
            ChallengeError::TimedOut => StatusCode::UNAUTHORIZED,
            ChallengeError::IncorrectAnswer => StatusCode::UNAUTHORIZED,
            ChallengeError::ResourceFailing => StatusCode::SERVICE_UNAVAILABLE,
            ChallengeError::OtherNodeError => StatusCode::INTERNAL_SERVER_ERROR,
            ChallengeError::ChallengeTypeNotSupported => StatusCode::BAD_REQUEST,
        }
    }

    pub fn error_code(&self) -> &'static str {
        match self {
            ChallengeError::RateLimited => "challenge_rate_limited",
            ChallengeError::NoAvailableResource => "challenge_no_available_resource",
            ChallengeError::TooManyChallengesInProgress => "challenge_too_many_in_progress",
            ChallengeError::ChallengeNotFound => "challenge_not_found",
            ChallengeError::TimedOut => "challenge_timed_out",
            ChallengeError::IncorrectAnswer => "challenge_incorrect_answer",
            ChallengeError::ResourceFailing => "challenge_resource_failing",
            ChallengeError::OtherNodeError => "challenge_other_node_error",
            ChallengeError::ChallengeTypeNotSupported => "challenge_type_not_supported",
        }
    }
}

impl From<UserChallengeOutcome> for ChallengeError {
    fn from(outcome: UserChallengeOutcome) -> Self {
        match outcome {
            UserChallengeOutcome::Success => panic!("unexpected success"),
            UserChallengeOutcome::ResourceFailing => ChallengeError::ResourceFailing,
            UserChallengeOutcome::OtherError => ChallengeError::OtherNodeError,
        }
    }
}
