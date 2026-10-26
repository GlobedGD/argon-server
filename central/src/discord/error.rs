use std::num::ParseIntError;

#[derive(Debug, Error)]
pub enum Error {
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("mismatched secret or account ID")]
    MismatchedState,
    #[error("malformed data in link callback")]
    MalformedCallback,
}

impl From<ParseIntError> for Error {
    fn from(value: ParseIntError) -> Self {
        Self::MalformedCallback
    }
}
