use std::{num::ParseIntError, string::FromUtf8Error};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("missing key {0}")]
    MissingKey(u32),
    #[error("failed to parse '{0}' as integer: {1}")]
    InvalidInt(String, ParseIntError),
    #[error("failed to decode base64 string: {0}")]
    InvalidBase64(#[from] base64::DecodeError),
    #[error("failed to parse string as UTF-8: {0}")]
    InvalidUtf8(#[from] FromUtf8Error),
    #[error("missing needed delimiter in string")]
    MissingDelimiter,
}

pub trait Parseable {
    fn parse(data: &str) -> Result<Self, ParseError>
    where
        Self: Sized;
}

impl Parseable for () {
    fn parse(_data: &str) -> Result<Self, ParseError> {
        Ok(())
    }
}

impl Parseable for String {
    fn parse(data: &str) -> Result<Self, ParseError> {
        Ok(data.to_owned())
    }
}
