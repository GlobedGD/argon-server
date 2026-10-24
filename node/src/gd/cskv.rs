use base64::{Engine, engine::general_purpose::URL_SAFE_PAD_INDIFFERENT as base64};
use std::{collections::HashMap, str::FromStr};

use crate::gd::parseable::ParseError;

/// CSKV - Colon Separated Key-Value map, used by RobTop api
pub struct CSKVMap(HashMap<u32, String>);

#[allow(unused)]
impl CSKVMap {
    pub fn size(&self) -> usize {
        self.0.len()
    }

    pub fn keys(&self) -> impl Iterator<Item = &u32> {
        self.0.keys()
    }

    pub fn values(&self) -> impl Iterator<Item = &String> {
        self.0.values()
    }

    pub fn contains(&self, key: u32) -> bool {
        self.0.contains_key(&key)
    }

    pub fn get(&self, key: u32) -> Result<String, ParseError> {
        self.0.get(&key).cloned().ok_or(ParseError::MissingKey(key))
    }

    pub fn get_base64(&self, key: u32) -> Result<String, ParseError> {
        Ok(String::from_utf8(base64.decode(&self.get(key)?)?)?)
    }

    pub fn get_i32(&self, key: u32) -> Result<i32, ParseError> {
        let value = self.get(key)?;
        value.parse::<i32>().map_err(|e| ParseError::InvalidInt(value.clone(), e))
    }

    pub fn get_u32(&self, key: u32) -> Result<u32, ParseError> {
        let value = self.get(key)?;
        value.parse::<u32>().map_err(|e| ParseError::InvalidInt(value.clone(), e))
    }

    pub fn parse_with_delimiter(s: &str, delimiter: char) -> Result<Self, ParseError> {
        let data = s.split_once('#').unwrap_or((s, s)).0;

        let map = data
            .split(delimiter)
            .array_chunks::<2>()
            .map(|[k, v]| {
                k.parse::<u32>()
                    .map(|key| (key, v.to_owned()))
                    .map_err(|e| ParseError::InvalidInt(k.to_owned(), e))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;

        Ok(CSKVMap(map))
    }
}

impl FromStr for CSKVMap {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_with_delimiter(s, ':')
    }
}
