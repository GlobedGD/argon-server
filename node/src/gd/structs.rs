use shared::message::GDAccountData;
use tracing::warn;

use crate::gd::{CSKVMap, ParseError, Parseable};

pub struct UserInfo {
    pub account_id: i32,
    pub user_id: i32,
    pub username: String,
    pub custom: String,
}

impl UserInfo {
    pub fn account_data(&self) -> GDAccountData {
        GDAccountData {
            account_id: self.account_id,
            user_id: self.user_id,
            username: self.username.clone(),
        }
    }
}

impl Parseable for UserInfo {
    fn parse(data: &str) -> Result<Self, super::ParseError> {
        let map = data.parse::<CSKVMap>()?;

        Ok(UserInfo {
            account_id: map.get_i32(16)?,
            user_id: map.get_i32(2)?,
            username: map.get(1)?,
            custom: map.get(61)?,
        })
    }
}

pub struct LevelComment {
    pub text: String,
    pub user_id: i32,
    pub account_id: i32,
    pub username: String,
}

impl LevelComment {
    pub fn account_data(&self) -> GDAccountData {
        GDAccountData {
            account_id: self.account_id,
            user_id: self.user_id,
            username: self.username.clone(),
        }
    }
}

impl Parseable for LevelComment {
    fn parse(data: &str) -> Result<Self, ParseError> {
        let (comment_obj_txt, user_obj_txt) = data.split_once(':').ok_or(ParseError::MissingDelimiter)?;

        let comment_obj = CSKVMap::parse_with_delimiter(comment_obj_txt, '~')?;
        let user_obj = CSKVMap::parse_with_delimiter(user_obj_txt, '~')?;

        Ok(LevelComment {
            user_id: comment_obj.get_i32(3)?,
            text: comment_obj.get_base64(2)?,
            account_id: user_obj.get_i32(16)?,
            username: user_obj.get(1)?,
        })
    }
}

impl Parseable for Vec<LevelComment> {
    fn parse(data: &str) -> Result<Self, super::ParseError>
    where
        Self: Sized,
    {
        let mut out = Vec::new();

        let data = data.split_once('#').unwrap_or((data, "")).0;
        for part in data.split('|').filter(|x| !x.is_empty()) {
            match LevelComment::parse(part) {
                Ok(comment) => out.push(comment),
                Err(e) => warn!("failed to parse level comment '{part}': {e:?}"),
            }
        }

        Ok(out)
    }
}
