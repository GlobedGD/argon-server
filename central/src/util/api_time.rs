//! Timestamp serialized as unix time
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

pub struct ApiTime(pub SystemTime);

impl ApiTime {
    pub fn from_timestamp(timestamp: u64) -> Self {
        ApiTime(SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp))
    }
}

impl<'de> Deserialize<'de> for ApiTime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let timestamp = i64::deserialize(deserializer)?;
        Ok(ApiTime(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(timestamp as u64)))
    }
}

impl Serialize for ApiTime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let timestamp = self.0.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64;
        serializer.serialize_i64(timestamp)
    }
}

impl From<SystemTime> for ApiTime {
    fn from(time: SystemTime) -> Self {
        ApiTime(time)
    }
}
