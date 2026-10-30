use chrono::{DateTime, Utc};
use time::OffsetDateTime;
use tower_sessions::{
    SessionStore,
    session::{Id, Record},
};
use tower_sessions_core::session_store::{Error, Result};
use uuid::Uuid;

use crate::db::repository::DevSessionRepository;

#[derive(Debug, Clone)]
pub struct DevSessionStore {
    repo: DevSessionRepository,
}

impl DevSessionStore {
    pub fn new(repo: DevSessionRepository) -> Self {
        Self { repo }
    }
}

#[async_trait::async_trait]
impl SessionStore for DevSessionStore {
    async fn create(&self, record: &mut Record) -> Result<()> {
        self.save(record).await
    }

    async fn save(&self, record: &Record) -> Result<()> {
        let id = Uuid::from_u128(record.id.0 as u128);
        let timestamp = record.expiry_date.unix_timestamp();
        let naive = DateTime::from_timestamp_secs(timestamp).unwrap();
        let data_json = serde_json::to_value(&record.data).map_err(|e| Error::Backend(e.to_string()))?;

        self.repo
            .upsert(id, data_json, naive.naive_utc())
            .await
            .map_err(|e| Error::Backend(e.to_string()))?;

        Ok(())
    }

    async fn load(&self, session_id: &Id) -> Result<Option<Record>> {
        let id = Uuid::from_u128(session_id.0 as u128);
        let Some(s) = self.repo.get(&id).await.map_err(|e| Error::Backend(e.to_string()))? else {
            return Ok(None);
        };

        if s.expires_at <= Utc::now().naive_utc() {
            return Ok(None);
        }

        // as_object returns a serde_json::Map that cannot be easily converted to hashmap, so do it manually
        let data = s
            .data
            .as_object()
            .map(|o| o.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();

        Ok(Some(Record {
            id: *session_id,
            data,
            expiry_date: OffsetDateTime::from_unix_timestamp(s.expires_at.and_utc().timestamp()).unwrap(),
        }))
    }

    async fn delete(&self, session_id: &Id) -> Result<()> {
        let id = Uuid::from_u128(session_id.0 as u128);
        self.repo.delete(&id).await.map_err(|e| Error::Backend(e.to_string()))?;

        Ok(())
    }
}
