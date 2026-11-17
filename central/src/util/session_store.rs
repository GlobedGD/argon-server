use std::{fmt::Debug, time::Duration};

use chrono::{DateTime, NaiveDateTime, Utc};
use time::OffsetDateTime;
use tower_cookies::cookie::SameSite;
use tower_sessions::{
    Expiry, SessionManagerLayer, SessionStore,
    session::{Id, Record},
};
use tower_sessions_core::session_store::{Error, Result};
use uuid::Uuid;

pub struct StoredSession {
    pub id: Uuid,
    pub data: serde_json::Value,
    pub expires_at: NaiveDateTime,
}

pub trait SessionStoreBackend: Send + Sync + Debug + 'static {
    fn upsert(&self, session: StoredSession) -> impl Future<Output = anyhow::Result<()>> + Send;
    fn get(&self, id: &Uuid) -> impl Future<Output = anyhow::Result<Option<StoredSession>>> + Send;
    fn delete(&self, id: &Uuid) -> impl Future<Output = anyhow::Result<()>> + Send;
}

#[derive(Clone, Debug)]
pub struct SessionStoreAdapter<T>(T);

impl<T> SessionStoreAdapter<T>
where
    T: SessionStoreBackend + Clone,
{
    pub fn new(backend: T) -> Self {
        Self(backend)
    }

    pub fn new_layer(backend: T, expiry: Duration) -> SessionManagerLayer<Self> {
        SessionManagerLayer::new(Self(backend))
            .with_expiry(Expiry::OnInactivity(expiry.try_into().unwrap()))
            // insecure in debug
            .with_secure(!cfg!(debug_assertions))
            // Lax so discord callback stays working
            .with_same_site(SameSite::Lax)
    }
}

#[async_trait::async_trait]
impl<T> SessionStore for SessionStoreAdapter<T>
where
    T: SessionStoreBackend + Clone,
{
    async fn create(&self, record: &mut Record) -> Result<()> {
        self.save(record).await
    }

    async fn save(&self, record: &Record) -> Result<()> {
        let id = Uuid::from_u128(record.id.0 as u128);
        let timestamp = record.expiry_date.unix_timestamp();
        let naive = DateTime::from_timestamp_secs(timestamp).unwrap();
        let data_json = serde_json::to_value(&record.data).map_err(|e| Error::Backend(e.to_string()))?;

        let session = StoredSession {
            id,
            data: data_json,
            expires_at: naive.naive_utc(),
        };

        self.0.upsert(session).await.map_err(|e| Error::Backend(e.to_string()))?;

        Ok(())
    }

    async fn load(&self, session_id: &Id) -> Result<Option<Record>> {
        let id = Uuid::from_u128(session_id.0 as u128);
        let Some(s) = self.0.get(&id).await.map_err(|e| Error::Backend(e.to_string()))? else {
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
        self.0.delete(&id).await.map_err(|e| Error::Backend(e.to_string()))?;

        Ok(())
    }
}
