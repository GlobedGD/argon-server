use crate::{
    db::{
        Result,
        entity::{prelude::*, user_session},
    },
    state::AppState,
    util::{SessionStoreBackend, StoredSession},
};
use axum::extract::FromRef;
use chrono::NaiveDateTime;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter,
    prelude::Uuid,
};
use shared::message::GDAccountData;

pub const USER_SESSION_DATA_KEY: &str = "account_data";

#[derive(Clone, Debug)]
pub struct UserSessionRepository {
    db: DatabaseConnection,
}

impl UserSessionRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn get(&self, id: &Uuid) -> Result<Option<user_session::Model>> {
        UserSession::find_by_id(*id).one(&self.db).await
    }

    pub async fn update(&self, user: user_session::ActiveModel) -> Result<user_session::Model> {
        user.update(&self.db).await
    }

    pub async fn save(&self, user: user_session::ActiveModel) -> Result<user_session::Model> {
        user.insert(&self.db).await
    }

    pub async fn delete(&self, id: &Uuid) -> Result<bool> {
        let r = UserSession::delete_by_id(*id).exec(&self.db).await?;
        Ok(r.rows_affected > 0)
    }

    pub async fn upsert(
        &self,
        uuid: Uuid,
        data: serde_json::Value,
        expires_at: NaiveDateTime,
    ) -> Result<user_session::Model> {
        let account_data = data
            .get(USER_SESSION_DATA_KEY)
            .and_then(|x| serde_json::from_value::<GDAccountData>(x.clone()).ok());

        let model = user_session::ActiveModel {
            id: Set(uuid),
            account_id: Set(account_data.map(|d| d.account_id as i64)),
            data: Set(data),
            expires_at: Set(expires_at),
        };

        UserSession::insert(model)
            .on_conflict(
                sea_orm::sea_query::OnConflict::column(user_session::Column::Id)
                    .update_columns(vec![user_session::Column::Data, user_session::Column::ExpiresAt])
                    .to_owned(),
            )
            .exec_with_returning(&self.db)
            .await
    }

    pub async fn delete_expired(&self, now: NaiveDateTime) -> Result<u64> {
        let r = UserSession::delete_many()
            .filter(user_session::Column::ExpiresAt.lte(now))
            .exec(&self.db)
            .await?;

        Ok(r.rows_affected)
    }

    pub async fn delete_all_for_account(&self, account_id: i32) -> Result<u64> {
        let r = UserSession::delete_many()
            .filter(user_session::Column::AccountId.eq(account_id as i64))
            .exec(&self.db)
            .await?;

        Ok(r.rows_affected)
    }
}

impl FromRef<AppState> for UserSessionRepository {
    fn from_ref(input: &AppState) -> Self {
        input.database.user_session_repository.clone()
    }
}

impl SessionStoreBackend for UserSessionRepository {
    async fn upsert(&self, session: StoredSession) -> anyhow::Result<()> {
        self.upsert(session.id, session.data, session.expires_at).await?;
        Ok(())
    }

    async fn get(&self, id: &Uuid) -> anyhow::Result<Option<StoredSession>> {
        let Some(s) = self.get(id).await? else {
            return Ok(None);
        };

        Ok(Some(StoredSession {
            id: s.id,
            data: s.data,
            expires_at: s.expires_at,
        }))
    }

    async fn delete(&self, id: &Uuid) -> anyhow::Result<()> {
        self.delete(id).await?;
        Ok(())
    }
}
