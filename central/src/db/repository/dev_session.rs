use crate::{
    db::{
        Result,
        entity::{dev_session, prelude::*},
    },
    state::AppState,
};
use axum::extract::FromRef;
use chrono::NaiveDateTime;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter,
    prelude::Uuid,
};

#[derive(Clone, Debug)]
pub struct DevSessionRepository {
    db: DatabaseConnection,
}

impl DevSessionRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn get(&self, id: &Uuid) -> Result<Option<dev_session::Model>> {
        DevSession::find_by_id(*id).one(&self.db).await
    }

    pub async fn update(&self, user: dev_session::ActiveModel) -> Result<dev_session::Model> {
        user.update(&self.db).await
    }

    pub async fn save(&self, user: dev_session::ActiveModel) -> Result<dev_session::Model> {
        user.insert(&self.db).await
    }

    pub async fn delete(&self, id: &Uuid) -> Result<bool> {
        let r = DevSession::delete_by_id(*id).exec(&self.db).await?;
        Ok(r.rows_affected > 0)
    }

    pub async fn upsert(
        &self,
        uuid: Uuid,
        data: serde_json::Value,
        expires_at: NaiveDateTime,
    ) -> Result<dev_session::Model> {
        let model = dev_session::ActiveModel {
            id: Set(uuid),
            account_id: Set(data.get("dev_id").and_then(|x| x.as_i64())),
            data: Set(data),
            expires_at: Set(expires_at),
        };

        DevSession::insert(model)
            .on_conflict(
                sea_orm::sea_query::OnConflict::column(dev_session::Column::Id)
                    .update_columns(vec![dev_session::Column::Data, dev_session::Column::ExpiresAt])
                    .to_owned(),
            )
            .exec_with_returning(&self.db)
            .await
    }

    pub async fn delete_expired(&self, now: NaiveDateTime) -> Result<u64> {
        let r =
            DevSession::delete_many().filter(dev_session::Column::ExpiresAt.lte(now)).exec(&self.db).await?;

        Ok(r.rows_affected)
    }

    pub async fn delete_all_for_account(&self, account_id: i64) -> Result<u64> {
        let r = DevSession::delete_many()
            .filter(dev_session::Column::AccountId.eq(account_id))
            .exec(&self.db)
            .await?;

        Ok(r.rows_affected)
    }
}

impl FromRef<AppState> for DevSessionRepository {
    fn from_ref(input: &AppState) -> Self {
        input.database.dev_session_repository.clone()
    }
}
