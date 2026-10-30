use crate::{
    db::{
        Result,
        entity::{dev_account, prelude::*},
    },
    state::AppState,
};
use axum::extract::FromRef;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};

#[derive(Clone)]
pub struct DevAccountRepository {
    db: DatabaseConnection,
}

impl DevAccountRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn get_account(&self, id: i64) -> Result<Option<dev_account::Model>> {
        DevAccount::find_by_id(id).one(&self.db).await
    }

    pub async fn get_by_username(&self, username: &str) -> Result<Option<dev_account::Model>> {
        DevAccount::find().filter(dev_account::Column::Username.eq(username)).one(&self.db).await
    }

    pub async fn update(&self, user: dev_account::ActiveModel) -> Result<dev_account::Model> {
        user.update(&self.db).await
    }

    pub async fn save(&self, user: dev_account::ActiveModel) -> Result<dev_account::Model> {
        user.insert(&self.db).await
    }

    pub async fn delete(&self, id: i64) -> Result<bool> {
        let r = DevAccount::delete_by_id(id).exec(&self.db).await?;
        Ok(r.rows_affected > 0)
    }

    pub async fn get_all(&self) -> Result<Vec<dev_account::Model>> {
        DevAccount::find().all(&self.db).await
    }
}

impl FromRef<AppState> for DevAccountRepository {
    fn from_ref(input: &AppState) -> Self {
        input.database.dev_account_repository.clone()
    }
}
