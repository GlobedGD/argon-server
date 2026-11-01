use crate::db::{
    Result,
    entity::{dev_api_key, prelude::*},
};
use constant_time_eq::constant_time_eq;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};

#[derive(Clone)]
pub struct DevApiKeyRepository {
    db: DatabaseConnection,
}

impl DevApiKeyRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn get_all(&self) -> Result<Vec<dev_api_key::Model>> {
        DevApiKey::find().all(&self.db).await
    }

    pub async fn get_key(&self, id: i64) -> Result<Option<dev_api_key::Model>> {
        DevApiKey::find_by_id(id).one(&self.db).await
    }

    /// Returns a key that matches the ID and secret.
    /// If the key in DB has no secret, it's considered invalid and thus not returned here.
    pub async fn get_key_by_id_and_secret(
        &self,
        id: i64,
        secret: &str,
    ) -> Result<Option<dev_api_key::Model>> {
        let key = DevApiKey::find_by_id(id).one(&self.db).await?;
        Ok(key.filter(|k| !k.secret.is_empty() && constant_time_eq(k.secret.as_bytes(), secret.as_bytes())))
    }

    pub async fn update(&self, user: dev_api_key::ActiveModel) -> Result<dev_api_key::Model> {
        user.update(&self.db).await
    }

    pub async fn save(&self, user: dev_api_key::ActiveModel) -> Result<dev_api_key::Model> {
        user.insert(&self.db).await
    }

    pub async fn delete(&self, id: i64) -> Result<bool> {
        let r = DevApiKey::delete_by_id(id).exec(&self.db).await?;
        Ok(r.rows_affected > 0)
    }

    pub async fn delete_by_developer_id(&self, developer_id: i64) -> Result<u64> {
        let r = DevApiKey::delete_many()
            .filter(dev_api_key::Column::Owner.eq(developer_id))
            .exec(&self.db)
            .await?;

        Ok(r.rows_affected)
    }

    pub async fn get_all_by_developer_id(&self, developer_id: i64) -> Result<Vec<dev_api_key::Model>> {
        DevApiKey::find().filter(dev_api_key::Column::Owner.eq(developer_id)).all(&self.db).await
    }
}

// Note: removed so that routes don't use this directly and use cache in devmanager
// impl FromRef<AppState> for DevApiKeyRepository {
//     fn from_ref(input: &AppState) -> Self {
//         input.database.dev_api_key_repository.clone()
//     }
// }
