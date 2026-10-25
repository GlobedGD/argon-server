use crate::db::{
    Result,
    entity::{prelude::*, user},
};
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait};

#[derive(Clone)]
pub struct UserRepository {
    db: DatabaseConnection,
}

impl UserRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn get_user(&self, account_id: i32) -> Result<Option<user::Model>> {
        User::find_by_id(account_id as i64).one(&self.db).await
    }

    pub async fn update(&self, user: user::ActiveModel) -> Result<user::Model> {
        user.update(&self.db).await
    }

    pub async fn save(&self, user: user::ActiveModel) -> Result<user::Model> {
        user.insert(&self.db).await
    }
}
