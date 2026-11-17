use crate::{
    db::{
        Result,
        entity::{prelude::*, user},
    },
    state::AppState,
};
use axum::extract::FromRef;
use migration::{Expr, OnConflict};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, Iterable, QueryFilter};

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

    pub async fn upsert(
        &self,
        user: user::ActiveModel,
        update_columns: impl IntoIterator<Item = user::Column>,
    ) -> Result<user::Model> {
        let res = User::insert(user)
            .on_conflict(OnConflict::column(user::Column::Id).update_columns(update_columns).to_owned())
            .exec_with_returning(&self.db)
            .await?;

        Ok(res)
    }

    pub async fn upsert_all(&self, user: user::ActiveModel) -> Result<user::Model> {
        self.upsert(user, user::Column::iter().collect::<Vec<_>>()).await
    }

    pub async fn update_advanced_auth(&self, account_id: i32, advanced_auth: bool) -> Result<user::Model> {
        let mut results = User::update_many()
            .col_expr(user::Column::AdvancedAuth, Expr::value(advanced_auth))
            .filter(user::Column::Id.eq(account_id as i64))
            .exec_with_returning(&self.db)
            .await?;

        if let Some(model) = results.pop() {
            Ok(model)
        } else {
            Err(sea_orm::DbErr::RecordNotFound(format!("User with account_id {} not found", account_id)))
        }
    }
}

impl FromRef<AppState> for UserRepository {
    fn from_ref(input: &AppState) -> Self {
        input.database.user_repository.clone()
    }
}
