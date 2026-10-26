use crate::{
    db::{
        Result,
        entity::{discord_user, prelude::*},
    },
    state::AppState,
};
use axum::extract::FromRef;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, QueryFilter};

#[derive(Clone)]
pub struct DiscordUserRepository {
    db: DatabaseConnection,
}

impl DiscordUserRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn get_user(&self, id: i64) -> Result<Option<discord_user::Model>> {
        DiscordUser::find_by_id(account_id).one(&self.db).await
    }

    pub async fn get_by_user_id(&self, id: i32) -> Result<Option<discord_user::Model>> {
        DiscordUser::find().filter(discord_user::Column::UserId.eq(id as i64)).one(&self.db).await
    }

    pub async fn update(&self, user: user::ActiveModel) -> Result<user::Model> {
        user.update(&self.db).await
    }

    pub async fn save(&self, user: user::ActiveModel) -> Result<user::Model> {
        user.insert(&self.db).await
    }

    /// Deletes the link, returns if it was successful. If this returns false, the user was not linked.
    /// This does not touch the `user` table.
    pub async fn delete(&self, id: i64) -> Result<bool> {
        let r = DiscordUser::delete_by_id(id).exec(&self.db).await?;
        Ok(r.rows_affected > 0)
    }

    /// Deletes the link, returns if it was successful. If this returns false, the user was not linked.
    /// This does not touch the `user` table.
    pub async fn delete_by_user_id(&self, id: i32) -> Result<bool> {
        let r = DiscordUser::delete_many()
            .filter(discord_user::Column::UserId.eq(id as i64))
            .exec(&self.db)
            .await?;

        Ok(r.rows_affected > 0)
    }
}

impl FromRef<AppState> for DiscordUserRepository {
    fn from_ref(input: &AppState) -> Self {
        input.database.discord_user_repository.clone()
    }
}
