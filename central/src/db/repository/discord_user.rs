use crate::{
    db::{
        Result,
        entity::{discord_user, prelude::*},
    },
    discord::client::DiscordUserData,
    state::AppState,
};
use axum::extract::FromRef;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter,
    sea_query::{Expr, Value},
};

#[derive(Clone)]
pub struct DiscordUserRepository {
    db: DatabaseConnection,
}

impl DiscordUserRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn get_user(&self, id: i64) -> Result<Option<discord_user::Model>> {
        DiscordUser::find_by_id(id).one(&self.db).await
    }

    pub async fn get_by_user_id(&self, id: i32) -> Result<Option<discord_user::Model>> {
        DiscordUser::find().filter(discord_user::Column::UserId.eq(id as i64)).one(&self.db).await
    }

    pub async fn update(&self, user: discord_user::ActiveModel) -> Result<discord_user::Model> {
        user.update(&self.db).await
    }

    pub async fn save(&self, user: discord_user::ActiveModel) -> Result<discord_user::Model> {
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

    /// Syncs avatar URL, username and sets the last sync time for the user
    pub async fn sync_details(&self, data: DiscordUserData) -> Result<()> {
        DiscordUser::update_many()
            .col_expr(discord_user::Column::AvatarUrl, Expr::value(Value::String(Some(data.avatar_url))))
            .col_expr(discord_user::Column::Username, Expr::value(Value::String(Some(data.username))))
            .col_expr(
                discord_user::Column::LastSyncTime,
                Expr::value(Value::ChronoDateTime(Some(chrono::Utc::now().naive_utc()))),
            )
            .filter(discord_user::Column::DiscordId.eq(data.account_id))
            .exec(&self.db)
            .await?;

        Ok(())
    }
}

impl FromRef<AppState> for DiscordUserRepository {
    fn from_ref(input: &AppState) -> Self {
        input.database.discord_user_repository.clone()
    }
}
