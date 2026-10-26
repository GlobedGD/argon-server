use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table("user")
                    .col(integer_uniq("id").primary_key())
                    .col(integer_uniq("gd_user_id"))
                    .col(string("username"))
                    .col(boolean("advanced_auth"))
                    .col(integer("token_epoch"))
                    .col(integer_null("discord_id").unique_key())
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("discord_user")
                    .col(integer_uniq("discord_id").primary_key())
                    .col(integer_uniq("user_id"))
                    .col(string("username"))
                    .col(string("avatar_url"))
                    .to_owned(),
            )
            .await?;

        manager.create_index(Index::create().table("discord_user").col("user_id").to_owned()).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table("user").to_owned()).await?;
        manager.drop_table(Table::drop().table("discord_user").to_owned()).await?;

        Ok(())
    }
}
