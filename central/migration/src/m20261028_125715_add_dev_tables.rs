use sea_orm_migration::{prelude::*, schema::*};

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261028_125715_add_dev_tables"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table("dev_account")
                    .col(pk_auto("id"))
                    .col(string_uniq("username"))
                    .col(string("password_hash"))
                    .col(boolean("setup_complete"))
                    .col(boolean("is_admin"))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("dev_api_key")
                    .col(pk_auto("id"))
                    .col(string("name"))
                    .col(string("description"))
                    .col(string("secret"))
                    .col(integer("owner"))
                    .col(integer("request_reload_ns"))
                    .col(date_time("created_at"))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("dev_session")
                    .col(pk_uuid("id"))
                    .col(json("data"))
                    .col(integer_null("account_id"))
                    .col(date_time("expires_at"))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table("dev_account").to_owned()).await?;
        manager.drop_table(Table::drop().table("dev_api_key").to_owned()).await?;
        manager.drop_table(Table::drop().table("dev_session").to_owned()).await?;

        Ok(())
    }
}
