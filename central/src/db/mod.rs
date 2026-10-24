use sea_orm::ConnectOptions;

use crate::{config::AppConfig, db::repository::UserRepository};
use migration::{Migrator, MigratorTrait};

pub mod entity;
pub mod repository;

pub struct Database {
    pub user_repository: UserRepository,
}

pub type Result<T> = std::result::Result<T, sea_orm::DbErr>;

impl Database {
    pub async fn new(config: &AppConfig) -> anyhow::Result<Self> {
        let mut opts = ConnectOptions::new(&config.database.url);
        opts.sqlx_logging_level(log::LevelFilter::Debug);

        let db = sea_orm::Database::connect(opts).await?;

        // run migrations
        Migrator::up(&db, None).await?;

        Ok(Self {
            user_repository: UserRepository::new(db.clone()),
        })
    }
}
