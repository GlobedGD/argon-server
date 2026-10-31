pub use sea_orm_migration::prelude::*;

mod m20220101_000001_create_table;
mod m20261028_125715_add_dev_tables;
mod m20261031_115530_add_user_session;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20220101_000001_create_table::Migration),
            Box::new(m20261028_125715_add_dev_tables::Migration),
            Box::new(m20261031_115530_add_user_session::Migration),
        ]
    }
}
