use std::time::Duration;

use argon_shared::{error, info};
use diesel::{SqliteConnection, connection::SimpleConnection};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use rocket::{
    Build, Rocket,
    fairing::{self, AdHoc},
};
use rocket_sync_db_pools::{database, diesel};

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

#[database("argon_db")]
pub struct ArgonDb(diesel::SqliteConnection);

impl ArgonDb {}

pub async fn run_migrations(rocket: Rocket<Build>) -> Rocket<Build> {
    match ArgonDb::get_one(&rocket).await {
        Some(db) => match db
            .run(|conn| conn.run_pending_migrations(MIGRATIONS).map(|v| v.len()))
            .await
        {
            Ok(migs) if migs != 0 => {
                info!("Applied {migs} migrations!");
            }

            Ok(_) => {}

            Err(err) => {
                error!("Failed to apply migrations: {err}");
                panic!("failed to apply migrations");
            }
        },

        None => {
            panic!("Failed to apply migrations (no database)");
        }
    }

    rocket
}

/* Lol */

#[derive(Debug)]
pub struct ConnectionOptions {
    pub enable_wal: bool,
    pub enable_foreign_keys: bool,
    pub busy_timeout: Option<Duration>,
}

impl diesel::r2d2::CustomizeConnection<SqliteConnection, diesel::r2d2::Error> for ConnectionOptions {
    fn on_acquire(&self, conn: &mut SqliteConnection) -> Result<(), diesel::r2d2::Error> {
        (|| {
            if self.enable_wal {
                conn.batch_execute("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
            }
            if self.enable_foreign_keys {
                conn.batch_execute("PRAGMA foreign_keys = ON;")?;
            }
            if let Some(d) = self.busy_timeout {
                conn.batch_execute(&format!("PRAGMA busy_timeout = {};", d.as_millis()))?;
            }
            Ok(())
        })()
        .map_err(diesel::r2d2::Error::QueryError)
    }
}
