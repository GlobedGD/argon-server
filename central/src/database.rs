use std::{fmt::Display, sync::Arc, time::Duration};

use crate::schema::api_tokens::{dsl::api_tokens, table as api_tokens_table};
use argon_shared::{debug, error, info, warn};
use diesel::{
    Connection, RunQueryDsl, SqliteConnection,
    connection::SimpleConnection,
    prelude::*,
    r2d2::{self, ConnectionManager, CustomizeConnection, Pool, PooledConnection},
};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use rocket::{
    Phase, Request, Rocket,
    http::Status,
    request::{FromRequest, Outcome},
};
use rocket_sync_db_pools::diesel;
use serde::Serialize;
use thiserror::Error;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

type ArgonDbInner = PooledConnection<ConnectionManager<SqliteConnection>>;
type ArgonDbPoolInner = Pool<ConnectionManager<SqliteConnection>>;

pub struct ArgonDb {
    conn: Arc<Mutex<Option<ArgonDbInner>>>,
    permit: Option<OwnedSemaphorePermit>,
}

// Models

#[derive(Queryable, Selectable, Serialize)]
#[diesel(table_name = crate::schema::api_tokens)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
#[allow(unused)]
pub struct ApiToken {
    pub id: i32,
    pub name: String,
    pub owner: String,
    pub description: String,
    pub validations_per_day: i32,
    pub validations_per_hour: i32,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::api_tokens)]
pub struct NewApiToken<'a> {
    pub name: &'a str,
    pub owner: &'a str,
    pub description: &'a str,
    pub validations_per_day: i32,
    pub validations_per_hour: i32,
}

#[derive(Error, Debug)]
pub enum ArgonDbError {
    #[error("diesel error: {0}")]
    Database(#[from] diesel::result::Error),
    #[error("row not found")]
    NotFound,
}

// Main database impl

impl ArgonDb {
    pub async fn get_one<P: Phase>(rocket: &Rocket<P>) -> Result<ArgonDb, Status> {
        match rocket.state::<Arc<ArgonDbPool>>() {
            Some(p) => match p.get_one().await {
                Ok(conn) => Ok(conn),
                _ => Err(Status::ServiceUnavailable),
            },

            None => Err(Status::InternalServerError),
        }
    }

    pub async fn run<R, F: FnOnce(&mut SqliteConnection) -> R>(&self, f: F) -> R {
        let conn = self.conn.clone();
        let mut conn = conn.lock_owned().await;

        let pconn = conn.as_mut().expect("self.connection should be Some");
        tokio::task::block_in_place(move || f(pconn))
    }

    pub async fn get_token(&self, token_id: i32) -> Result<ApiToken, ArgonDbError> {
        let token = self
            .run(|conn| {
                api_tokens
                    .find(token_id)
                    .select(ApiToken::as_select())
                    .first(conn)
                    .optional()
            })
            .await;

        match token {
            Ok(Some(token)) => Ok(token),
            Ok(None) => Err(ArgonDbError::NotFound),
            Err(err) => Err(ArgonDbError::Database(err)),
        }
    }

    pub async fn get_all_tokens(&self) -> Result<Vec<ApiToken>, ArgonDbError> {
        let tokens = self
            .run(|conn| api_tokens.select(ApiToken::as_select()).load(conn))
            .await?;

        Ok(tokens)
    }

    pub async fn insert_token<'a>(&self, token: NewApiToken<'a>) -> Result<ApiToken, ArgonDbError> {
        let token = self
            .run(|conn| {
                diesel::insert_into(api_tokens_table)
                    .values(&token)
                    .returning(ApiToken::as_returning())
                    .get_result(conn)
            })
            .await?;

        Ok(token)
    }
}

// Migrations

pub fn do_run_migrations(url: &str) -> Result<(), diesel::ConnectionError> {
    debug!("Running migrations");

    let mut conn = SqliteConnection::establish(url)?;

    // also turn on wal
    diesel::sql_query("PRAGMA journal_mode=wal")
        .execute(&mut conn)
        .expect("Failed to turn on WAL");

    match conn.run_pending_migrations(MIGRATIONS).map(|v| v.len()) {
        Ok(migs) if migs != 0 => {
            info!("Applied {migs} migrations!");
        }

        Ok(_) => {}

        Err(err) => {
            error!("Failed to apply migrations: {err}");
            panic!("failed to apply migrations");
        }
    }

    Ok(())
}

// Boring setup stuff
// reference: https://github.com/dani-garcia/vaultwarden/blob/main/src/db/mod.rs

pub async fn run_blocking<F, R>(job: F) -> R
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    match tokio::task::spawn_blocking(job).await {
        Ok(ret) => ret,
        Err(e) => match e.try_into_panic() {
            Ok(panic) => std::panic::resume_unwind(panic),
            Err(_) => unreachable!("spawn_blocking tasks are never cancelled"),
        },
    }
}

#[derive(Debug)]
pub struct ArgonDbOptions;

impl CustomizeConnection<SqliteConnection, r2d2::Error> for ArgonDbOptions {
    fn on_acquire(&self, conn: &mut SqliteConnection) -> Result<(), r2d2::Error> {
        conn.batch_execute("PRAGMA busy_timeout = 5000; PRAGMA synchronous = NORMAL;")
            .map_err(r2d2::Error::QueryError)?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct ArgonDbPool {
    pool: Option<ArgonDbPoolInner>,
    semaphore: Arc<Semaphore>,
}

impl Drop for ArgonDb {
    fn drop(&mut self) {
        let conn = self.conn.clone();
        let permit = self.permit.take();

        tokio::task::spawn_blocking(move || {
            let mut conn = tokio::runtime::Handle::current().block_on(conn.lock_owned());

            if let Some(conn) = conn.take() {
                drop(conn);
            }

            drop(permit);
        });
    }
}

impl Drop for ArgonDbPool {
    fn drop(&mut self) {
        let pool = self.pool.take();
        tokio::task::spawn_blocking(move || drop(pool));
    }
}

impl ArgonDbPool {
    pub fn from_url(database_url: &str) -> Result<Self, &'static str> {
        if let Err(err) = do_run_migrations(database_url) {
            warn!("Error running migrations: {err}");
            return Err("failed to apply migrations!");
        }

        let manager = ConnectionManager::new(database_url);
        let pool = Pool::builder()
            .connection_timeout(Duration::from_secs(10))
            .connection_customizer(Box::new(ArgonDbOptions))
            .build(manager)
            .map_err(|_| "Failed to create pool")?;

        Ok(ArgonDbPool {
            pool: Some(pool),
            semaphore: Arc::new(Semaphore::new(10)),
        })
    }

    pub async fn get_one(&self) -> Result<ArgonDb, &'static str> {
        let duration = Duration::from_secs(10);
        let permit = match tokio::time::timeout(duration, self.semaphore.clone().acquire_owned()).await {
            Ok(p) => p.expect("semaphore should be open"),
            Err(_) => {
                return Err("timeout waiting for database connection");
            }
        };

        let pool = self.pool.as_ref().expect("pool should exist").clone();
        let c = run_blocking(move || pool.get_timeout(duration))
            .await
            .map_err(|_| "error retrieving connection from the pool")?;

        Ok(ArgonDb {
            conn: Arc::new(Mutex::new(Some(c))),
            permit: Some(permit),
        })
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ArgonDb {
    type Error = ();
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match ArgonDb::get_one(request.rocket()).await {
            Ok(conn) => Outcome::Success(conn),
            Err(status) => Outcome::Error((status, ())),
        }
    }
}
