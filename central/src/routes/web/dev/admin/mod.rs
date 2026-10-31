use std::sync::Arc;

use askama::Template;
use axum::{
    Form, Router,
    extract::{Path, State},
    response::Redirect,
    routing::{get, post},
};
use rand::{RngExt, distr::Alphanumeric};
use serde::Deserialize;

use super::{
    error::{WebError, WebResult, flash_from_dev_error},
    session::AdminSession,
};
use crate::{
    developer::{DevApiKey, Developer, DeveloperManager},
    routes::web::{
        Html,
        csrf::{csrf_token, verify_csrf_token},
        flash::{Flash, redirect_with_flash, take_flash},
    },
    state::AppState,
};

pub mod keys;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(get_admin))
        .route("/developers", post(create_developer))
        .route("/developers/{id}", get(get_developer))
        .route("/developers/{id}/reset", post(reset_developer_password))
        .route("/developers/{id}/delete", post(delete_developer))
        .merge(keys::router())
}

#[derive(Template)]
#[template(path = "dev/admin/index.html")]
pub struct AdminPageTemplate {
    me: Developer,
    developers: Vec<Developer>,
    csrf_token: String,
    flash: Option<Flash>,
}

pub async fn get_admin(
    AdminSession { dev, session }: AdminSession,
    State(dev_manager): State<Arc<DeveloperManager>>,
) -> WebResult<Html<AdminPageTemplate>> {
    Ok(Html(AdminPageTemplate {
        me: dev,
        developers: dev_manager.get_developers().await?,
        csrf_token: csrf_token(&session).await?,
        flash: take_flash(&session).await?,
    }))
}

#[derive(Deserialize)]
pub struct CreateData {
    username: String,
    csrf_token: String,
}

pub async fn create_developer(
    AdminSession { session, .. }: AdminSession,
    State(dev_manager): State<Arc<DeveloperManager>>,
    Form(data): Form<CreateData>,
) -> WebResult<Redirect> {
    verify_csrf_token(&session, &data.csrf_token).await?;

    let temp_password = generate_password();
    let flash = match dev_manager.create_developer(&data.username, &temp_password).await {
        Ok(other) => Flash::success(format!(
            "Created developer {}, temporary password: {}",
            other.username, temp_password
        )),
        Err(e) => flash_from_dev_error(e)?,
    };

    redirect_with_flash(&session, "/dev/admin", flash).await
}

#[derive(Deserialize)]
pub struct DeleteData {
    csrf_token: String,
}

pub async fn delete_developer(
    AdminSession { session, .. }: AdminSession,
    State(dev_manager): State<Arc<DeveloperManager>>,
    Path(id): Path<i64>,
    Form(data): Form<DeleteData>,
) -> WebResult<Redirect> {
    verify_csrf_token(&session, &data.csrf_token).await?;

    let flash = match dev_manager.delete_developer(id).await {
        Ok(()) => Flash::success(format!("Deleted developer with ID {}", id)),
        Err(e) => flash_from_dev_error(e)?,
    };

    redirect_with_flash(&session, "/dev/admin", flash).await
}

#[derive(Deserialize)]
pub struct ResetDeveloperData {
    csrf_token: String,
}

pub async fn reset_developer_password(
    AdminSession { session, .. }: AdminSession,
    State(dev_manager): State<Arc<DeveloperManager>>,
    Path(id): Path<i64>,
    Form(data): Form<ResetDeveloperData>,
) -> WebResult<Redirect> {
    verify_csrf_token(&session, &data.csrf_token).await?;

    let temp_password = generate_password();

    let flash = match dev_manager.set_developer_password(id, &temp_password, true).await {
        Ok(()) => Flash::success(format!("Reset successful, new password: {temp_password}")),
        Err(e) => flash_from_dev_error(e)?,
    };

    redirect_with_flash(&session, "/dev/admin", flash).await
}

#[derive(Template)]
#[template(path = "dev/admin/developer.html")]
pub struct AdminDeveloperPageTemplate {
    me: Developer,
    csrf_token: String,
    developer: Developer,
    keys: Vec<DevApiKey>,
    flash: Option<Flash>,
}

pub async fn get_developer(
    AdminSession { dev, session }: AdminSession,
    State(dev_manager): State<Arc<DeveloperManager>>,
    Path(id): Path<i64>,
) -> WebResult<Html<AdminDeveloperPageTemplate>> {
    let Some(developer) = dev_manager.get_developer(id).await? else {
        return Err(WebError::NotFound);
    };

    Ok(Html(AdminDeveloperPageTemplate {
        me: dev,
        csrf_token: csrf_token(&session).await?,
        developer,
        keys: dev_manager.get_developer_keys(id).await?,
        flash: take_flash(&session).await?,
    }))
}

fn generate_password() -> String {
    rand::rng().sample_iter(&Alphanumeric).take(16).map(char::from).collect::<String>()
}
