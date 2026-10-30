use std::sync::Arc;

use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    response::Redirect,
};
use rand::{RngExt, distr::Alphanumeric};
use serde::Deserialize;

use crate::{
    developer::{DevApiKey, Developer, DeveloperManager},
    routes::web::{
        error::{WebError, WebResult},
        util::{AdminSession, Flash, Html, csrf_token, redirect_with_flash, take_flash, verify_csrf_token},
    },
};

pub mod keys;

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
        Err(e) => Flash::from_dev_error(e)?,
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
        Err(e) => Flash::from_dev_error(e)?,
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
        Err(e) => Flash::from_dev_error(e)?,
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
