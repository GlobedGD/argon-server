use std::sync::Arc;

use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    response::Redirect,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    developer::{DevApiKey, Developer, DeveloperManager},
    routes::web::{
        error::{WebError, WebResult},
        util::{AdminSession, Flash, Html, csrf_token, redirect_with_flash, take_flash, verify_csrf_token},
    },
};

#[derive(Template)]
#[template(path = "admin/key.html")]
pub struct AdminKeyPageTemplate {
    me: Developer,
    key: DevApiKey,
    developer: Developer,
    csrf_token: String,
    flash: Option<Flash>,
}

pub async fn get_key(
    AdminSession { dev, session }: AdminSession,
    State(dev_manager): State<Arc<DeveloperManager>>,
    Path((dev_id, key_id)): Path<(i64, i64)>,
) -> WebResult<Html<AdminKeyPageTemplate>> {
    let Some(key) = dev_manager.get_developer_key(dev_id, key_id).await? else {
        return Err(WebError::NotFound);
    };

    Ok(Html(AdminKeyPageTemplate {
        me: dev,
        key,
        developer: dev_manager.get_developer(dev_id).await?.ok_or(WebError::NotFound)?,
        csrf_token: csrf_token(&session).await?,
        flash: take_flash(&session).await?,
    }))
}

#[derive(Deserialize)]
pub struct CreateKeyData {
    csrf_token: String,
    name: String,
    description: String,
    requests: u64,
    period: String,
}

pub async fn create_key(
    AdminSession { session, .. }: AdminSession,
    State(dev_manager): State<Arc<DeveloperManager>>,
    Path(dev_id): Path<i64>,
    Form(data): Form<CreateKeyData>,
) -> WebResult<Redirect> {
    verify_csrf_token(&session, &data.csrf_token).await?;

    let request_reload_ms = parse_reload_ms(&data.period, data.requests)?;

    let flash = match dev_manager.create_key(dev_id, &data.name, &data.description, request_reload_ms).await {
        Ok(_) => Flash::success("Successfully created key"),
        Err(e) => Flash::from_dev_error(e)?,
    };

    redirect_with_flash(&session, &format!("/dashboard/admin/developers/{dev_id}"), flash).await
}

#[derive(Deserialize)]
pub struct EditKeyData {
    csrf_token: String,
    name: String,
    description: String,
    requests: u64,
    period: String,
}

pub async fn edit_key(
    AdminSession { session, .. }: AdminSession,
    State(dev_manager): State<Arc<DeveloperManager>>,
    Path((dev_id, key_id)): Path<(i64, i64)>,
    Form(data): Form<EditKeyData>,
) -> WebResult<Redirect> {
    verify_csrf_token(&session, &data.csrf_token).await?;

    let request_reload_ms = parse_reload_ms(&data.period, data.requests)?;

    let flash = match dev_manager.edit_key(key_id, &data.name, &data.description, request_reload_ms).await {
        Ok(_) => Flash::success("Successfully updated key"),
        Err(e) => Flash::from_dev_error(e)?,
    };

    redirect_with_flash(&session, &format!("/dashboard/admin/developers/{dev_id}/keys/{key_id}"), flash).await
}

#[derive(Deserialize)]
pub struct DeleteKeyData {
    csrf_token: String,
}

pub async fn delete_key(
    AdminSession { session, .. }: AdminSession,
    State(dev_manager): State<Arc<DeveloperManager>>,
    Path((dev_id, key_id)): Path<(i64, i64)>,
    Form(data): Form<DeleteKeyData>,
) -> WebResult<Redirect> {
    verify_csrf_token(&session, &data.csrf_token).await?;

    let flash = match dev_manager.delete_key(key_id).await {
        Ok(_) => Flash::success("Successfully deleted key"),
        Err(e) => Flash::from_dev_error(e)?,
    };

    redirect_with_flash(&session, &format!("/dashboard/admin/developers/{dev_id}"), flash).await
}

#[derive(Deserialize)]
pub struct RotateKeyData {
    csrf_token: String,
}

pub async fn rotate_key(
    AdminSession { session, .. }: AdminSession,
    State(dev_manager): State<Arc<DeveloperManager>>,
    Path((dev_id, key_id)): Path<(i64, i64)>,
    Form(data): Form<RotateKeyData>,
) -> WebResult<Redirect> {
    verify_csrf_token(&session, &data.csrf_token).await?;

    let new_secret = generate_secret();
    let flash = match dev_manager.rotate_key(dev_id, key_id, &new_secret).await {
        Ok(key) => Flash::success(format!("Key rotated: \"{key}\"")),
        Err(e) => Flash::from_dev_error(e)?,
    };

    redirect_with_flash(&session, &format!("/dashboard/admin/developers/{dev_id}"), flash).await
}

fn parse_reload_ms(period: &str, requests: u64) -> Result<u64, WebError> {
    let period_ms = match period {
        "second" => 1000,
        "minute" => 60_000,
        "hour" => 3_600_000,
        "day" => 86_400_000,
        _ => return Err(WebError::BadRequest("Invalid period".to_string())),
    };
    Ok(period_ms / requests)
}

fn generate_secret() -> String {
    Uuid::new_v4().to_string()
}
