use std::{sync::Arc, time::Duration};

use askama::Template;
use axum::{
    Router,
    extract::{Path, State},
    response::Redirect,
    routing::{get, post},
};
// Note: axum::Form does not support forms with repeated keys, axum_extra does
use axum_extra::extract::Form;
use serde::Deserialize;
use uuid::Uuid;

use super::super::{
    error::{WebError, WebResult, flash_from_dev_error},
    session::AdminSession,
};
use crate::{
    developer::{DevApiKey, DevScope, DevScopeChoice, Developer, DeveloperManager},
    routes::web::{
        Html,
        csrf::{csrf_token, verify_csrf_token},
        flash::{Flash, redirect_with_flash, take_flash},
    },
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/developers/{id}/keys", post(create_key))
        .route("/developers/{id}/keys/{key_id}", get(get_key).post(edit_key))
        .route("/developers/{id}/keys/{key_id}/delete", post(delete_key))
        .route("/developers/{id}/keys/{key_id}/rotate", post(rotate_key))
}

#[derive(Template)]
#[template(path = "dev/admin/key.html")]
pub struct AdminKeyPageTemplate {
    me: Developer,
    key: DevApiKey,
    developer: Developer,
    csrf_token: String,
    flash: Option<Flash>,
    scopes: Vec<DevScopeChoice>,
}

pub async fn get_key(
    AdminSession { dev, session }: AdminSession,
    State(dev_manager): State<Arc<DeveloperManager>>,
    Path((dev_id, key_id)): Path<(i64, i64)>,
) -> WebResult<Html<AdminKeyPageTemplate>> {
    let Some(key) = dev_manager.get_developer_key(dev_id, key_id).await? else {
        return Err(WebError::NotFound);
    };

    let scopes = parse_scopes_str(&key.scope)?;

    Ok(Html(AdminKeyPageTemplate {
        me: dev,
        key,
        developer: dev_manager.get_developer(dev_id).await?.ok_or(WebError::NotFound)?,
        csrf_token: csrf_token(&session).await?,
        flash: take_flash(&session).await?,
        scopes: DevScope::choices(&scopes),
    }))
}

#[derive(Deserialize)]
pub struct CreateKeyData {
    csrf_token: String,
    name: String,
    description: String,
    requests: u64,
    period: String,
    #[serde(default)]
    scopes: Vec<String>,
}

pub async fn create_key(
    AdminSession { session, .. }: AdminSession,
    State(dev_manager): State<Arc<DeveloperManager>>,
    Path(dev_id): Path<i64>,
    Form(data): Form<CreateKeyData>,
) -> WebResult<Redirect> {
    verify_csrf_token(&session, &data.csrf_token).await?;

    let request_reload_ns = parse_reload_ns(&data.period, data.requests)?;
    let scopes = parse_and_join_scopes(&data.scopes)?;

    let flash =
        match dev_manager.create_key(dev_id, &data.name, &data.description, &scopes, request_reload_ns).await
        {
            Ok(_) => Flash::success("Successfully created key"),
            Err(e) => flash_from_dev_error(e)?,
        };

    redirect_with_flash(&session, &format!("/dev/admin/developers/{dev_id}"), flash).await
}

#[derive(Deserialize)]
pub struct EditKeyData {
    csrf_token: String,
    name: String,
    description: String,
    requests: u64,
    period: String,
    #[serde(default)]
    scopes: Vec<String>,
}

pub async fn edit_key(
    AdminSession { session, .. }: AdminSession,
    State(dev_manager): State<Arc<DeveloperManager>>,
    Path((dev_id, key_id)): Path<(i64, i64)>,
    Form(data): Form<EditKeyData>,
) -> WebResult<Redirect> {
    verify_csrf_token(&session, &data.csrf_token).await?;

    let request_reload_ns = parse_reload_ns(&data.period, data.requests)?;
    let scopes = parse_and_join_scopes(&data.scopes)?;

    let flash =
        match dev_manager.edit_key(key_id, &data.name, &data.description, &scopes, request_reload_ns).await {
            Ok(_) => Flash::success("Successfully updated key"),
            Err(e) => flash_from_dev_error(e)?,
        };

    redirect_with_flash(&session, &format!("/dev/admin/developers/{dev_id}/keys/{key_id}"), flash).await
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
        Err(e) => flash_from_dev_error(e)?,
    };

    redirect_with_flash(&session, &format!("/dev/admin/developers/{dev_id}"), flash).await
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
        Err(e) => flash_from_dev_error(e)?,
    };

    redirect_with_flash(&session, &format!("/dev/admin/developers/{dev_id}"), flash).await
}

fn parse_reload_ns(period: &str, requests: u64) -> Result<u64, WebError> {
    let period_s = match period {
        "second" => 1,
        "minute" => 60,
        "hour" => 3600,
        "day" => 86400,
        _ => return Err(WebError::BadRequest("Invalid period".to_string())),
    };

    let period_ns = Duration::from_secs(period_s).as_nanos() as u64;
    Ok(period_ns / requests.max(1))
}

fn generate_secret() -> String {
    Uuid::new_v4().to_string()
}

fn parse_scopes(scopes: &[String]) -> Result<Vec<DevScope>, WebError> {
    // convert and validate all scopes
    let scopes = scopes.iter().map(|k| DevScope::from_str(k)).collect::<Option<Vec<_>>>();
    scopes.ok_or_else(|| WebError::BadRequest("invalid choice for devscope".to_owned()))
}

fn parse_scopes_str(scopes: &str) -> Result<Vec<DevScope>, WebError> {
    let scopes = scopes.split(',').map(DevScope::from_str).collect::<Option<Vec<_>>>();
    scopes.ok_or_else(|| WebError::BadRequest("invalid choice for devscope".to_owned()))
}

fn join_scopes(scopes: &[DevScope]) -> String {
    itertools::join(scopes.iter().map(|s| s.to_str()), ",")
}

fn parse_and_join_scopes(scopes: &[String]) -> Result<String, WebError> {
    let scopes = parse_scopes(scopes)?;
    Ok(join_scopes(&scopes))
}
