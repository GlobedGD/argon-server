use std::sync::Arc;

use askama::Template;
use axum::{
    Form, Router,
    extract::{Path, Query, State},
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
    developer::{DEFAULT_SCOPES, DevApiKey, DevScope, DevScopeChoice, Developer, DeveloperManager},
    discord::client::DiscordView,
    routes::web::{
        Html,
        csrf::{csrf_token, verify_csrf_token},
        flash::{Flash, redirect_with_flash, take_flash},
    },
    state::AppState,
    user::{User, UserManager},
};

pub mod keys;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(get_admin))
        .route("/developers", post(create_developer))
        .route("/developers/{id}", get(get_developer))
        .route("/developers/{id}/reset", post(reset_developer_password))
        .route("/developers/{id}/delete", post(delete_developer))
        .route("/users/search", get(search_users))
        .route("/users/{id}", get(get_user))
        .route("/users/{id}/discord/unlink", post(unlink_user_discord))
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
        // create_developer validates allowed chars so no html injection can happen here
        Ok(other) => Flash::success_html(format!(
            "Created developer {}, temporary password: <code>{}</code>",
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
        Ok(()) => {
            Flash::success_html(format!("Reset successful, new password: <code>{temp_password}</code>"))
        }
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
    scopes: Vec<DevScopeChoice>,
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
        scopes: DevScope::choices(DEFAULT_SCOPES),
    }))
}

fn generate_password() -> String {
    rand::rng().sample_iter(&Alphanumeric).take(16).map(char::from).collect::<String>()
}

#[derive(Deserialize)]
pub struct SearchUsersData {
    query: String,
}

pub async fn search_users(
    AdminSession { session, .. }: AdminSession,
    State(user_manager): State<Arc<UserManager>>,
    Query(data): Query<SearchUsersData>,
) -> WebResult<Redirect> {
    match user_manager.find_user(&data.query).await? {
        Some(user) => Ok(Redirect::to(&format!("/dev/admin/users/{}", user.account_id))),
        None => redirect_with_flash(&session, "/dev/admin", Flash::error("User not found")).await,
    }
}

#[derive(Template)]
#[template(path = "dev/admin/user.html")]
pub struct AdminUserPageTemplate {
    me: Developer,
    csrf_token: String,

    user: User,
    discord_enabled: bool,
    discord_user: Option<DiscordView>,
    flash: Option<Flash>,
}

pub async fn get_user(
    AdminSession {
        session,
        dev: me,
    }: AdminSession,
    State(user_manager): State<Arc<UserManager>>,
    Path(id): Path<i32>,
) -> WebResult<Html<AdminUserPageTemplate>> {
    let Some(user) = user_manager.get_user(id).await? else {
        return Err(WebError::NotFound);
    };

    let discord_enabled = user_manager.discord_enabled();
    let discord_user = user_manager.get_discord_data_ext(user.account_id).await?;

    Ok(Html(AdminUserPageTemplate {
        me,
        user,
        discord_enabled,
        discord_user: discord_user.map(Into::into),
        csrf_token: csrf_token(&session).await?,
        flash: take_flash(&session).await?,
    }))
}

#[derive(Deserialize)]
pub struct UnlinkUserDiscordData {
    csrf_token: String,
}

pub async fn unlink_user_discord(
    AdminSession { session, .. }: AdminSession,
    State(user_manager): State<Arc<UserManager>>,
    Path(id): Path<i32>,
    Form(data): Form<UnlinkUserDiscordData>,
) -> WebResult<Redirect> {
    verify_csrf_token(&session, &data.csrf_token).await?;

    let Some(user) = user_manager.get_user(id).await? else {
        return Err(WebError::NotFound);
    };

    if !user_manager.unlink_discord_user(user.account_id).await? {
        return Err(WebError::BadRequest("User does not have a linked Discord account".to_owned()));
    }

    redirect_with_flash(
        &session,
        &format!("/dev/admin/users/{}", id),
        Flash::success("Discord account unlinked"),
    )
    .await
}
