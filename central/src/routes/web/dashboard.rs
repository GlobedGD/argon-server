use std::sync::Arc;

use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use tower_sessions::Session;
use tracing::error;
use uuid::Uuid;

use crate::{
    developer::{DevApiKey, DevError, Developer, DeveloperManager, LoginError},
    routes::web::{
        error::WebResult,
        util::{
            DevSession, Flash, Html, csrf_token, redirect_with_flash, rotate_csrf_token, take_flash,
            verify_csrf_token,
        },
    },
};

#[derive(Template)]
#[template(path = "dashboard/index.html")]
pub struct DashboardTemplate {
    me: Developer,
    csrf_token: String,
    flash: Option<Flash>,
    keys: Vec<DevApiKey>,
}

pub async fn get_dashboard(
    DevSession { dev, session }: DevSession,
    State(dev_manager): State<Arc<DeveloperManager>>,
) -> WebResult<Response> {
    if !dev.setup_complete {
        return Ok(Redirect::to("/dashboard/setup").into_response());
    }

    let keys = dev_manager.get_developer_keys(dev.id).await?;

    Ok(Html(DashboardTemplate {
        me: dev,
        csrf_token: csrf_token(&session).await?,
        flash: take_flash(&session).await?,
        keys,
    })
    .into_response())
}

#[derive(Template)]
#[template(path = "dashboard/setup.html")]
pub struct SetupTemplate {
    me: Developer,
    csrf_token: String,
    flash: Option<Flash>,
}

pub async fn setup(DevSession { dev, session }: DevSession) -> WebResult<Response> {
    Ok(Html(SetupTemplate {
        me: dev,
        csrf_token: csrf_token(&session).await?,
        flash: take_flash(&session).await?,
    })
    .into_response())
}

#[derive(Deserialize)]
pub struct SetupData {
    password: String,
    csrf_token: String,
}

pub async fn post_setup(
    DevSession { dev, session }: DevSession,
    State(dev_manager): State<Arc<DeveloperManager>>,
    Form(data): Form<SetupData>,
) -> WebResult<Redirect> {
    verify_csrf_token(&session, &data.csrf_token).await?;

    if dev.setup_complete {
        return Ok(Redirect::to("/dashboard"));
    }

    match dev_manager.set_developer_password(dev.id, &data.password, false).await {
        Ok(()) => {
            // this kills all sessions including the current one, so make the user log in again
            session.flush().await?;

            Ok(Redirect::to("/dashboard/login"))
        }

        Err(e) => redirect_with_flash(&session, "/dashboard/setup", password_setup_err_msg(&e)).await,
    }
}

fn password_setup_err_msg(e: &DevError) -> Flash {
    Flash::error(match e {
        DevError::PasswordLength => "Password must be between 8 and 256 characters",
        DevError::Login(LoginError::InvalidCredentials) => "Incorrect old password",
        _ => "Internal server error",
    })
}

#[derive(Template, Default)]
#[template(path = "dashboard/login.html")]
pub struct LoginTemplate {
    csrf_token: String,
    username: String,
    error: Option<String>,
}

pub async fn get_login(session: Session) -> WebResult<Response> {
    if session.get::<i64>("dev_id").await?.is_some() {
        return Ok(Redirect::to("/dashboard").into_response());
    }

    // set csrf token
    let csrf_token = csrf_token(&session).await?;

    Ok(Html(LoginTemplate {
        csrf_token,
        ..Default::default()
    })
    .into_response())
}

#[derive(Deserialize)]
pub struct LoginData {
    username: String,
    password: String,
    csrf_token: String,
}

pub async fn post_login(
    session: Session,
    State(dev_manager): State<Arc<DeveloperManager>>,
    Form(data): Form<LoginData>,
) -> WebResult<Response> {
    verify_csrf_token(&session, &data.csrf_token).await?;

    match dev_manager.handle_login(&data.username, &data.password).await {
        Ok(dev) => {
            session.cycle_id().await?;
            session.insert("dev_id", dev.id).await?;

            // generate new csrf token
            rotate_csrf_token(&session).await?;

            Ok(Redirect::to("/dashboard").into_response())
        }

        Err(LoginError::InvalidCredentials) => Ok(login_error(
            &session,
            &data.username,
            StatusCode::UNAUTHORIZED,
            "Invalid username or password",
        )
        .await?),

        Err(e) => {
            error!("Login failed: {e}");

            Ok(login_error(
                &session,
                &data.username,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error, please try again",
            )
            .await?)
        }
    }
}

async fn login_error(
    session: &Session,
    username: &str,
    status: StatusCode,
    message: &str,
) -> WebResult<Response> {
    let csrf_token = csrf_token(session).await?;

    Ok((
        status,
        Html(LoginTemplate {
            csrf_token,
            username: username.to_owned(),
            error: Some(message.to_owned()),
        }),
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct LogoutData {
    csrf_token: String,
}

pub async fn post_logout(session: Session, Form(data): Form<LogoutData>) -> WebResult<Redirect> {
    verify_csrf_token(&session, &data.csrf_token).await?;

    session.flush().await?;
    Ok(Redirect::to("/dashboard/login"))
}

#[derive(Template)]
#[template(path = "dashboard/change_password.html")]
pub struct ChangePasswordTemplate {
    me: Developer,
    csrf_token: String,
    flash: Option<Flash>,
}

pub async fn get_change_password(DevSession { dev, session }: DevSession) -> WebResult<Response> {
    Ok(Html(ChangePasswordTemplate {
        me: dev,
        csrf_token: csrf_token(&session).await?,
        flash: take_flash(&session).await?,
    })
    .into_response())
}

#[derive(Deserialize)]
pub struct ChangePasswordData {
    old_password: String,
    new_password: String,
    csrf_token: String,
}

pub async fn change_password(
    DevSession { dev, session }: DevSession,
    State(dev_manager): State<Arc<DeveloperManager>>,
    Form(data): Form<ChangePasswordData>,
) -> WebResult<Redirect> {
    verify_csrf_token(&session, &data.csrf_token).await?;

    match dev_manager.handle_change_password(dev.id, &data.old_password, &data.new_password).await {
        Ok(()) => Ok(Redirect::to("/dashboard")),

        Err(e) => redirect_with_flash(&session, "/dashboard/password", password_setup_err_msg(&e)).await,
    }
}

#[derive(Deserialize)]
pub struct RotateKeyData {
    csrf_token: String,
}

pub async fn rotate_key(
    DevSession { dev, session }: DevSession,
    State(dev_manager): State<Arc<DeveloperManager>>,
    Path(key_id): Path<i64>,
    Form(data): Form<RotateKeyData>,
) -> WebResult<Redirect> {
    verify_csrf_token(&session, &data.csrf_token).await?;

    let new_secret = generate_secret();
    let flash = match dev_manager.rotate_key(dev.id, key_id, &new_secret).await {
        Ok(key) => Flash::success(format!("Key rotated: \"{key}\"")),
        Err(e) => Flash::from_dev_error(e)?,
    };

    redirect_with_flash(&session, "/dashboard", flash).await
}

fn generate_secret() -> String {
    Uuid::new_v4().to_string()
}
