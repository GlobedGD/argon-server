use std::sync::Arc;

use askama::Template;
use axum::{
    Form, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::Deserialize;
use tower_cookies::Cookies;
use tower_sessions::Session;
use tracing::error;
use uuid::Uuid;

use super::{
    error::{WebResult, flash_from_dev_error},
    session::DevSession,
};
use crate::{
    db::repository::DEV_SESSION_ID_KEY,
    developer::{DevApiKey, DevError, Developer, DeveloperManager, LoginError},
    routes::{
        util::rate_limited,
        web::{
            Html,
            csrf::{csrf_token, rotate_csrf_token, verify_csrf_token},
            dev::error::WebError,
            flash::{Flash, redirect_with_flash, take_flash},
        },
    },
    state::AppState,
    util::CsrfCookieManager,
};

pub fn router(state: &AppState) -> Router<AppState> {
    Router::new()
        .route("/", get(get_dashboard))
        .route("/login", get(get_login))
        // rate limit /login
        .merge(rate_limited(Router::new().route("/login", post(post_login)), state.clone(), 5, 1))
        .route("/logout", post(post_logout))
        .route("/setup", get(setup).post(post_setup))
        .route("/password", get(get_change_password).post(change_password))
        .route("/keys/{id}/rotate", post(rotate_key))
}

#[derive(Template)]
#[template(path = "dev/index.html")]
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
        return Ok(Redirect::to("/dev/setup").into_response());
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
#[template(path = "dev/setup.html")]
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
        return Ok(Redirect::to("/dev"));
    }

    match dev_manager.set_developer_password(dev.id, &data.password, false).await {
        Ok(()) => {
            // this kills all sessions including the current one, so make the user log in again
            session.flush().await?;

            Ok(Redirect::to("/dev/login"))
        }

        Err(e) => redirect_with_flash(&session, "/dev/setup", password_setup_err_msg(&e)).await,
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
#[template(path = "dev/login.html")]
pub struct LoginTemplate {
    csrf_token: String,
    username: String,
    error: Option<String>,
}

pub async fn get_login(
    session: Session,
    cookies: Cookies,
    State(csrf): State<Arc<CsrfCookieManager>>,
) -> WebResult<Response> {
    if session.get::<i64>(DEV_SESSION_ID_KEY).await?.is_some() {
        return Ok(Redirect::to("/dev").into_response());
    }

    // set secure csrf token
    let csrf_token = csrf.token(&cookies);

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
    State(csrf): State<Arc<CsrfCookieManager>>,
    cookies: Cookies,
    Form(data): Form<LoginData>,
) -> WebResult<Response> {
    if !csrf.verify(&cookies, &data.csrf_token) {
        return Err(WebError::Csrf);
    }

    match dev_manager.handle_login(&data.username, &data.password).await {
        Ok(dev) => {
            session.cycle_id().await?;
            session.insert(DEV_SESSION_ID_KEY, dev.id).await?;

            // generate new csrf token
            rotate_csrf_token(&session).await?;

            Ok(Redirect::to("/dev").into_response())
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
    Ok(Redirect::to("/dev/login"))
}

#[derive(Template)]
#[template(path = "dev/change_password.html")]
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
        Ok(()) => Ok(Redirect::to("/dev")),

        Err(e) => redirect_with_flash(&session, "/dev/password", password_setup_err_msg(&e)).await,
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
        Err(e) => flash_from_dev_error(e)?,
    };

    redirect_with_flash(&session, "/dev", flash).await
}

fn generate_secret() -> String {
    Uuid::new_v4().to_string()
}
