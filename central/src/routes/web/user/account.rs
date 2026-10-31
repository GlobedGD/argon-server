use std::sync::Arc;

use askama::Template;
use axum::{
    Form,
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use shared::message::GDAccountData;
use tower_sessions::Session;

use crate::{
    db::repository::USER_SESSION_DATA_KEY,
    routes::web::{
        Html,
        csrf::{csrf_token, verify_csrf_token},
        user::{
            error::{WebError, WebResult},
            session::UserSession,
        },
    },
    user::{User, UserManager},
};

#[derive(Template)]
#[template(path = "account.html")]
pub struct AccountTemplate {
    me: User,
    csrf_token: String,
}

pub async fn get_account(UserSession { user, session }: UserSession) -> WebResult<Html<AccountTemplate>> {
    Ok(Html(AccountTemplate {
        me: user,
        csrf_token: csrf_token(&session).await?,
    }))
}

#[derive(Deserialize)]
pub struct LoginQuery {
    token: Option<String>,
}

#[derive(Template, Default)]
#[template(path = "login.html")]
pub struct LoginTemplate {}

pub async fn get_login(
    State(manager): State<Arc<UserManager>>,
    Query(query): Query<LoginQuery>,
    session: Session,
) -> WebResult<Response> {
    // if one-time access code is passed in the query, use it to log in
    if let Some(token) = query.token {
        match manager.verify_web_access_code(&token) {
            Some(account_data) => {
                // successful auth
                session.cycle_id().await?;
                session.insert(USER_SESSION_DATA_KEY, account_data).await?;
                return Ok(Redirect::to("/account").into_response());
            }

            None => return Err(WebError::AccessCodeExpired),
        }
    }

    if session.get::<GDAccountData>(USER_SESSION_DATA_KEY).await?.is_some() {
        return Ok(Redirect::to("/account").into_response());
    }

    // render the login page
    Ok(Html(LoginTemplate {}).into_response())
}

#[derive(Deserialize)]
pub struct LogoutData {
    csrf_token: String,
}

pub async fn logout(session: Session, Form(data): Form<LogoutData>) -> WebResult<Redirect> {
    verify_csrf_token(&session, &data.csrf_token).await?;

    session.flush().await?;
    Ok(Redirect::to("/login"))
}
