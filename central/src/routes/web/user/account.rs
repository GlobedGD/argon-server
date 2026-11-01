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
    discord::client::{DiscordClient, DiscordUserDataFull, OauthFlowType},
    routes::web::{
        Html,
        csrf::{csrf_token, verify_csrf_token},
        flash::{Flash, redirect_with_flash, take_flash},
        user::{
            error::{WebError, WebResult},
            session::UserSession,
        },
    },
    user::{User, UserManager},
};

pub struct DiscordView {
    pub id: i64,
    pub username: String,
    pub avatar_url: String,
    pub last_sync: String,
}

impl From<DiscordUserDataFull> for DiscordView {
    fn from(data: DiscordUserDataFull) -> Self {
        Self {
            id: data.id,
            username: data.username,
            avatar_url: data.avatar_url,
            last_sync: data.last_sync_time.format("%Y-%m-%d %H:%M").to_string(),
        }
    }
}

#[derive(Template)]
#[template(path = "account.html")]
pub struct AccountTemplate {
    me: User,
    csrf_token: String,
    flash: Option<Flash>,
    discord: Option<DiscordView>,
    discord_enabled: bool,
}

pub async fn get_account(
    UserSession { user, session }: UserSession,
    State(user_manager): State<Arc<UserManager>>,
) -> WebResult<Html<AccountTemplate>> {
    let discord_enabled = user_manager.discord_client().is_some();
    let discord = if discord_enabled {
        user_manager.get_discord_data_ext(user.account_id).await?.map(Into::into)
    } else {
        None
    };

    Ok(Html(AccountTemplate {
        me: user,
        csrf_token: csrf_token(&session).await?,
        flash: take_flash(&session).await?,
        discord,
        discord_enabled,
    }))
}

#[derive(Deserialize)]
pub struct ActionData {
    csrf_token: String,
}

pub async fn enable_advanced_auth(
    UserSession { session, user }: UserSession,
    State(user_manager): State<Arc<UserManager>>,
    Form(data): Form<ActionData>,
) -> WebResult<Redirect> {
    verify_csrf_token(&session, &data.csrf_token).await?;

    user_manager.enable_advanced_auth(user.account_id).await?;

    Ok(Redirect::to("/login"))
}

pub async fn rotate_advanced_auth(
    UserSession { session, user }: UserSession,
    State(user_manager): State<Arc<UserManager>>,
    Form(data): Form<ActionData>,
) -> WebResult<Redirect> {
    verify_csrf_token(&session, &data.csrf_token).await?;

    user_manager.reset_tokens_and_sessions_for(user.account_id).await?;

    Ok(Redirect::to("/login"))
}

pub async fn link_discord(
    UserSession { session, user }: UserSession,
    State(discord_client): State<Arc<DiscordClient>>,
    Form(data): Form<ActionData>,
) -> WebResult<Redirect> {
    verify_csrf_token(&session, &data.csrf_token).await?;

    let redirect_url =
        discord_client.begin_oauth_flow(user.account_id, OauthFlowType::Link, Some("/account".to_owned()));

    Ok(Redirect::to(&redirect_url))
}

pub async fn unlink_discord(
    UserSession { session, user }: UserSession,
    State(user_manager): State<Arc<UserManager>>,
    Form(data): Form<ActionData>,
) -> WebResult<Redirect> {
    verify_csrf_token(&session, &data.csrf_token).await?;

    let unlinked = user_manager.unlink_discord_user(user.account_id).await?;
    if unlinked {
        Ok(Redirect::to("/account"))
    } else {
        redirect_with_flash(&session, "/account", Flash::error("Not linked to a Discord account")).await
    }
}

pub async fn sync_discord(
    UserSession { session, user }: UserSession,
    State(discord_client): State<Arc<DiscordClient>>,
    Form(data): Form<ActionData>,
) -> WebResult<Redirect> {
    verify_csrf_token(&session, &data.csrf_token).await?;

    let redirect_url =
        discord_client.begin_oauth_flow(user.account_id, OauthFlowType::Sync, Some("/account".to_owned()));

    Ok(Redirect::to(&redirect_url))
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
