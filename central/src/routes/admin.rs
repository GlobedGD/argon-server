use std::sync::Arc;

use rocket::http::{Cookie, CookieJar, Status};
use rocket::request::{FromRequest, Outcome};
use rocket::response::{Flash, Redirect};
use rocket::serde::json::Json;
use rocket::{Request, State, get, post};

use super::api_error::{ApiError, ApiResult};
use crate::api_token_manager::ApiTokenManager;
use crate::database::{ApiToken, ArgonDb};
use crate::node_handler::constant_time_compare;
use crate::state::ServerState;

pub struct AdminTokenGuard;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AdminTokenGuard {
    type Error = ApiError<false>;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let cookies = request.cookies();
        if cookies.get_private("admin_token").is_some() {
            Outcome::Success(AdminTokenGuard)
        } else {
            Outcome::Error((
                Status::Unauthorized,
                ApiError::unauthorized("admin token required"),
            ))
        }
    }
}

#[post("/admin/api/create-token?<name>&<owner>&<description>&<perday>&<perhour>")]
pub async fn api_create_token(
    db: ArgonDb,
    token_manager: &State<Arc<ApiTokenManager>>,
    name: &str,
    owner: &str,
    description: &str,
    perday: i32,
    perhour: i32,
    _guard: AdminTokenGuard,
) -> ApiResult<String, false> {
    use crate::database::NewApiToken;

    token_manager
        .generate_token(
            &db,
            NewApiToken {
                name,
                owner,
                description,
                validations_per_day: perday,
                validations_per_hour: perhour,
            },
        )
        .await
        .map_err(|e| ApiError::internal_server_error(e.to_string()))
}

#[get("/admin/api/tokens")]
pub async fn api_tokens(
    db: ArgonDb,
    state_: &State<ServerState>,
    _guard: AdminTokenGuard,
) -> ApiResult<Json<Vec<ApiToken>>, false> {
    let state = state_.state_read().await;
    let tokens = state.api_token_manager.get_all_tokens(&db).await?;

    Ok(Json(tokens))
}

#[get("/admin/dash")]
pub async fn dashboard(_db: ArgonDb, _state: &State<ServerState>, _guard: AdminTokenGuard) -> String {
    "Well this is the dashboard".to_string()
}

#[post("/admin/login", data = "<data>")]
pub async fn login(
    state_: &State<ServerState>,
    cookies: &CookieJar<'_>,
    data: String,
) -> ApiResult<Redirect, false> {
    let state = state_.state_read().await;

    let correct = constant_time_compare(&state.config.secret_key, &data);
    if !correct {
        return Err(ApiError::unauthorized("invalid credentials"));
    }

    cookies.add_private(Cookie::build(("admin_token", "true")).build());

    Ok(Redirect::to("/admin/dash"))
}

#[post("/admin/logout")]
pub async fn logout(cookies: &CookieJar<'_>) -> Flash<Redirect> {
    cookies.remove_private("admin_token");
    Flash::success(Redirect::to("/admin/login"), "You have been logged out.")
}
