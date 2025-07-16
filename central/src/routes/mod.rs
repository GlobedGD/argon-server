use rocket::{Route, get, routes};

mod admin;
mod api_error;
mod client;
mod routes_util;
mod status;
mod validation;
mod websockets;

#[get("/")]
pub async fn index() -> &'static str {
    "There is nothing interesting here. Not yet, at least."
}

pub fn build_v1_routes() -> Vec<Route> {
    routes![
        admin::api_create_token,
        admin::api_tokens,
        admin::dashboard,
        admin::login,
        admin::logout,
        status::status,
        client::challenge_start,
        client::challenge_restart,
        client::challenge_verify,
        client::challenge_verify_poll,
        validation::validation_check,
        validation::validation_check_many,
        validation::validation_check_strong,
        validation::validation_check_strong_alias,
        validation::validation_check_strong_many,
        validation::validation_check_data_many,
        websockets::ws_handler,
    ]
}
