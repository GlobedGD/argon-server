use rocket::{Route, get, routes};

mod api_error;
mod client;
mod dev;
mod routes_util;
mod status;

#[get("/")]
pub async fn index() -> &'static str {
    "There is nothing interesting here. Not yet, at least."
}

pub fn build_routes() -> Vec<Route> {
    routes![
        status::status,
        client::challenge_start,
        client::challenge_restart,
        client::challenge_verify,
        client::challenge_verify_poll,
        dev::validation_check,
        dev::validation_check_many,
        dev::validation_check_strong,
        dev::validation_check_strong_alias,
        dev::validation_check_strong_many,
    ]
}
