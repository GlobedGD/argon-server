use cot::{
    App,
    router::{Route, Router},
};

mod account;
mod check;
mod status;

pub struct ApiApp;

impl App for ApiApp {
    fn name(&self) -> &str {
        "api"
    }

    fn router(&self) -> Router {
        Router::with_urls([
            Route::with_handler_and_name("/status", status::status, "status"),
            Route::with_handler_and_name("/check", check::check, "check"),
            Route::with_handler_and_name("/account/create", account::create, "account_create"),
            Route::with_handler_and_name("/account/verify", account::verify, "account_verify"),
        ])
    }
}

impl ApiApp {
    pub fn new() -> Self {
        Self
    }
}
