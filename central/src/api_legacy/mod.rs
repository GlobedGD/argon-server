use cot::{
    App,
    router::{Route, Router},
};

pub struct LegacyApiApp;

impl App for LegacyApiApp {
    fn name(&self) -> &str {
        "api"
    }

    fn router(&self) -> Router {
        Router::with_urls([Route::with_handler_and_name("/", index, "index")])
    }
}

impl LegacyApiApp {
    pub fn new() -> Self {
        Self
    }
}
