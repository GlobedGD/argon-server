use axum::Router;
use utoipa::{
    OpenApi,
    openapi::{
        self, Components,
        security::{Http, HttpAuthScheme, SecurityScheme},
    },
};
use utoipa_swagger_ui::SwaggerUi;

use crate::state::AppState;

use super::error::ErrorBody;

#[derive(utoipa::OpenApi)]
#[openapi(
    info(
        title = "Argon API",
        version = env!("CARGO_PKG_VERSION"),
        description = "API for authenticating Geometry Dash accounts"
    ),
    tags(
        (name = "token", description = "Token validation"),
        (name = "account", description = "Authentication and token issuing (note: this is primarily for the client)"),
        (name = "discord", description = "Discord account linking"),
        (name = "misc", description = "Miscellaneous endpoints")
    ),
    components(schemas(ErrorBody)),
)]
pub struct ApiDoc;

pub fn document(operations: openapi::OpenApi) -> openapi::OpenApi {
    let mut doc = ApiDoc::openapi();
    doc.merge(operations);

    let components = doc.components.get_or_insert_with(Components::new);
    components.add_security_scheme(
        "bearer_auth",
        SecurityScheme::Http(Http::builder().scheme(HttpAuthScheme::Bearer).bearer_format("JWT").build()),
    );
    components.add_security_scheme(
        "api_key",
        SecurityScheme::Http(
            Http::builder().scheme(HttpAuthScheme::Bearer).description(Some("Developer API key")).build(),
        ),
    );

    doc
}

/// Serves the documentation UI and the raw spec for the given set of operations.
pub fn router(operations: openapi::OpenApi) -> Router<AppState> {
    let doc = document(operations);
    Router::new().merge(SwaggerUi::new("/docs").url("/v2/openapi.json", doc))
}
