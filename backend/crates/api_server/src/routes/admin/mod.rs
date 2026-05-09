pub mod apps;
pub mod audit;
pub mod auth;
pub mod client_scopes;
pub mod events;
pub mod groups;
pub mod ldap;
pub mod scim;
pub mod security;
pub mod sessions;
pub mod sso_mgmt;
pub mod users;
pub mod whoami;

use crate::state::AppState;
use axum::Router;

pub fn router() -> Router<AppState> {
    Router::new()
        .nest("/apps", apps::router())
        .nest("/auth", auth::router())
        .nest("/audit", audit::router())
        .nest("/client-scopes", client_scopes::router())
        .nest("/events", events::router())
        .nest("/groups", groups::router())
        .nest("/ldap", ldap::router())
        .nest("/scim", scim::admin_router())
        .nest("/security", security::router())
        .nest("/sessions", sessions::router())
        .nest("/sso", sso_mgmt::router())
        .nest("/users", users::router())
        .nest("/whoami", whoami::router())
}
