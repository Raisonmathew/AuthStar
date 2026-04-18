pub mod apps;
pub mod audit;
pub mod auth;
pub mod events;
pub mod sessions;
pub mod sso_mgmt;

use crate::state::AppState;
use axum::Router;

pub fn router() -> Router<AppState> {
    Router::new()
        .nest("/apps", apps::router())
        .nest("/auth", auth::router())
        .nest("/audit", audit::router())
        .nest("/events", events::router())
        .nest("/sessions", sessions::router())
        .nest("/sso", sso_mgmt::router())
}
