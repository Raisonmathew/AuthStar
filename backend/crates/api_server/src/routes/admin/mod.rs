pub mod apps;
pub mod auth;
pub mod policies;
pub mod audit;
pub mod sso_mgmt;

use axum::Router;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .nest("/apps", apps::router())
        .nest("/auth", auth::router())
        .nest("/policies", policies::router())
        .nest("/audit", audit::router())
        .nest("/sso", sso_mgmt::router())
}
