//! Unified Policy Builder — One system for all personas
//!
//! Permission tiers (enforced per-endpoint):
//!   PlatformAdmin   = tenant_id='system' + role owner/admin
//!   TenantAdmin     = role owner/admin
//!   TenantDeveloper = role owner/admin/developer/member (all authenticated)
//!
//! Route layout:
//!   /templates/*          → templates.rs
//!   /actions/*            → actions.rs
//!   /configs/*            → configs.rs + groups.rs + rules.rs + conditions.rs
//!   /configs/:id/preview  → compile.rs
//!   /configs/:id/simulate → compile.rs
//!   /configs/:id/compile  → compile.rs
//!   /configs/:id/activate → compile.rs
//!   /configs/:id/versions → versions.rs
//!   /configs/:id/audit    → audit.rs

use axum::{
    routing::{get, post, put},
    Router,
};
use crate::state::AppState;

pub mod types;
pub mod permissions;
pub mod templates;
pub mod actions;
pub mod configs;
pub mod groups;
pub mod rules;
pub mod conditions;
pub mod compile;
pub mod versions;
pub mod audit;
pub mod compiler;

pub fn router() -> Router<AppState> {
    Router::new()
        // ── Templates ──────────────────────────────────────────────────────
        .route("/templates",
            get(templates::list_templates)
            .post(templates::create_template))
        .route("/templates/:slug",
            get(templates::get_template)
            .put(templates::update_template)
            .delete(templates::deprecate_template))
        .route("/templates/:slug/conditions",
            get(templates::list_supported_conditions))

        // ── Condition Types catalog ────────────────────────────────────────
        .route("/condition-types",
            get(conditions::list_condition_types))

        // ── Actions ────────────────────────────────────────────────────────
        .route("/actions",
            get(actions::list_actions)
            .post(actions::create_action))
        .route("/actions/:id",
            put(actions::update_action)
            .delete(actions::delete_action))

        // ── Configs ────────────────────────────────────────────────────────
        .route("/configs",
            get(configs::list_configs)
            .post(configs::create_config))
        .route("/configs/:id",
            get(configs::get_config)
            .put(configs::update_config)
            .delete(configs::archive_config))

        // ── Rule Groups ────────────────────────────────────────────────────
        .route("/configs/:id/groups",
            post(groups::add_group))
        .route("/configs/:id/groups/reorder",
            post(groups::reorder_groups))
        .route("/configs/:id/groups/:gid",
            put(groups::update_group)
            .delete(groups::remove_group))

        // ── Rules within Groups ────────────────────────────────────────────
        .route("/configs/:id/groups/:gid/rules",
            post(rules::add_rule))
        .route("/configs/:id/groups/:gid/rules/reorder",
            post(rules::reorder_rules))
        .route("/configs/:id/groups/:gid/rules/:rid",
            put(rules::update_rule)
            .delete(rules::remove_rule))

        // ── Conditions on Rules ────────────────────────────────────────────
        .route("/configs/:id/groups/:gid/rules/:rid/conditions",
            post(conditions::add_condition))
        .route("/configs/:id/groups/:gid/rules/:rid/conditions/reorder",
            post(conditions::reorder_conditions))
        .route("/configs/:id/groups/:gid/rules/:rid/conditions/:cid",
            put(conditions::update_condition)
            .delete(conditions::remove_condition))

        // ── Compile, Preview, Simulate, Activate ──────────────────────────
        .route("/configs/:id/preview",
            get(compile::preview_config))
        .route("/configs/:id/simulate",
            post(compile::simulate_config))
        .route("/configs/:id/compile",
            post(compile::compile_config))
        .route("/configs/:id/activate",
            post(compile::activate_config))

        // ── Version History & Rollback ─────────────────────────────────────
        .route("/configs/:id/versions",
            get(versions::list_versions))
        .route("/configs/:id/versions/:vid",
            get(versions::get_version))
        .route("/configs/:id/versions/:vid/rollback",
            post(versions::rollback_version))
        .route("/configs/:id/versions/:vid/diff",
            post(versions::diff_versions))
        .route("/configs/:id/versions/:vid/export-ast",
            get(versions::export_version_ast))

        // ── Raw AST Import/Export (developer tier) ─────────────────────────
        .route("/configs/:id/import-ast",
            post(compile::import_ast))
        .route("/configs/:id/export-ast",
            get(compile::export_ast))

        // ── Audit ──────────────────────────────────────────────────────────
        .route("/configs/:id/audit",
            get(audit::get_config_audit))
        .route("/audit",
            get(audit::get_tenant_audit))
}
