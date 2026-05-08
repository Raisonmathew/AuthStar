//! Admin LDAP / Active Directory connection management.
//!
//! Mounted under `/api/admin/v1/ldap` (JWT + EiaaAuthzLayer::AdminManage).
//!
//! Routes:
//! - `GET    /`            — list tenant LDAP connections
//! - `POST   /`            — create a new LDAP connection
//! - `PUT    /:id`         — update an existing LDAP connection
//! - `PATCH  /:id`         — partial update (enable/disable)
//! - `DELETE /:id`         — delete an LDAP connection
//! - `POST   /:id/test`    — test connectivity + bind credentials
//! - `POST   /:id/sync`    — trigger a full user synchronisation
//! - `GET    /:id/sync-runs` — list recent sync run history
//!
//! Security: bind_password is write-only — it is never returned in API responses.
//! It is stored encrypted at rest via AES-256-GCM (`state.ldap_encryption`).

use crate::services::audit_event_service::{event_types, RecordEventParams};
use crate::services::ldap_client;
use crate::state::AppState;
use auth_core::jwt::Claims;
use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    routing::{get, post, put},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use shared_types::{id_generator, AppError, Result};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_connections).post(create_connection))
        .route(
            "/:id",
            put(update_connection)
                .patch(patch_connection)
                .delete(delete_connection),
        )
        .route("/:id/test", post(test_connection))
        .route("/:id/sync", post(sync_connection))
        .route("/:id/sync-runs", get(list_sync_runs))
        .route("/:id/mappers", get(list_mappers).post(create_mapper))
        .route(
            "/:id/mappers/:mapper_id",
            put(update_mapper).delete(delete_mapper),
        )
}

// ── Periodic scheduler ─────────────────────────────────────────────────────────

/// Spawn a background task that triggers auto-sync for connections whose
/// `sync_interval_minutes > 0` and whose last sync is overdue.
/// Called once from `AppState::new_with_pool` after all services are initialized.
pub(crate) fn spawn_ldap_scheduler(
    db: sqlx::PgPool,
    enc: crate::services::factor_encryption::FactorEncryption,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;

            // Find connections whose next scheduled sync is now due.
            // A connection is due when:
            //   last_sync_at IS NULL   (never synced)
            //   OR last_sync_at + interval <= NOW()
            let due: Vec<(String, String, String, i32, i32)> = sqlx::query_as(
                "SELECT id, tenant_id, bind_password_ref, page_size, connection_timeout_secs \
                 FROM ldap_connections \
                 WHERE enabled = true \
                   AND sync_interval_minutes > 0 \
                   AND sync_status != 'syncing' \
                   AND (last_sync_at IS NULL \
                        OR last_sync_at + (sync_interval_minutes * INTERVAL '1 minute') <= NOW())",
            )
            .fetch_all(&db)
            .await
            .unwrap_or_default();
            for (conn_id, tenant_id, enc_pw, _page_size, timeout) in due {
                // Re-read the full row for this connection
                let row: Option<LdapConnectionRow> = {
                    let q = format!(
                        "SELECT {SELECT_COLS} FROM ldap_connections WHERE id = $1 AND tenant_id = $2"
                    );
                    sqlx::query_as::<_, LdapConnectionRow>(&q)
                        .bind(&conn_id)
                        .bind(&tenant_id)
                        .fetch_optional(&db)
                        .await
                        .unwrap_or(None)
                };
                let Some(cfg) = row else { continue };

                // Advisory lock — skip if already syncing
                let locked = sqlx::query_scalar::<_, bool>(
                    "SELECT pg_try_advisory_lock(hashtext($1)::int8)",
                )
                .bind(&conn_id)
                .fetch_one(&db)
                .await
                .unwrap_or(false);
                if !locked {
                    continue;
                }

                let bind_pw = enc.decrypt(&enc_pw).unwrap_or_default();
                let _ = timeout;

                // Create sync_run record
                let run_id = shared_types::id_generator::generate_id("ldsr");
                let _ = sqlx::query(
                    "INSERT INTO ldap_sync_runs (id, tenant_id, connection_id, status) \
                     VALUES ($1, $2, $3, 'running')",
                )
                .bind(&run_id)
                .bind(&tenant_id)
                .bind(&conn_id)
                .execute(&db)
                .await;

                let _ = sqlx::query(
                    "UPDATE ldap_connections SET sync_status = 'syncing', updated_at = NOW() \
                     WHERE id = $1",
                )
                .bind(&conn_id)
                .execute(&db)
                .await;

                let db2 = db.clone();
                let conn_id2 = conn_id.clone();
                let tenant_id2 = tenant_id.clone();
                let run_id2 = run_id.clone();
                tokio::spawn(async move {
                    let result =
                        run_sync_task(&db2, &conn_id2, &tenant_id2, &run_id2, &cfg, &bind_pw).await;
                    let _ = sqlx::query("SELECT pg_advisory_unlock(hashtext($1)::int8)")
                        .bind(&conn_id2)
                        .execute(&db2)
                        .await;
                    let final_status = if result.is_ok() { "idle" } else { "error" };
                    let _ = sqlx::query(
                        "UPDATE ldap_connections \
                         SET sync_status = $1, last_sync_at = NOW(), updated_at = NOW() \
                         WHERE id = $2",
                    )
                    .bind(final_status)
                    .bind(&conn_id2)
                    .execute(&db2)
                    .await;
                    if let Err(ref e) = result {
                        tracing::warn!(conn_id = conn_id2, error = e, "Scheduled LDAP sync failed");
                    } else {
                        tracing::info!(conn_id = conn_id2, "Scheduled LDAP sync completed");
                    }
                });
            }
        }
    });
}

// ── Internal DB row (includes bind_password_ref for operations) ───────────────

#[derive(sqlx::FromRow)]
struct LdapConnectionRow {
    id: String,
    name: String,
    host: String,
    port: i32,
    use_ssl: bool,
    bind_dn: String,
    bind_password_ref: String,
    base_dn: String,
    user_search_filter: String,
    attr_map_email: String,
    attr_map_name: String,
    enabled: bool,
    last_sync_at: Option<DateTime<Utc>>,
    sync_status: String,
    vendor: String,
    edit_mode: String,
    sync_interval_minutes: i32,
    connection_timeout_secs: i32,
    page_size: i32,
    // New in migration 064
    start_tls: bool,
    uuid_attr: String,
    username_attr: String,
    groups_dn: Option<String>,
    group_name_attr: String,
    group_object_class: String,
    group_membership_attr: String,
    group_membership_type: String,
    last_full_sync_at: Option<DateTime<Utc>>,
    last_delta_sync_at: Option<DateTime<Utc>>,
    last_manual_sync_at: Option<DateTime<Utc>>,
    trust_email: bool,
    skip_tls_verify: bool,
    read_timeout_secs: i32,
    memberof_attr: String,
    failover_hosts: String,
    search_scope: String,
}

// ── Public API type (bind_password intentionally OMITTED) ─────────────────────

#[derive(Serialize)]
struct LdapConnectionPublic {
    id: String,
    name: String,
    host: String,
    port: i32,
    use_ssl: bool,
    start_tls: bool,
    bind_dn: String,
    base_dn: String,
    user_search_filter: String,
    attr_map_email: String,
    attr_map_name: String,
    enabled: bool,
    last_sync_at: Option<DateTime<Utc>>,
    sync_status: String,
    vendor: String,
    edit_mode: String,
    sync_interval_minutes: i32,
    connection_timeout_secs: i32,
    page_size: i32,
    uuid_attr: String,
    username_attr: String,
    groups_dn: Option<String>,
    group_name_attr: String,
    group_object_class: String,
    group_membership_attr: String,
    group_membership_type: String,
    last_full_sync_at: Option<DateTime<Utc>>,
    last_delta_sync_at: Option<DateTime<Utc>>,
    trust_email: bool,
    skip_tls_verify: bool,
    read_timeout_secs: i32,
    memberof_attr: String,
    failover_hosts: String,
    search_scope: String,
}

impl From<LdapConnectionRow> for LdapConnectionPublic {
    fn from(r: LdapConnectionRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            host: r.host,
            port: r.port,
            use_ssl: r.use_ssl,
            start_tls: r.start_tls,
            bind_dn: r.bind_dn,
            base_dn: r.base_dn,
            user_search_filter: r.user_search_filter,
            attr_map_email: r.attr_map_email,
            attr_map_name: r.attr_map_name,
            enabled: r.enabled,
            last_sync_at: r.last_sync_at,
            sync_status: r.sync_status,
            vendor: r.vendor,
            edit_mode: r.edit_mode,
            sync_interval_minutes: r.sync_interval_minutes,
            connection_timeout_secs: r.connection_timeout_secs,
            page_size: r.page_size,
            uuid_attr: r.uuid_attr,
            username_attr: r.username_attr,
            groups_dn: r.groups_dn,
            group_name_attr: r.group_name_attr,
            group_object_class: r.group_object_class,
            group_membership_attr: r.group_membership_attr,
            group_membership_type: r.group_membership_type,
            last_full_sync_at: r.last_full_sync_at,
            last_delta_sync_at: r.last_delta_sync_at,
            trust_email: r.trust_email,
            skip_tls_verify: r.skip_tls_verify,
            read_timeout_secs: r.read_timeout_secs,
            memberof_attr: r.memberof_attr,
            failover_hosts: r.failover_hosts,
            search_scope: r.search_scope,
        }
    }
}

#[derive(Deserialize)]
struct CreateLdapRequest {
    name: String,
    host: String,
    #[serde(default = "default_port")]
    port: i32,
    #[serde(default)]
    use_ssl: bool,
    #[serde(default)]
    start_tls: bool,
    #[serde(default)]
    bind_dn: String,
    #[serde(default)]
    bind_password: String,
    #[serde(default)]
    base_dn: String,
    #[serde(default = "default_filter")]
    user_search_filter: String,
    #[serde(default = "default_email_attr")]
    attr_map_email: String,
    #[serde(default = "default_name_attr")]
    attr_map_name: String,
    #[serde(default = "default_enabled")]
    enabled: bool,
    #[serde(default = "default_vendor")]
    vendor: String,
    #[serde(default = "default_edit_mode")]
    edit_mode: String,
    #[serde(default)]
    sync_interval_minutes: i32,
    #[serde(default = "default_conn_timeout")]
    connection_timeout_secs: i32,
    #[serde(default = "default_page_size")]
    page_size: i32,
    #[serde(default = "default_uuid_attr")]
    uuid_attr: String,
    #[serde(default = "default_username_attr")]
    username_attr: String,
    #[serde(default)]
    groups_dn: Option<String>,
    #[serde(default = "default_group_name_attr")]
    group_name_attr: String,
    #[serde(default = "default_group_object_class")]
    group_object_class: String,
    #[serde(default = "default_group_membership_attr")]
    group_membership_attr: String,
    #[serde(default = "default_group_membership_type")]
    group_membership_type: String,
    #[serde(default = "default_trust_email")]
    trust_email: bool,
    #[serde(default)]
    skip_tls_verify: bool,
    #[serde(default = "default_read_timeout")]
    read_timeout_secs: i32,
    #[serde(default = "default_memberof_attr")]
    memberof_attr: String,
    #[serde(default = "default_failover_hosts")]
    failover_hosts: String,
    #[serde(default = "default_search_scope")]
    search_scope: String,
}

#[derive(Deserialize)]
struct UpdateLdapRequest {
    name: Option<String>,
    host: Option<String>,
    port: Option<i32>,
    use_ssl: Option<bool>,
    start_tls: Option<bool>,
    bind_dn: Option<String>,
    bind_password: Option<String>,
    base_dn: Option<String>,
    user_search_filter: Option<String>,
    attr_map_email: Option<String>,
    attr_map_name: Option<String>,
    enabled: Option<bool>,
    vendor: Option<String>,
    edit_mode: Option<String>,
    sync_interval_minutes: Option<i32>,
    connection_timeout_secs: Option<i32>,
    page_size: Option<i32>,
    uuid_attr: Option<String>,
    username_attr: Option<String>,
    groups_dn: Option<String>,
    group_name_attr: Option<String>,
    group_object_class: Option<String>,
    group_membership_attr: Option<String>,
    group_membership_type: Option<String>,
    trust_email: Option<bool>,
    skip_tls_verify: Option<bool>,
    read_timeout_secs: Option<i32>,
    memberof_attr: Option<String>,
    failover_hosts: Option<String>,
    search_scope: Option<String>,
}

fn default_port() -> i32 {
    389
}
fn default_filter() -> String {
    "(objectClass=person)".into()
}
fn default_email_attr() -> String {
    "mail".into()
}
fn default_name_attr() -> String {
    "cn".into()
}
fn default_enabled() -> bool {
    true
}
fn default_vendor() -> String {
    "other".into()
}
fn default_edit_mode() -> String {
    "READ_ONLY".into()
}
fn default_conn_timeout() -> i32 {
    10
}
fn default_page_size() -> i32 {
    100
}
fn default_uuid_attr() -> String {
    "entryUUID".into()
}
fn default_username_attr() -> String {
    "uid".into()
}
fn default_group_name_attr() -> String {
    "cn".into()
}
fn default_group_object_class() -> String {
    "groupOfNames".into()
}
fn default_group_membership_attr() -> String {
    "member".into()
}
fn default_group_membership_type() -> String {
    "DN".into()
}
fn default_trust_email() -> bool {
    true
}
fn default_read_timeout() -> i32 {
    30
}
fn default_memberof_attr() -> String {
    "memberOf".to_string()
}
fn default_failover_hosts() -> String {
    String::new()
}
fn default_search_scope() -> String {
    "subtree".to_string()
}

// ── Query helper ──────────────────────────────────────────────────────────────

const SELECT_COLS: &str = "id, name, host, port, use_ssl, bind_dn, bind_password_ref, base_dn, \
     user_search_filter, attr_map_email, attr_map_name, enabled, last_sync_at, \
     sync_status, vendor, edit_mode, sync_interval_minutes, \
     connection_timeout_secs, page_size, \
     start_tls, uuid_attr, username_attr, \
     groups_dn, group_name_attr, group_object_class, group_membership_attr, group_membership_type, \
     last_full_sync_at, last_delta_sync_at, last_manual_sync_at, trust_email, skip_tls_verify, \
     read_timeout_secs, memberof_attr, failover_hosts, search_scope";

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn list_connections(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<LdapConnectionPublic>>> {
    let query = format!(
        "SELECT {SELECT_COLS} FROM ldap_connections \
         WHERE tenant_id = $1 ORDER BY created_at ASC"
    );
    let rows = sqlx::query_as::<_, LdapConnectionRow>(&query)
        .bind(&claims.tenant_id)
        .fetch_all(&state.db)
        .await?;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn create_connection(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<CreateLdapRequest>,
) -> Result<Json<LdapConnectionPublic>> {
    let id = id_generator::generate_id("ldap");

    // Encrypt bind_password at rest
    let enc_pw = state.ldap_encryption.encrypt(&payload.bind_password);

    let query = format!(
        "INSERT INTO ldap_connections \
         (id, tenant_id, name, host, port, use_ssl, start_tls, bind_dn, bind_password_enc, \
          bind_password_ref, base_dn, user_search_filter, attr_map_email, attr_map_name, \
          enabled, vendor, edit_mode, sync_interval_minutes, connection_timeout_secs, page_size, \
          uuid_attr, username_attr, groups_dn, group_name_attr, group_object_class, \
          group_membership_attr, group_membership_type, trust_email, skip_tls_verify, \
          read_timeout_secs, memberof_attr, failover_hosts, search_scope) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32) \
         RETURNING {SELECT_COLS}"
    );

    let row = sqlx::query_as::<_, LdapConnectionRow>(&query)
        .bind(&id)
        .bind(&claims.tenant_id)
        .bind(&payload.name)
        .bind(&payload.host)
        .bind(payload.port)
        .bind(payload.use_ssl)
        .bind(payload.start_tls)
        .bind(&payload.bind_dn)
        .bind(&enc_pw)
        .bind(&payload.base_dn)
        .bind(&payload.user_search_filter)
        .bind(&payload.attr_map_email)
        .bind(&payload.attr_map_name)
        .bind(payload.enabled)
        .bind(&payload.vendor)
        .bind(&payload.edit_mode)
        .bind(payload.sync_interval_minutes)
        .bind(payload.connection_timeout_secs)
        .bind(payload.page_size)
        .bind(&payload.uuid_attr)
        .bind(&payload.username_attr)
        .bind(&payload.groups_dn)
        .bind(&payload.group_name_attr)
        .bind(&payload.group_object_class)
        .bind(&payload.group_membership_attr)
        .bind(&payload.group_membership_type)
        .bind(payload.trust_email)
        .bind(payload.skip_tls_verify)
        .bind(payload.read_timeout_secs)
        .bind(&payload.memberof_attr)
        .bind(&payload.failover_hosts)
        .bind(&payload.search_scope)
        .fetch_one(&state.db)
        .await?;

    state
        .audit_event_service
        .record(RecordEventParams {
            tenant_id: claims.tenant_id.clone(),
            event_type: event_types::LDAP_CONNECTION_CREATED,
            actor_id: Some(claims.sub.clone()),
            actor_email: None,
            target_type: Some("ldap_connection"),
            target_id: Some(id),
            ip_address: None,
            user_agent: None,
            metadata: serde_json::json!({"name": &payload.name, "host": &payload.host}),
        })
        .await;

    Ok(Json(row.into()))
}

async fn update_connection(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(payload): Json<UpdateLdapRequest>,
) -> Result<StatusCode> {
    // Only encrypt and update bind_password_ref when a new password is supplied
    let enc_pw = payload
        .bind_password
        .as_deref()
        .map(|p| state.ldap_encryption.encrypt(p));

    let result = sqlx::query(
        "UPDATE ldap_connections SET \
         name                   = COALESCE($1, name), \
         host                   = COALESCE($2, host), \
         port                   = COALESCE($3, port), \
         use_ssl                = COALESCE($4, use_ssl), \
         bind_dn                = COALESCE($5, bind_dn), \
         bind_password_enc      = COALESCE($6, bind_password_enc), \
         bind_password_ref      = COALESCE($6, bind_password_ref), \
         base_dn                = COALESCE($7, base_dn), \
         user_search_filter     = COALESCE($8, user_search_filter), \
         attr_map_email         = COALESCE($9, attr_map_email), \
         attr_map_name          = COALESCE($10, attr_map_name), \
         enabled                = COALESCE($11, enabled), \
         vendor                 = COALESCE($12, vendor), \
         edit_mode              = COALESCE($13, edit_mode), \
         sync_interval_minutes  = COALESCE($14, sync_interval_minutes), \
         connection_timeout_secs= COALESCE($15, connection_timeout_secs), \
         page_size              = COALESCE($16, page_size), \
         start_tls              = COALESCE($17, start_tls), \
         uuid_attr              = COALESCE($18, uuid_attr), \
         username_attr          = COALESCE($19, username_attr), \
         groups_dn              = COALESCE($20, groups_dn), \
         group_name_attr        = COALESCE($21, group_name_attr), \
         group_object_class     = COALESCE($22, group_object_class), \
         group_membership_attr  = COALESCE($23, group_membership_attr), \
         group_membership_type  = COALESCE($24, group_membership_type), \
         trust_email            = COALESCE($25, trust_email), \
         skip_tls_verify        = COALESCE($26, skip_tls_verify), \
         read_timeout_secs      = COALESCE($27, read_timeout_secs), \
         memberof_attr          = COALESCE($28, memberof_attr), \
         failover_hosts         = COALESCE($29, failover_hosts), \
         search_scope           = COALESCE($30, search_scope), \
         updated_at             = NOW() \
         WHERE id = $31 AND tenant_id = $32",
    )
    .bind(&payload.name)
    .bind(&payload.host)
    .bind(payload.port)
    .bind(payload.use_ssl)
    .bind(&payload.bind_dn)
    .bind(&enc_pw)
    .bind(&payload.base_dn)
    .bind(&payload.user_search_filter)
    .bind(&payload.attr_map_email)
    .bind(&payload.attr_map_name)
    .bind(payload.enabled)
    .bind(&payload.vendor)
    .bind(&payload.edit_mode)
    .bind(payload.sync_interval_minutes)
    .bind(payload.connection_timeout_secs)
    .bind(payload.page_size)
    .bind(payload.start_tls)
    .bind(&payload.uuid_attr)
    .bind(&payload.username_attr)
    .bind(&payload.groups_dn)
    .bind(&payload.group_name_attr)
    .bind(&payload.group_object_class)
    .bind(&payload.group_membership_attr)
    .bind(&payload.group_membership_type)
    .bind(payload.trust_email)
    .bind(payload.skip_tls_verify)
    .bind(payload.read_timeout_secs)
    .bind(&payload.memberof_attr)
    .bind(&payload.failover_hosts)
    .bind(&payload.search_scope)
    .bind(&id)
    .bind(&claims.tenant_id)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("LDAP connection not found".into()));
    }

    state
        .audit_event_service
        .record(RecordEventParams {
            tenant_id: claims.tenant_id.clone(),
            event_type: event_types::LDAP_CONNECTION_UPDATED,
            actor_id: Some(claims.sub.clone()),
            actor_email: None,
            target_type: Some("ldap_connection"),
            target_id: Some(id),
            ip_address: None,
            user_agent: None,
            metadata: serde_json::json!({}),
        })
        .await;

    Ok(StatusCode::OK)
}

async fn delete_connection(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    let result = sqlx::query("DELETE FROM ldap_connections WHERE id = $1 AND tenant_id = $2")
        .bind(&id)
        .bind(&claims.tenant_id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("LDAP connection not found".into()));
    }

    state
        .audit_event_service
        .record(RecordEventParams {
            tenant_id: claims.tenant_id.clone(),
            event_type: event_types::LDAP_CONNECTION_DELETED,
            actor_id: Some(claims.sub.clone()),
            actor_email: None,
            target_type: Some("ldap_connection"),
            target_id: Some(id),
            ip_address: None,
            user_agent: None,
            metadata: serde_json::json!({}),
        })
        .await;

    Ok(StatusCode::NO_CONTENT)
}

// ── PATCH (partial update / toggle enabled) ────────────────────────────────────

#[derive(Deserialize)]
struct PatchLdapRequest {
    enabled: Option<bool>,
    name: Option<String>,
    host: Option<String>,
    port: Option<i32>,
}

async fn patch_connection(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(payload): Json<PatchLdapRequest>,
) -> Result<StatusCode> {
    let result = sqlx::query(
        "UPDATE ldap_connections SET \
         enabled    = COALESCE($1, enabled), \
         name       = COALESCE($2, name), \
         host       = COALESCE($3, host), \
         port       = COALESCE($4, port), \
         updated_at = NOW() \
         WHERE id = $5 AND tenant_id = $6",
    )
    .bind(payload.enabled)
    .bind(&payload.name)
    .bind(&payload.host)
    .bind(payload.port)
    .bind(&id)
    .bind(&claims.tenant_id)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("LDAP connection not found".into()));
    }
    Ok(StatusCode::OK)
}

// ── Test connection (real LDAP bind + rootDSE probe) ───────────────────────────

#[derive(Serialize)]
struct TestResult {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    naming_contexts: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ldap_versions: Vec<String>,
}

async fn test_connection(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<TestResult>> {
    let query =
        format!("SELECT {SELECT_COLS} FROM ldap_connections WHERE id = $1 AND tenant_id = $2");
    let row = sqlx::query_as::<_, LdapConnectionRow>(&query)
        .bind(&id)
        .bind(&claims.tenant_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::NotFound("LDAP connection not found".into()))?;

    if row.host.is_empty() {
        return Ok(Json(TestResult {
            success: false,
            message: "Host is not configured".into(),
            naming_contexts: vec![],
            ldap_versions: vec![],
        }));
    }

    // Decrypt bind_password
    let bind_pw = state
        .ldap_encryption
        .decrypt(&row.bind_password_ref)
        .unwrap_or_default();

    let timeout = row.connection_timeout_secs.max(3) as u64;
    let read_timeout = row.read_timeout_secs.max(5) as u64;
    let fallback_hosts_str = row.failover_hosts.clone();
    let fallback_hosts: Vec<&str> = fallback_hosts_str
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let result = ldap_client::test_bind(
        &row.host,
        row.port,
        row.use_ssl,
        row.start_tls,
        row.skip_tls_verify,
        &row.bind_dn,
        &bind_pw,
        timeout,
        read_timeout,
        &fallback_hosts,
    )
    .await;

    let event_type = if result.success {
        event_types::LDAP_TEST_SUCCEEDED
    } else {
        event_types::LDAP_TEST_FAILED
    };

    state
        .audit_event_service
        .record(RecordEventParams {
            tenant_id: claims.tenant_id.clone(),
            event_type,
            actor_id: Some(claims.sub.clone()),
            actor_email: None,
            target_type: Some("ldap_connection"),
            target_id: Some(id.clone()),
            ip_address: None,
            user_agent: None,
            metadata: serde_json::json!({
                "host": row.host,
                "port": row.port,
                "success": result.success,
                "message": result.message,
            }),
        })
        .await;

    Ok(Json(TestResult {
        message: result.message,
        success: result.success,
        naming_contexts: result.naming_contexts,
        ldap_versions: result.ldap_versions,
    }))
}

// ── Sync users (real paged search + upsert + sync_runs record) ─────────────────

#[derive(Serialize)]
struct SyncResult {
    synced: bool,
    message: String,
    sync_run_id: String,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct SyncRunRow {
    id: String,
    connection_id: String,
    started_at: DateTime<Utc>,
    finished_at: Option<DateTime<Utc>>,
    status: String,
    users_found: i32,
    users_created: i32,
    users_updated: i32,
    users_disabled: i32,
    error_message: Option<String>,
}

async fn list_sync_runs(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<Vec<SyncRunRow>>> {
    // Verify the connection belongs to this tenant
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM ldap_connections WHERE id = $1 AND tenant_id = $2)",
    )
    .bind(&id)
    .bind(&claims.tenant_id)
    .fetch_one(&state.db)
    .await?;

    if !exists {
        return Err(AppError::NotFound("LDAP connection not found".into()));
    }

    let rows = sqlx::query_as::<_, SyncRunRow>(
        "SELECT id, connection_id, started_at, finished_at, status, \
                users_found, users_created, users_updated, users_disabled, error_message \
         FROM ldap_sync_runs \
         WHERE connection_id = $1 AND tenant_id = $2 \
         ORDER BY started_at DESC LIMIT 50",
    )
    .bind(&id)
    .bind(&claims.tenant_id)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rows))
}

async fn sync_connection(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<SyncResult>> {
    let query =
        format!("SELECT {SELECT_COLS} FROM ldap_connections WHERE id = $1 AND tenant_id = $2");
    let row = sqlx::query_as::<_, LdapConnectionRow>(&query)
        .bind(&id)
        .bind(&claims.tenant_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::NotFound("LDAP connection not found".into()))?;

    if !row.enabled {
        return Err(AppError::BadRequest(
            "LDAP connection is disabled \u{2014} enable it first".into(),
        ));
    }

    // Rate-limit manual syncs: allow at most one per 60 seconds.
    if let Some(last_manual) = row.last_manual_sync_at {
        let elapsed = Utc::now().signed_duration_since(last_manual);
        if elapsed.num_seconds() < 60 {
            return Err(AppError::BadRequest(
                "A sync was already triggered recently. Please wait 60 seconds.".into(),
            ));
        }
    }

    // Record that a manual sync was requested right now.
    sqlx::query(
        "UPDATE ldap_connections SET last_manual_sync_at = NOW() WHERE id = $1 AND tenant_id = $2",
    )
    .bind(&id)
    .bind(&claims.tenant_id)
    .execute(&state.db)
    .await?;

    // Try to acquire a per-connection advisory lock to prevent concurrent syncs.
    // hashtext() returns int4 in PG; cast to int8 for advisory_lock.
    let lock_acquired =
        sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock(hashtext($1)::int8)")
            .bind(&id)
            .fetch_one(&state.db)
            .await
            .unwrap_or(false);

    if !lock_acquired {
        return Err(AppError::BadRequest(
            "A sync is already running for this connection".into(),
        ));
    }

    // Create sync_run record (status = 'running')
    let run_id = id_generator::generate_id("ldsr");
    sqlx::query(
        "INSERT INTO ldap_sync_runs (id, tenant_id, connection_id, status) \
         VALUES ($1, $2, $3, 'running')",
    )
    .bind(&run_id)
    .bind(&claims.tenant_id)
    .bind(&id)
    .execute(&state.db)
    .await?;

    // Mark connection as syncing
    sqlx::query(
        "UPDATE ldap_connections SET sync_status = 'syncing', updated_at = NOW() \
         WHERE id = $1 AND tenant_id = $2",
    )
    .bind(&id)
    .bind(&claims.tenant_id)
    .execute(&state.db)
    .await?;

    // Decrypt bind password
    let bind_pw = state
        .ldap_encryption
        .decrypt(&row.bind_password_ref)
        .unwrap_or_default();

    // Emit SYNC_STARTED audit event
    state
        .audit_event_service
        .record(RecordEventParams {
            tenant_id: claims.tenant_id.clone(),
            event_type: event_types::LDAP_SYNC_STARTED,
            actor_id: Some(claims.sub.clone()),
            actor_email: None,
            target_type: Some("ldap_connection"),
            target_id: Some(id.clone()),
            ip_address: None,
            user_agent: None,
            metadata: serde_json::json!({"sync_run_id": &run_id}),
        })
        .await;

    // Clone what the background task needs
    let db = state.db.clone();
    let audit_svc = state.audit_event_service.clone();
    let tenant_id = claims.tenant_id.clone();
    let conn_id = id.clone();
    let actor_id = claims.sub.clone();
    let run_id_bg = run_id.clone();

    tokio::spawn(async move {
        let result = run_sync_task(&db, &conn_id, &tenant_id, &run_id_bg, &row, &bind_pw).await;

        // Release the advisory lock regardless of success/failure
        let _ = sqlx::query("SELECT pg_advisory_unlock(hashtext($1)::int8)")
            .bind(&conn_id)
            .execute(&db)
            .await;

        let (final_status, event_type, meta) = match result {
            Ok(counts) => (
                "idle",
                event_types::LDAP_SYNC_COMPLETED,
                serde_json::json!({
                    "sync_run_id": &run_id_bg,
                    "users_found": counts.0,
                    "users_created": counts.1,
                    "users_updated": counts.2,
                }),
            ),
            Err(ref e) => (
                "error",
                event_types::LDAP_SYNC_FAILED,
                serde_json::json!({
                    "sync_run_id": &run_id_bg,
                    "error": e,
                }),
            ),
        };

        let _ = sqlx::query(
            "UPDATE ldap_connections \
             SET sync_status = $1, last_sync_at = NOW(), updated_at = NOW() \
             WHERE id = $2 AND tenant_id = $3",
        )
        .bind(final_status)
        .bind(&conn_id)
        .bind(&tenant_id)
        .execute(&db)
        .await;

        audit_svc
            .record(RecordEventParams {
                tenant_id: tenant_id.clone(),
                event_type,
                actor_id: Some(actor_id),
                actor_email: None,
                target_type: Some("ldap_connection"),
                target_id: Some(conn_id),
                ip_address: None,
                user_agent: None,
                metadata: meta,
            })
            .await;
    });

    Ok(Json(SyncResult {
        synced: true,
        message: "Sync started in background".into(),
        sync_run_id: run_id,
    }))
}

// ── Background sync task ───────────────────────────────────────────────────────

/// Returns `(users_found, users_created, users_updated)` on success.
async fn run_sync_task(
    db: &sqlx::PgPool,
    conn_id: &str,
    tenant_id: &str,
    run_id: &str,
    cfg: &LdapConnectionRow,
    bind_pw: &str,
) -> std::result::Result<(i32, i32, i32), String> {
    // ── Load mappers ──────────────────────────────────────────────────────────
    let mappers: Vec<(String, serde_json::Value, bool)> = sqlx::query_as(
        "SELECT mapper_type, config, enabled FROM ldap_mappers \
         WHERE connection_id = $1 AND tenant_id = $2",
    )
    .bind(conn_id)
    .bind(tenant_id)
    .fetch_all(db)
    .await
    .unwrap_or_default();

    // ── Build search filter (delta if available) ──────────────────────────────
    let base_filter = &cfg.user_search_filter;
    let is_delta = cfg.last_full_sync_at.is_some();
    let (effective_filter, sync_type) = if is_delta {
        if let Some(last_full) = cfg.last_full_sync_at {
            // modifyTimestamp format: YYYYMMDDHHMMSSZ
            let ts = last_full.format("%Y%m%d%H%M%SZ").to_string();
            let delta_filter = format!("(&{base_filter}(modifyTimestamp>={ts}))");
            (delta_filter, "delta")
        } else {
            (base_filter.clone(), "full")
        }
    } else {
        (base_filter.clone(), "full")
    };

    // ── Collect attribute names for LDAP search ───────────────────────────────
    let mut attr_names: Vec<String> = vec![
        cfg.attr_map_email.clone(),
        cfg.attr_map_name.clone(),
        cfg.uuid_attr.clone(),
        cfg.username_attr.clone(),
        "sAMAccountName".into(),
        "uid".into(),
        "entryUUID".into(),
        "objectGUID".into(),
        "userAccountControl".into(),
        "givenName".into(),
        "sn".into(),
        cfg.memberof_attr.clone(), // for role-ldap-mapper reverse lookup
    ];
    // Also collect LDAP attrs referenced by user-attribute mappers
    for (mapper_type, config, enabled) in &mappers {
        if *enabled && mapper_type == "user-attribute" {
            if let Some(ldap_attr) = config.get("ldap_attr").and_then(|v| v.as_str()) {
                attr_names.push(ldap_attr.to_string());
            }
        }
    }
    attr_names.sort();
    attr_names.dedup();
    let attr_refs: Vec<&str> = attr_names.iter().map(|s| s.as_str()).collect();

    // ── Parse failover hosts + search scope from config ───────────────────────
    let fallback_hosts_str = cfg.failover_hosts.clone();
    let fallback_hosts: Vec<&str> = fallback_hosts_str
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let scope = ldap_client::parse_scope(&cfg.search_scope);

    // ── User search with retry + exponential backoff ──────────────────────────
    const MAX_ATTEMPTS: u32 = 3;
    const RETRY_DELAYS_MS: &[u64] = &[5_000, 30_000];

    let mut last_err = String::new();
    let mut search_result: Option<ldap_client::SearchResult> = None;

    for attempt in 0..MAX_ATTEMPTS {
        if attempt > 0 {
            let delay = RETRY_DELAYS_MS
                .get(attempt as usize - 1)
                .copied()
                .unwrap_or(30_000);
            tracing::warn!(
                conn_id,
                attempt,
                delay_ms = delay,
                "LDAP sync: user search failed, retrying"
            );
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }
        match ldap_client::search_users(
            &cfg.host,
            cfg.port,
            cfg.use_ssl,
            cfg.start_tls,
            cfg.skip_tls_verify,
            &cfg.bind_dn,
            bind_pw,
            &cfg.base_dn,
            &effective_filter,
            &attr_refs,
            cfg.page_size,
            cfg.connection_timeout_secs.max(3) as u64,
            cfg.read_timeout_secs.max(5) as u64,
            &fallback_hosts,
            scope,
        )
        .await
        {
            Ok(r) => {
                search_result = Some(r);
                break;
            }
            Err(e) => {
                last_err = e;
            }
        }
    }

    let search = search_result
        .ok_or_else(|| format!("LDAP search failed after {MAX_ATTEMPTS} attempts: {last_err}"))?;

    let users_found = search.entries.len() as i32;
    let mut users_created = 0i32;
    let mut users_updated = 0i32;

    for entry in &search.entries {
        // ── Extract email ─────────────────────────────────────────────────────
        let email = entry
            .attrs
            .get(&cfg.attr_map_email)
            .and_then(|v| v.first())
            .map(|s| s.to_lowercase());

        let Some(email) = email else { continue };
        if email.is_empty() {
            continue;
        }

        // ── Extract stable UUID (prefer server UUID attr, fallback to DN-based) ─
        let ldap_uuid = entry
            .attrs
            .get(&cfg.uuid_attr)
            .or_else(|| entry.attrs.get("entryUUID"))
            .or_else(|| entry.attrs.get("objectGUID"))
            .and_then(|v| v.first())
            .cloned();

        // ── Extract display name ──────────────────────────────────────────────
        let display_name = entry
            .attrs
            .get(&cfg.attr_map_name)
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| email.clone());

        // ── Extract username ──────────────────────────────────────────────────
        let ldap_uid = entry
            .attrs
            .get(&cfg.username_attr)
            .or_else(|| entry.attrs.get("sAMAccountName"))
            .or_else(|| entry.attrs.get("uid"))
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| entry.dn.split(',').next().unwrap_or("").to_string());

        // ── Apply mappers: determine first_name / last_name / enabled ─────────
        let parts: Vec<&str> = display_name.splitn(2, ' ').collect();
        let mut first_name = parts.first().copied().unwrap_or("").to_string();
        let mut last_name = parts.get(1).copied().unwrap_or("").to_string();
        let mut user_enabled = true;

        for (mapper_type, config, enabled) in &mappers {
            if !enabled {
                continue;
            }
            match mapper_type.as_str() {
                "full-name" => {
                    // full-name-ldap-mapper: reads cn (or configured attr), splits first/last
                    let src_attr = config
                        .get("ldap_attr")
                        .and_then(|v| v.as_str())
                        .unwrap_or("cn");
                    if let Some(full) = entry.attrs.get(src_attr).and_then(|v| v.first()) {
                        let p: Vec<&str> = full.splitn(2, ' ').collect();
                        first_name = p.first().copied().unwrap_or("").to_string();
                        last_name = p.get(1).copied().unwrap_or("").to_string();
                    }
                }
                "msad-uac" => {
                    // msad-uac-mapper: reads userAccountControl, checks ACCOUNTDISABLE bit
                    if let Some(uac_str) = entry
                        .attrs
                        .get("userAccountControl")
                        .and_then(|v| v.first())
                    {
                        if let Ok(uac) = uac_str.parse::<i64>() {
                            // Bit 0x2 = ACCOUNTDISABLE
                            if uac & 0x2 != 0 {
                                user_enabled = false;
                            }
                        }
                    }
                }
                "user-attribute" | "role" | "hardcoded-role" => {
                    // Handled after user_id is known
                }
                _ => {}
            }
        }

        // ── Look up existing user by email or by UUID via federated_users ─────
        let existing_user_id = sqlx::query_scalar::<_, String>(
            "SELECT u.id FROM users u \
             INNER JOIN identities i ON i.user_id = u.id \
             WHERE i.type = 'email' AND i.identifier = $1 \
               AND i.organization_id = $2 \
               AND u.deleted_at IS NULL \
             LIMIT 1",
        )
        .bind(&email)
        .bind(tenant_id)
        .fetch_optional(db)
        .await
        .unwrap_or(None);

        let user_id = if let Some(uid) = existing_user_id {
            // Update display name and enabled state
            let _ = sqlx::query(
                "UPDATE users SET first_name = $1, last_name = $2, enabled = $3, updated_at = NOW() \
                 WHERE id = $4",
            )
            .bind(&first_name)
            .bind(&last_name)
            .bind(user_enabled)
            .bind(&uid)
            .execute(db)
            .await;

            users_updated += 1;
            uid
        } else {
            // Create a new user (no local password — authentication via LDAP bind)
            let uid = shared_types::id_generator::generate_id("user");
            let res = sqlx::query(
                "INSERT INTO users \
                 (id, first_name, last_name, organization_id, enabled, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, NOW(), NOW()) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(&uid)
            .bind(&first_name)
            .bind(&last_name)
            .bind(tenant_id)
            .bind(user_enabled)
            .execute(db)
            .await;

            if let Err(e) = res {
                tracing::warn!(email, error = %e, "LDAP sync: failed to create user");
                continue;
            }

            // Create email identity (verified = true — LDAP implies ownership)
            let _ = sqlx::query(
                "INSERT INTO identities \
                 (id, user_id, organization_id, type, identifier, verified, created_at, updated_at) \
                 VALUES ($1, $2, $3, 'email', $4, true, NOW(), NOW()) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(shared_types::id_generator::generate_id("ident"))
            .bind(&uid)
            .bind(tenant_id)
            .bind(&email)
            .execute(db)
            .await;

            users_created += 1;
            uid
        };

        // ── Apply user-attribute mappers ──────────────────────────────────────
        for (mapper_type, config, enabled) in &mappers {
            if !enabled || mapper_type != "user-attribute" {
                continue;
            }
            let ldap_attr = match config.get("ldap_attr").and_then(|v| v.as_str()) {
                Some(a) => a,
                None => continue,
            };
            let user_attr = match config.get("user_attr").and_then(|v| v.as_str()) {
                Some(a) => a,
                None => continue,
            };
            let value = match entry.attrs.get(ldap_attr).and_then(|v| v.first()) {
                Some(v) => v.clone(),
                None => continue,
            };
            // Allowlist: only map safe, known user columns
            let col = match user_attr {
                "first_name" | "last_name" | "phone" => user_attr,
                _ => continue,
            };
            let q = format!("UPDATE users SET {col} = $1, updated_at = NOW() WHERE id = $2");
            let _ = sqlx::query(&q)
                .bind(&value)
                .bind(&user_id)
                .execute(db)
                .await;
        }

        // ── Apply role-ldap-mappers ───────────────────────────────────────────
        // Config: { "ldap_group_dn": "cn=admins,...", "membership_role": "admin" }
        let user_member_of: Vec<&str> = entry
            .attrs
            .get(&cfg.memberof_attr)
            .map(|v| v.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default();

        for (mapper_type, config, enabled) in &mappers {
            if !enabled || mapper_type != "role" {
                continue;
            }
            let ldap_group_dn = match config.get("ldap_group_dn").and_then(|v| v.as_str()) {
                Some(d) => d,
                None => continue,
            };
            let membership_role = match config.get("membership_role").and_then(|v| v.as_str()) {
                Some(r) => r,
                None => continue,
            };
            // Check if user is a member of this LDAP group (case-insensitive DN compare)
            let is_member = user_member_of
                .iter()
                .any(|dn| dn.eq_ignore_ascii_case(ldap_group_dn));
            if is_member {
                // Upsert membership with the specified role
                let _ = sqlx::query(
                    "INSERT INTO memberships (user_id, organization_id, role, created_at, updated_at) \
                     VALUES ($1, $2, $3, NOW(), NOW()) \
                     ON CONFLICT (user_id, organization_id) \
                     DO UPDATE SET role = EXCLUDED.role, updated_at = NOW()",
                )
                .bind(&user_id)
                .bind(tenant_id)
                .bind(membership_role)
                .execute(db)
                .await;
            }
        }

        // ── Apply hardcoded-role-mappers ──────────────────────────────────────
        // Config: { "role": "member" }
        // Unconditionally assigns the configured role to every synced user.
        // Useful when all LDAP users should receive the same tenant role.
        for (mapper_type, config, enabled) in &mappers {
            if !enabled || mapper_type != "hardcoded-role" {
                continue;
            }
            let role = config
                .get("role")
                .and_then(|v| v.as_str())
                .unwrap_or("member");
            let _ = sqlx::query(
                "INSERT INTO memberships (user_id, organization_id, role, created_at, updated_at) \
                 VALUES ($1, $2, $3, NOW(), NOW()) \
                 ON CONFLICT (user_id, organization_id) \
                 DO UPDATE SET role = EXCLUDED.role, updated_at = NOW()",
            )
            .bind(&user_id)
            .bind(tenant_id)
            .bind(role)
            .execute(db)
            .await;
        }

        // ── Session revocation on disabled accounts ───────────────────────────
        if !user_enabled {
            let _ = sqlx::query(
                "UPDATE sessions SET revoked = TRUE, revoked_at = NOW(), expires_at = NOW() \
                 WHERE user_id = $1 AND revoked = FALSE",
            )
            .bind(&user_id)
            .execute(db)
            .await;
        }

        // ── Upsert ldap_federated_users (UUID-stable) ─────────────────────────
        let fed_id = shared_types::id_generator::generate_id("lfu");
        let _ = sqlx::query(
            "INSERT INTO ldap_federated_users \
             (id, tenant_id, connection_id, user_id, ldap_dn, ldap_uid, ldap_uuid, last_synced_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW()) \
             ON CONFLICT (connection_id, ldap_dn) \
             DO UPDATE SET \
               last_synced_at = NOW(), \
               user_id        = EXCLUDED.user_id, \
               ldap_uid       = EXCLUDED.ldap_uid, \
               ldap_uuid      = EXCLUDED.ldap_uuid",
        )
        .bind(&fed_id)
        .bind(tenant_id)
        .bind(conn_id)
        .bind(&user_id)
        .bind(&entry.dn)
        .bind(&ldap_uid)
        .bind(&ldap_uuid)
        .execute(db)
        .await;
    }

    // ── Group sync (if groups_dn is configured) ───────────────────────────────
    if let Some(ref groups_dn) = cfg.groups_dn {
        if !groups_dn.is_empty() {
            match ldap_client::search_groups(
                &cfg.host,
                cfg.port,
                cfg.use_ssl,
                cfg.start_tls,
                cfg.skip_tls_verify,
                &cfg.bind_dn,
                bind_pw,
                groups_dn,
                &cfg.group_object_class,
                &cfg.group_name_attr,
                &cfg.group_membership_attr,
                &cfg.uuid_attr,
                cfg.connection_timeout_secs.max(3) as u64,
                cfg.read_timeout_secs.max(5) as u64,
                &fallback_hosts,
                scope,
            )
            .await
            {
                Ok(groups) => {
                    // Collect all DNs from the current sync to drop stale groups after.
                    let synced_dns: Vec<&str> = groups.iter().map(|g| g.dn.as_str()).collect();

                    for grp in &groups {
                        let group_id = shared_types::id_generator::generate_id("lgrp");
                        // Upsert group row
                        let row: Option<(String,)> = sqlx::query_as(
                            "INSERT INTO ldap_groups \
                             (id, tenant_id, connection_id, ldap_dn, ldap_uuid, name, last_synced_at) \
                             VALUES ($1, $2, $3, $4, $5, $6, NOW()) \
                             ON CONFLICT (connection_id, ldap_dn) \
                             DO UPDATE SET \
                               name           = EXCLUDED.name, \
                               ldap_uuid      = EXCLUDED.ldap_uuid, \
                               last_synced_at = NOW() \
                             RETURNING id",
                        )
                        .bind(&group_id)
                        .bind(tenant_id)
                        .bind(conn_id)
                        .bind(&grp.dn)
                        .bind(&grp.uuid)
                        .bind(&grp.name)
                        .fetch_optional(db)
                        .await
                        .unwrap_or(None);

                        let saved_group_id = match row {
                            Some((id,)) => id,
                            None => continue,
                        };

                        // ── Stale member cleanup: replace current membership set ──
                        // Delete all existing members for this group before re-inserting
                        // the current set — this is the correct way to handle removed members.
                        let _ = sqlx::query("DELETE FROM ldap_group_members WHERE group_id = $1")
                            .bind(&saved_group_id)
                            .execute(db)
                            .await;

                        // Resolve member identifiers → user_ids and re-insert
                        for member_ref in &grp.members {
                            // Resolve by DN (ldap_dn) or by UID (ldap_uid)
                            let user_id_opt: Option<String> = if cfg.group_membership_type == "DN" {
                                sqlx::query_scalar::<_, String>(
                                    "SELECT user_id FROM ldap_federated_users \
                                     WHERE connection_id = $1 AND ldap_dn = $2 LIMIT 1",
                                )
                                .bind(conn_id)
                                .bind(member_ref)
                                .fetch_optional(db)
                                .await
                                .unwrap_or(None)
                            } else {
                                sqlx::query_scalar::<_, String>(
                                    "SELECT user_id FROM ldap_federated_users \
                                     WHERE connection_id = $1 AND ldap_uid = $2 LIMIT 1",
                                )
                                .bind(conn_id)
                                .bind(member_ref)
                                .fetch_optional(db)
                                .await
                                .unwrap_or(None)
                            };

                            if let Some(uid) = user_id_opt {
                                let _ = sqlx::query(
                                    "INSERT INTO ldap_group_members \
                                     (tenant_id, group_id, user_id) \
                                     VALUES ($1, $2, $3) \
                                     ON CONFLICT (group_id, user_id) DO NOTHING",
                                )
                                .bind(tenant_id)
                                .bind(&saved_group_id)
                                .bind(&uid)
                                .execute(db)
                                .await;
                            }
                        }
                    }

                    // ── Drop stale groups (no longer present in LDAP) ────────────
                    // Delete member rows first to avoid FK violations if no CASCADE is set.
                    if !synced_dns.is_empty() {
                        let _ = sqlx::query(
                            "DELETE FROM ldap_group_members lgm \
                             USING ldap_groups lg \
                             WHERE lgm.group_id = lg.id \
                               AND lg.connection_id = $1 \
                               AND lg.ldap_dn != ALL($2)",
                        )
                        .bind(conn_id)
                        .bind(&synced_dns)
                        .execute(db)
                        .await;

                        let _ = sqlx::query(
                            "DELETE FROM ldap_groups \
                             WHERE connection_id = $1 AND ldap_dn != ALL($2)",
                        )
                        .bind(conn_id)
                        .bind(&synced_dns)
                        .execute(db)
                        .await;
                    } else {
                        // No groups at all: delete everything for this connection
                        let _ = sqlx::query(
                            "DELETE FROM ldap_group_members lgm \
                             USING ldap_groups lg \
                             WHERE lgm.group_id = lg.id AND lg.connection_id = $1",
                        )
                        .bind(conn_id)
                        .execute(db)
                        .await;

                        let _ = sqlx::query("DELETE FROM ldap_groups WHERE connection_id = $1")
                            .bind(conn_id)
                            .execute(db)
                            .await;
                    }
                }
                Err(e) => {
                    tracing::warn!(conn_id, error = e, "LDAP group sync failed (non-fatal)");
                }
            }
        }
    }

    // ── WRITABLE mode: sync registrations ────────────────────────────────────
    // Find IDaaS users in this tenant who have no ldap_federated_users row for
    // this connection, and write them back to LDAP.
    if cfg.edit_mode == "WRITABLE" {
        let unfederated: Vec<(String, String, String, String, String)> = sqlx::query_as(
            "SELECT u.id, u.first_name, u.last_name, \
                    COALESCE(i.identifier, ''), \
                    COALESCE( \
                        (SELECT ldap_uid FROM ldap_federated_users \
                         WHERE connection_id = $1 AND user_id = u.id LIMIT 1), \
                        u.id \
                    ) \
             FROM users u \
             LEFT JOIN identities i \
               ON i.user_id = u.id AND i.type = 'email' AND i.organization_id = $2 \
             WHERE u.organization_id = $2 \
               AND u.deleted_at IS NULL \
               AND NOT EXISTS ( \
                   SELECT 1 FROM ldap_federated_users lfu \
                   WHERE lfu.connection_id = $1 AND lfu.user_id = u.id \
               ) \
             LIMIT 100",
        )
        .bind(conn_id)
        .bind(tenant_id)
        .fetch_all(db)
        .await
        .unwrap_or_default();

        for (uid, first_name, last_name, email, username) in unfederated {
            if email.is_empty() {
                continue;
            }
            // Build user DN: uid=<username>,<base_dn>
            let user_dn = format!("uid={username},{}", cfg.base_dn);
            match ldap_client::write_user_to_ldap(
                &cfg.host,
                cfg.port,
                cfg.use_ssl,
                cfg.start_tls,
                cfg.skip_tls_verify,
                &cfg.bind_dn,
                bind_pw,
                &user_dn,
                &username,
                &first_name,
                &last_name,
                &email,
                cfg.connection_timeout_secs.max(3) as u64,
                cfg.read_timeout_secs.max(5) as u64,
                &fallback_hosts,
            )
            .await
            {
                Ok(()) => {
                    // Record federation entry so we don't re-create next sync
                    let fed_id = shared_types::id_generator::generate_id("lfu");
                    let _ = sqlx::query(
                        "INSERT INTO ldap_federated_users \
                         (id, tenant_id, connection_id, user_id, ldap_dn, ldap_uid, last_synced_at) \
                         VALUES ($1, $2, $3, $4, $5, $6, NOW()) \
                         ON CONFLICT (connection_id, ldap_dn) DO NOTHING",
                    )
                    .bind(&fed_id)
                    .bind(tenant_id)
                    .bind(conn_id)
                    .bind(&uid)
                    .bind(&user_dn)
                    .bind(&username)
                    .execute(db)
                    .await;
                    tracing::info!(
                        conn_id,
                        uid,
                        user_dn,
                        "LDAP sync registration: user written to LDAP"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        conn_id,
                        uid,
                        user_dn,
                        error = e,
                        "LDAP sync registration: failed to write user (non-fatal)"
                    );
                }
            }
        }
    }

    // ── Update sync timestamps ────────────────────────────────────────────────
    if sync_type == "full" {
        let _ = sqlx::query("UPDATE ldap_connections SET last_full_sync_at = NOW() WHERE id = $1")
            .bind(conn_id)
            .execute(db)
            .await;
    } else {
        let _ = sqlx::query("UPDATE ldap_connections SET last_delta_sync_at = NOW() WHERE id = $1")
            .bind(conn_id)
            .execute(db)
            .await;
    }

    // ── Finalise sync_run record ──────────────────────────────────────────────
    let _ = sqlx::query(
        "UPDATE ldap_sync_runs SET \
         finished_at = NOW(), status = 'completed', \
         users_found = $1, users_created = $2, users_updated = $3 \
         WHERE id = $4",
    )
    .bind(users_found)
    .bind(users_created)
    .bind(users_updated)
    .bind(run_id)
    .execute(db)
    .await;

    tracing::info!(
        conn_id,
        run_id,
        sync_type,
        users_found,
        users_created,
        users_updated,
        "LDAP sync completed"
    );

    Ok((users_found, users_created, users_updated))
}

// ── Mapper CRUD ────────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow, Serialize)]
struct LdapMapper {
    id: String,
    connection_id: String,
    name: String,
    mapper_type: String,
    config: serde_json::Value,
    enabled: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct CreateMapperRequest {
    name: String,
    mapper_type: String,
    #[serde(default)]
    config: serde_json::Value,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

#[derive(Deserialize)]
struct UpdateMapperRequest {
    name: Option<String>,
    mapper_type: Option<String>,
    config: Option<serde_json::Value>,
    enabled: Option<bool>,
}

async fn list_mappers(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<Vec<LdapMapper>>> {
    // Verify connection belongs to tenant
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM ldap_connections WHERE id = $1 AND tenant_id = $2)",
    )
    .bind(&id)
    .bind(&claims.tenant_id)
    .fetch_one(&state.db)
    .await?;
    if !exists {
        return Err(AppError::NotFound("LDAP connection not found".into()));
    }

    let rows = sqlx::query_as::<_, LdapMapper>(
        "SELECT id, connection_id, name, mapper_type, config, enabled, created_at, updated_at \
         FROM ldap_mappers WHERE connection_id = $1 AND tenant_id = $2 \
         ORDER BY created_at ASC",
    )
    .bind(&id)
    .bind(&claims.tenant_id)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rows))
}

async fn create_mapper(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(payload): Json<CreateMapperRequest>,
) -> Result<Json<LdapMapper>> {
    // Verify connection belongs to tenant
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM ldap_connections WHERE id = $1 AND tenant_id = $2)",
    )
    .bind(&id)
    .bind(&claims.tenant_id)
    .fetch_one(&state.db)
    .await?;
    if !exists {
        return Err(AppError::NotFound("LDAP connection not found".into()));
    }

    let mapper_id = shared_types::id_generator::generate_id("lmap");
    let row = sqlx::query_as::<_, LdapMapper>(
        "INSERT INTO ldap_mappers (id, tenant_id, connection_id, name, mapper_type, config, enabled) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         RETURNING id, connection_id, name, mapper_type, config, enabled, created_at, updated_at",
    )
    .bind(&mapper_id)
    .bind(&claims.tenant_id)
    .bind(&id)
    .bind(&payload.name)
    .bind(&payload.mapper_type)
    .bind(&payload.config)
    .bind(payload.enabled)
    .fetch_one(&state.db)
    .await?;

    state
        .audit_event_service
        .record(RecordEventParams {
            tenant_id: claims.tenant_id.clone(),
            event_type: event_types::LDAP_MAPPER_CREATED,
            actor_id: Some(claims.sub.clone()),
            actor_email: None,
            target_type: Some("ldap_mapper"),
            target_id: Some(mapper_id),
            ip_address: None,
            user_agent: None,
            metadata: serde_json::json!({
                "connection_id": &id,
                "name": &payload.name,
                "mapper_type": &payload.mapper_type,
            }),
        })
        .await;

    Ok(Json(row))
}

async fn update_mapper(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((id, mapper_id)): Path<(String, String)>,
    Json(payload): Json<UpdateMapperRequest>,
) -> Result<Json<LdapMapper>> {
    let row = sqlx::query_as::<_, LdapMapper>(
        "UPDATE ldap_mappers SET \
         name         = COALESCE($1, name), \
         mapper_type  = COALESCE($2, mapper_type), \
         config       = COALESCE($3, config), \
         enabled      = COALESCE($4, enabled), \
         updated_at   = NOW() \
         WHERE id = $5 AND connection_id = $6 AND tenant_id = $7 \
         RETURNING id, connection_id, name, mapper_type, config, enabled, created_at, updated_at",
    )
    .bind(&payload.name)
    .bind(&payload.mapper_type)
    .bind(&payload.config)
    .bind(payload.enabled)
    .bind(&mapper_id)
    .bind(&id)
    .bind(&claims.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Mapper not found".into()))?;

    Ok(Json(row))
}

async fn delete_mapper(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((id, mapper_id)): Path<(String, String)>,
) -> Result<StatusCode> {
    let result = sqlx::query(
        "DELETE FROM ldap_mappers WHERE id = $1 AND connection_id = $2 AND tenant_id = $3",
    )
    .bind(&mapper_id)
    .bind(&id)
    .bind(&claims.tenant_id)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Mapper not found".into()));
    }

    state
        .audit_event_service
        .record(RecordEventParams {
            tenant_id: claims.tenant_id.clone(),
            event_type: event_types::LDAP_MAPPER_DELETED,
            actor_id: Some(claims.sub.clone()),
            actor_email: None,
            target_type: Some("ldap_mapper"),
            target_id: Some(mapper_id),
            ip_address: None,
            user_agent: None,
            metadata: serde_json::json!({"connection_id": &id}),
        })
        .await;

    Ok(StatusCode::NO_CONTENT)
}
