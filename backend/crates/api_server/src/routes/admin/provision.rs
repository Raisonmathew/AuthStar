//! Tenant self-serve provisioning route.
//!
//! `POST /api/v1/tenants/provision` — unauthenticated signup endpoint that
//! creates an org, admin user, seeds default EIAA capsules, and returns a
//! first-time SDK API key.
//!
//! ## Route placement (P5 constraint)
//!
//! This route MUST be merged at the **final-router level** (alongside
//! `step_up_routes`), NOT inside `protected_routes`.  A brand-new tenant has
//! no subscription — placing it inside `protected_routes` returns 402 before
//! signup completes.  See the block comment in `router.rs`.
//!
//! ## RLS bootstrap
//!
//! Two-phase transaction:
//!   1. INSERT org into `organizations` (no RLS needed — not tenant-scoped).
//!   2. Set RLS context to the new `org_id`.
//!   3. INSERT admin user, identities, memberships, and seed capsules inside
//!      that context.
//!   4. Create SDK API key (outside the tx — uses its own connection with RLS).
//!
//! On any failure the transaction rolls back, leaving the DB clean.

use crate::services::api_key_service::CreateApiKeyParams;
use crate::state::AppState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use shared_types::{generate_id, validation, AppError, Result};

// ─── Router ───────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    Router::new().route("/provision", post(provision_tenant))
}

// ─── Request / Response types ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ProvisionRequest {
    /// Organisation display name.
    pub org_name: String,
    /// Optional org slug (auto-generated from name if absent).
    pub org_slug: Option<String>,
    /// Admin user email.
    pub admin_email: String,
    /// Admin user password (validated against global complexity rules).
    pub admin_password: String,
    /// Admin first name (optional).
    pub first_name: Option<String>,
    /// Admin last name (optional).
    pub last_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ProvisionResponse {
    pub tenant_id: String,
    pub user_id: String,
    pub org_name: String,
    pub org_slug: String,
    /// SDK API key — returned ONCE.  Store it; it cannot be retrieved again.
    pub sdk_api_key: String,
    pub sdk_api_key_id: String,
    /// SHA-256 fingerprint of the SDK key — safe to display in the UI.
    pub key_fingerprint: String,
    pub message: &'static str,
}

// ─── Handler ──────────────────────────────────────────────────────────────────

/// `POST /api/v1/tenants/provision`
///
/// Unauthenticated endpoint — the EIAA capsule for `"tenant:provision"` is
/// compiled as a public-access default (VerifyIdentity → Allow) and is executed
/// by the `EiaaAuthzLayer` wrapping this router.  The layer treats the absence
/// of a JWT as "no identity" and uses the fallback compilation path, which still
/// runs the capsule and writes an audit record.
pub async fn provision_tenant(
    State(state): State<AppState>,
    Json(req): Json<ProvisionRequest>,
) -> Result<impl IntoResponse> {
    // ── Input validation ────────────────────────────────────────────────────
    let org_name = req.org_name.trim().to_string();
    if org_name.is_empty() || org_name.len() > 100 {
        return Err(AppError::Validation(
            "org_name must be 1–100 characters".into(),
        ));
    }

    if !validation::validate_email(&req.admin_email) {
        return Err(AppError::Validation("Invalid email format".into()));
    }

    if let Err(errors) = validation::validate_password(&req.admin_password) {
        return Err(AppError::Validation(errors.join(", ")));
    }

    let org_slug = if let Some(ref slug) = req.org_slug {
        if !validation::validate_slug(slug) {
            return Err(AppError::Validation("Invalid slug format".into()));
        }
        slug.clone()
    } else {
        validation::slugify(&org_name)
    };

    // ── Phase 1: Create organisation (no RLS needed — not tenant-scoped) ───
    let existing_slug: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM organizations WHERE slug = $1)",
    )
    .bind(&org_slug)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("slug check: {e}")))?;

    if existing_slug {
        return Err(AppError::Conflict(
            "Organisation slug already taken — choose a different name or provide a custom slug"
                .into(),
        ));
    }

    // Also check email uniqueness globally (provisioning creates a global admin).
    let existing_email: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM identities WHERE type = 'email' AND identifier = $1)",
    )
    .bind(&req.admin_email)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("email check: {e}")))?;

    if existing_email {
        return Err(AppError::Conflict(
            "An account with that email already exists".into(),
        ));
    }

    // ── Phase 2: Transactional setup ────────────────────────────────────────
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(format!("begin tx: {e}")))?;

    // 2a. Create org
    let tenant_id = generate_id("org");
    sqlx::query(
        "INSERT INTO organizations (id, name, slug, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())",
    )
    .bind(&tenant_id)
    .bind(&org_name)
    .bind(&org_slug)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Internal(format!("create org: {e}")))?;

    // 2b. Set RLS context so tenant-scoped INSERTs work inside this tx.
    sqlx::query("SELECT set_config('app.current_org_id', $1, true)")
        .bind(&tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("set RLS context: {e}")))?;

    // 2c. Create admin user
    let user_id = generate_id("user");
    sqlx::query(
        r#"
        INSERT INTO users (id, first_name, last_name, organization_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4, NOW(), NOW())
        "#,
    )
    .bind(&user_id)
    .bind(req.first_name.as_deref())
    .bind(req.last_name.as_deref())
    .bind(&tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Internal(format!("create user: {e}")))?;

    // 2d. Create email identity (no credential column on identities — password
    //     is stored in the separate `passwords` table, matching signup.rs).
    sqlx::query(
        r#"
        INSERT INTO identities (id, user_id, type, identifier, organization_id, verified, verified_at, created_at, updated_at)
        VALUES ($1, $2, 'email', $3, $4, true, NOW(), NOW(), NOW())
        "#,
    )
    .bind(generate_id("idn"))
    .bind(&user_id)
    .bind(&req.admin_email)
    .bind(&tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Internal(format!("create identity: {e}")))?;

    // 2e-pre. Hash password and store in the passwords table
    let password_hash = auth_core::hash_password(&req.admin_password)
        .map_err(|e| AppError::Internal(format!("hash password: {e}")))?;

    sqlx::query(
        r#"
        INSERT INTO passwords (user_id, password_hash)
        VALUES ($1, $2)
        "#,
    )
    .bind(&user_id)
    .bind(&password_hash)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Internal(format!("create password: {e}")))?;

    // 2f. Create admin membership
    sqlx::query(
        r#"
        INSERT INTO memberships (id, organization_id, user_id, role, created_at, updated_at)
        VALUES ($1, $2, $3, 'admin', NOW(), NOW())
        "#,
    )
    .bind(generate_id("memb"))
    .bind(&tenant_id)
    .bind(&user_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Internal(format!("create membership: {e}")))?;

    tx.commit()
        .await
        .map_err(|e| AppError::Internal(format!("commit provision tx: {e}")))?;

    // ── Phase 3: Seed capsules (outside the main tx — seeder manages its own connection) ──
    crate::services::capsule_seeder::seed_tenant(
        &tenant_id,
        &state.db,
        &state.ks,
        &state.compiler_kid,
    )
    .await
    .map_err(|e| {
        tracing::error!(
            tenant_id = %tenant_id,
            error = %e,
            "Capsule seeding failed after provisioning — tenant may have limited access until first request"
        );
        // Non-fatal: EiaaAuthzLayer will compile defaults on-demand at first request.
        // We log but don't fail the signup so the user isn't left with a broken account.
        e
    })
    .unwrap_or(0);

    // ── Phase 4: Create starter SDK API key ─────────────────────────────────
    let sdk_key = state
        .api_key_service
        .create(
            &user_id,
            &tenant_id,
            &CreateApiKeyParams {
                name: "Default SDK Key".to_string(),
                scopes: vec!["*".to_string()],
                expires_at: None,
            },
        )
        .await
        .map_err(|e| AppError::Internal(format!("create SDK key: {e}")))?;

    // ── Audit + PLG activation event ────────────────────────────────────────
    tracing::info!(
        tenant_id = %tenant_id,
        user_id   = %user_id,
        org_slug  = %org_slug,
        "New tenant provisioned via self-serve"
    );

    // PLG funnel event: consumed by PostHog/Amplitude via structured log
    // collector. Downstream filter: event_name = "tenant_created".
    tracing::info!(
        event_name = "tenant_created",
        tenant_id  = %tenant_id,
        user_id    = %user_id,
        org_name   = %org_name,
        org_slug   = %org_slug,
        "PLG event: tenant_created"
    );

    Ok((
        StatusCode::CREATED,
        Json(ProvisionResponse {
            tenant_id,
            user_id,
            org_name,
            org_slug,
            sdk_api_key: sdk_key.key,
            sdk_api_key_id: sdk_key.id,
            key_fingerprint: sdk_key.key_fingerprint,
            message: "Tenant provisioned. Store the sdk_api_key — it is shown only once.",
        }),
    ))
}
