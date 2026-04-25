use crate::capsules::signup_capsule::{build_signup_context, compile_signup_capsule};
use crate::services::StoreAttestationParams;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
// GAP-1 FIX: Use SharedRuntimeClient from AppState instead of per-request connect
use identity_engine::models::SignupTicket;
use shared_types::{AppError, Result};

#[derive(Deserialize)]
pub struct InitFlowRequest {
    pub signup_ticket_id: String,
}

#[derive(Serialize)]
pub struct InitFlowResponse {
    pub flow_id: String,
    pub ui_step: UiStep,
}

#[derive(Serialize, Clone)]
#[serde(tag = "type")]
pub enum UiStep {
    #[serde(rename = "verification_code")]
    VerificationCode {
        label: String,
        attempts_remaining: i32,
    },
}

#[derive(Deserialize)]
pub struct SubmitRequest {
    #[serde(rename = "type")]
    pub step_type: String,
    pub value: String,
}

/// FIX-FUNC-4: commit_decision now requires the caller to prove they own the
/// signup flow by supplying the flow_id that was issued during init_flow.
/// Without this, any party who guesses or obtains a decision_ref can create
/// an account without going through the verification flow.
#[derive(Deserialize)]
pub struct CommitRequest {
    /// The flow_id issued by init_flow — proves the caller completed the flow.
    pub flow_id: String,
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum SubmitResponse {
    DecisionReady {
        status: String,
        decision_ref: String,
    },
    NextStep {
        flow_id: String,
        ui_step: UiStep,
    },
}

#[derive(Serialize)]
pub struct CommitResult {
    pub status: String,
    pub user_id: String,
    pub identity_id: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/flows", post(init_flow))
        .route("/flows/:flow_id/submit", post(submit_flow))
        .route("/decisions/:decision_ref/commit", post(commit_decision))
}

async fn init_flow(
    State(state): State<AppState>,
    Json(payload): Json<InitFlowRequest>,
) -> Result<Json<InitFlowResponse>> {
    // Get signup ticket
    let ticket = sqlx::query_as::<_, SignupTicket>("SELECT * FROM signup_tickets WHERE id = $1")
        .bind(&payload.signup_ticket_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::NotFound("Signup ticket not found".into()))?;

    // Validate ticket
    if ticket.expires_at < chrono::Utc::now() {
        return Err(AppError::BadRequest("Signup ticket expired".into()));
    }

    if ticket.status != "awaiting_verification" {
        return Err(AppError::BadRequest("Ticket already used".into()));
    }

    // Generate flow ID
    let flow_id = shared_types::id_generator::generate_id("flow_signup");

    // Bind flow to ticket
    sqlx::query("UPDATE signup_tickets SET flow_id = $1 WHERE id = $2")
        .bind(&flow_id)
        .bind(&payload.signup_ticket_id)
        .execute(&state.db)
        .await?;

    Ok(Json(InitFlowResponse {
        flow_id,
        ui_step: UiStep::VerificationCode {
            label: "Enter the 6-digit code sent to your email".to_string(),
            attempts_remaining: 3 - ticket.verification_attempts,
        },
    }))
}

async fn submit_flow(
    State(state): State<AppState>,
    Path(flow_id): Path<String>,
    Json(payload): Json<SubmitRequest>,
) -> Result<Json<SubmitResponse>> {
    // Get ticket by flow_id
    let ticket =
        sqlx::query_as::<_, SignupTicket>("SELECT * FROM signup_tickets WHERE flow_id = $1")
            .bind(&flow_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| AppError::NotFound("Flow not found".into()))?;

    tracing::info!(
        "Submitting signup flow step: type={}, flow_id={}",
        payload.step_type,
        flow_id
    );

    // Compile signup capsule
    let org_id = "platform"; // For now, platform-level signup
    let capsule = compile_signup_capsule(org_id, &state)
        .await
        .map_err(|e| AppError::BadRequest(format!("Capsule compilation failed: {e}")))?;

    // Build context
    let context = build_signup_context(&ticket, &payload.value);
    let input_json = serde_json::to_string(&context)?;

    // Execute via gRPC — GAP-1 FIX: use shared singleton client
    let nonce = crate::services::audit_writer::AuditWriter::generate_nonce();
    let response = state
        .runtime_client
        .execute_capsule(capsule.clone(), input_json, nonce.clone())
        .await
        .map_err(|e| AppError::BadRequest(format!("Capsule execution failed: {e}")))?;

    // Parse decision
    let decision = response
        .decision
        .ok_or_else(|| AppError::BadRequest("No decision returned".into()))?;

    // Increment attempts
    sqlx::query(
        "UPDATE signup_tickets SET verification_attempts = verification_attempts + 1, last_attempt_at = NOW() WHERE id = $1"
    )
    .bind(&ticket.id)
    .execute(&state.db)
    .await?;

    if decision.allow {
        // Generate decision reference
        let decision_ref = shared_types::id_generator::generate_id("dec_signup");

        // Store decision_ref on ticket
        sqlx::query(
            "UPDATE signup_tickets SET decision_ref = $1, status = 'complete' WHERE id = $2",
        )
        .bind(&decision_ref)
        .bind(&ticket.id)
        .execute(&state.db)
        .await?;

        // Store attestation if present
        if let Some(attestation) = response.attestation {
            state
                .audit_writer
                .store_attestation(StoreAttestationParams {
                    decision_ref: &decision_ref,
                    capsule: &capsule,
                    decision: &decision,
                    attestation,
                    nonce: &nonce,
                    action: "signup",
                    capsule_version: "signup_capsule_v1",
                    tenant_id: "platform",
                    user_id: None,
                })?;
        }

        Ok(Json(SubmitResponse::DecisionReady {
            status: "decision_ready".to_string(),
            decision_ref,
        }))
    } else {
        // Return error with attempts remaining
        let attempts_left = 3 - (ticket.verification_attempts + 1);

        Ok(Json(SubmitResponse::NextStep {
            flow_id,
            ui_step: UiStep::VerificationCode {
                label: if attempts_left > 0 {
                    format!("Verification failed. {attempts_left} attempts remaining")
                } else {
                    "Too many attempts. Please start over.".to_string()
                },
                attempts_remaining: attempts_left,
            },
        }))
    }
}

async fn commit_decision(
    State(state): State<AppState>,
    Path(decision_ref): Path<String>,
    Json(payload): Json<CommitRequest>,
) -> Result<Json<CommitResult>> {
    // FIX-FUNC-4: Verify the caller owns the signup flow by checking that the
    // supplied flow_id matches the one bound to this decision_ref ticket.
    // This prevents an attacker who discovers a decision_ref from committing
    // a signup without having gone through the email verification step.

    // Get ticket by decision_ref AND flow_id — both must match
    let ticket = sqlx::query_as::<_, SignupTicket>(
        "SELECT * FROM signup_tickets WHERE decision_ref = $1 AND flow_id = $2",
    )
    .bind(&decision_ref)
    .bind(&payload.flow_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Decision not found or flow_id mismatch".into()))?;

    // Idempotency check - if user already exists with this email, return it
    let email_str = ticket.email.as_deref().unwrap_or("");
    let org_id = ticket.organization_id.as_deref();
    if let Some(existing) = check_existing_identity(&state.db, email_str, org_id).await? {
        return Ok(Json(CommitResult {
            status: "already_exists".to_string(),
            user_id: existing.0,
            identity_id: existing.1,
        }));
    }

    // Begin transaction
    let mut tx = state.db.begin().await?;

    // Create user (no email column on users table — stored in identities)
    let user_id = shared_types::id_generator::generate_id("usr");
    let user_org = ticket.organization_id.as_deref().unwrap_or("platform");
    sqlx::query(
        r#"
        INSERT INTO users (id, first_name, last_name, organization_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4, NOW(), NOW())
        "#,
    )
    .bind(&user_id)
    .bind(&ticket.first_name)
    .bind(&ticket.last_name)
    .bind(user_org)
    .execute(&mut *tx)
    .await?;

    // Create identity (org-scoped)
    let identity_id = shared_types::id_generator::generate_id("idn");
    sqlx::query(
        r#"
        INSERT INTO identities (id, user_id, organization_id, type, identifier, verified, verified_at, created_at)
        VALUES ($1, $2, $3, 'email', $4, true, NOW(), NOW())
        "#
    )
    .bind(&identity_id)
    .bind(&user_id)
    .bind(user_org)
    .bind(&ticket.email)
    .execute(&mut *tx)
    .await?;

    // Create password
    sqlx::query(
        r#"
        INSERT INTO passwords (user_id, password_hash)
        VALUES ($1, $2)
        "#,
    )
    .bind(&user_id)
    .bind(&ticket.password_hash)
    .execute(&mut *tx)
    .await?;

    // Create org membership — required for get_user_by_email_in_org and
    // multi-tenant login. Without this the user can never log in because
    // the identify query JOINs on memberships.
    let membership_id = shared_types::id_generator::generate_id("mem");
    sqlx::query(
        r#"
        INSERT INTO memberships (id, organization_id, user_id, role, created_at, updated_at)
        VALUES ($1, $2, $3, 'member', NOW(), NOW())
        ON CONFLICT (organization_id, user_id) DO NOTHING
        "#,
    )
    .bind(&membership_id)
    .bind(user_org)
    .bind(&user_id)
    .execute(&mut *tx)
    .await?;

    // Delete signup ticket
    sqlx::query("DELETE FROM signup_tickets WHERE id = $1")
        .bind(&ticket.id)
        .execute(&mut *tx)
        .await?;

    // Commit transaction
    tx.commit().await?;

    Ok(Json(CommitResult {
        status: "signup_completed".to_string(),
        user_id,
        identity_id,
    }))
}

// Helper functions

async fn check_existing_identity(
    db: &sqlx::PgPool,
    email: &str,
    org_id: Option<&str>,
) -> Result<Option<(String, String)>> {
    let row: Option<(String, String)> = if let Some(oid) = org_id {
        sqlx::query_as(
            r#"
            SELECT u.id, i.id
            FROM users u
            JOIN identities i ON i.user_id = u.id
            WHERE i.identifier = $1 AND i.type = 'email' AND i.organization_id = $2
            LIMIT 1
            "#,
        )
        .bind(email)
        .bind(oid)
        .fetch_optional(db)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT u.id, i.id
            FROM users u
            JOIN identities i ON i.user_id = u.id
            WHERE i.identifier = $1 AND i.type = 'email'
            LIMIT 1
            "#,
        )
        .bind(email)
        .fetch_optional(db)
        .await?
    };

    Ok(row)
}
