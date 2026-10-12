//! Session lifecycle helpers shared across auth handlers.
//!
//! ## Why this module exists
//!
//! Session promotion (elevating `is_provisional` → false, bumping `aal_level`,
//! appending to `verified_capabilities`) was previously duplicated as raw SQL in
//! three places inside `routes/auth/step_up.rs`:
//!
//!   • passkey branch  (line ~352)
//!   • email OTP branch (line ~435)
//!   • TOTP branch (via `verify_factor_for_session` in UserFactorService)
//!
//! A fourth copy was about to be added for the agent consent flow.
//!
//! Centralising the logic here means:
//!   • Schema changes to `sessions` need a one-line fix.
//!   • `GREATEST(aal_level, $new)` prevents accidentally downgrading an AAL3
//!     session to AAL2 — something two of the three previous copies got wrong by
//!     hard-coding `aal_level = 2`.
//!   • The consent handler can call the same function and gets correct behaviour
//!     for free (P8 fix; P9 design requirement).

use shared_types::{AppError, Result};
use sqlx::PgPool;

/// Promote a session to the given AAL level and record the capability that
/// was just satisfied.
///
/// ## Invariants enforced
///
/// * `is_provisional` is always set to `false` — a promoted session is never
///   provisional.
/// * `aal_level` uses `GREATEST(current, $new)` — a session can only go up,
///   never down.  This prevents an email-OTP step-up from downgrading an
///   AAL3 hardware-key session.
/// * `verified_capabilities` is append-only: the capability is added only when
///   it is not already present (idempotent).
///
/// ## Errors
///
/// Returns [`AppError::NotFound`] when no matching session row exists (wrong
/// `session_id`, `user_id`, or `tenant_id`). Returns [`AppError::Internal`] on
/// database errors.
pub async fn promote_session(
    db: &PgPool,
    session_id: &str,
    user_id: &str,
    tenant_id: &str,
    aal_level: i16,
    capability: &str,
) -> Result<()> {
    let rows = sqlx::query(
        r#"
        UPDATE sessions
        SET
            is_provisional        = false,
            aal_level             = GREATEST(aal_level, $1),
            verified_capabilities = CASE
                WHEN verified_capabilities @> to_jsonb($2::text)
                    THEN verified_capabilities
                ELSE verified_capabilities || to_jsonb($2::text)
            END,
            updated_at = NOW()
        WHERE id = $3
          AND user_id = $4
          AND tenant_id = $5
        "#,
    )
    .bind(aal_level)
    .bind(capability)
    .bind(session_id)
    .bind(user_id)
    .bind(tenant_id)
    .execute(db)
    .await
    .map_err(|e| AppError::Internal(format!("session promote: {e}")))?
    .rows_affected();

    if rows == 0 {
        return Err(AppError::NotFound(format!(
            "Session {session_id} not found for user {user_id} in tenant {tenant_id}"
        )));
    }
    Ok(())
}
