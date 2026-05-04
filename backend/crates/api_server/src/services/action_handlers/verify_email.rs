//! `VerifyEmail` action handler.
//!
//! Marks the (`type='email'`, `identifier=<payload.email>`) identity row as
//! verified for the user named in the token's `sub`. Idempotent: re-running
//! the same verified action returns success without modifying the row again
//! (though replay protection at the dispatch layer means this should not
//! actually fire twice for the same `jti`).
//!
//! ## Token payload schema
//!
//! ```json
//! { "email": "alice@example.com" }
//! ```
//!
//! Binding the email into the payload (rather than relying on a lookup) defends
//! against the case where the user changes their primary email between token
//! issuance and consumption — the token verifies the email it was issued for,
//! and only that one.

use async_trait::async_trait;
use auth_core::{ActionCode, ActionTokenClaims};
use shared_types::{AppError, Result};

use super::{ActionContext, ActionHandler, ActionOutcome};

pub struct VerifyEmailHandler;

#[async_trait]
impl ActionHandler for VerifyEmailHandler {
    fn code(&self) -> ActionCode {
        ActionCode::VerifyEmail
    }

    async fn execute(
        &self,
        claims: &ActionTokenClaims,
        ctx: &ActionContext,
    ) -> Result<ActionOutcome> {
        // Extract & validate payload — the token signature attests to *this exact*
        // email having been issued, so the verify must target it specifically.
        let email = claims
            .payload
            .get("email")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::BadRequest("verify_email: missing payload.email".into()))?;

        tracing::debug!(
            request_ip = ?ctx.request_ip,
            user_agent = ?ctx.user_agent,
            "executing verify_email action"
        );

        let updated = sqlx::query(
            r#"
            UPDATE identities
               SET verified = TRUE,
                   verified_at = NOW(),
                   updated_at = NOW()
             WHERE user_id = $1
               AND type = 'email'
               AND identifier = $2
               AND verified = FALSE
            "#,
        )
        .bind(&claims.sub)
        .bind(email)
        .execute(&ctx.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Idempotent path: row already verified or never existed.
        // We don't distinguish — both answer "the email is verified now if it
        // belongs to this user". A non-existent (user, email) pair returning
        // success is not a leak because the `sub` came from a signed token.
        let _ = updated.rows_affected();

        Ok(ActionOutcome {
            code: "email_verified".into(),
            redirect_to: None,
            data: serde_json::json!({ "email": email }),
        })
    }
}
