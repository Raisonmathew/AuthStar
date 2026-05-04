//! Action Token Framework (T1.4)
//!
//! ## Purpose
//!
//! Generalises the email-verify "signed URL" pattern into a typed, single-use,
//! short-lived token framework. Each token is bound to a specific *action*
//! (e.g. verify_email, reset_password, magic_link, accept_invite, link_account)
//! and carries a unique `jti` for replay protection.
//!
//! ## EIAA Fit
//!
//! Action tokens carry **identity** (`sub`, `tenant_id`) plus a typed *purpose*
//! discriminator (`act`). They DO NOT carry roles, scopes, or permissions —
//! the EIAA invariant is preserved. Authorisation (whether the action may
//! execute now) is still decided by a capsule downstream.
//!
//! ## Design Pattern
//!
//! - **Command pattern.** The token *is* the serialised command; the handler
//!   (in `api_server::services::action_handlers`) is the executor.
//! - **Newtype + sealed enum.** `ActionCode` is closed over the actions we ship,
//!   preventing typos and forgotten-handler bugs at compile time.
//!
//! ## Wire Format
//!
//! ```text
//! eyJhbGciOiJFUzI1NiIsImtpZCI6Ii4uLiJ9.<base64url-payload>.<base64url-sig>
//! ```
//!
//! The payload is an `ActionTokenClaims` JSON object signed with the platform
//! ES256 key (the same key used for session JWTs). Replay protection is
//! the responsibility of the consumer (typically via `NonceStore::check_and_mark`
//! on the `jti` claim).
//!
//! ## Lifetime Guidance
//!
//! | Action          | Recommended TTL |
//! |-----------------|-----------------|
//! | VerifyEmail     | 24 h            |
//! | ResetPassword   | 1 h             |
//! | MagicLink       | 10 min          |
//! | AcceptInvite    | 7 d             |
//! | LinkAccount     | 10 min          |
//! | UpdateEmail     | 1 h             |
//!
//! TTLs are enforced by the JWT `exp` claim and validated on `verify_action_token`.

use crate::JwtService;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use shared_types::{AppError, Result};

/// Audience claim for all action tokens.
///
/// Distinct from session JWTs (which use the platform audience) so an action
/// token cannot be confused with — or substituted for — a session credential.
pub const ACTION_TOKEN_AUDIENCE: &str = "urn:authstar:action-token";

/// Typed action discriminator. Closed enum: every variant must have a registered
/// handler. Adding a new action is a compile-time event in both auth_core and
/// the action_handlers registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionCode {
    /// Verify a user's email address (post-signup or after email change).
    VerifyEmail,
    /// Reset password — the token consumer presents a new password.
    ResetPassword,
    /// Passwordless login via emailed link.
    MagicLink,
    /// Accept an organisation invitation.
    AcceptInvite,
    /// Link an external IdP account to an existing local account
    /// (broker first-login flow).
    LinkAccount,
    /// Confirm an email change after the user updates their profile.
    UpdateEmail,
}

impl ActionCode {
    /// Stable string code — used in URL paths, audit logs, and DB lookups.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::VerifyEmail => "verify_email",
            Self::ResetPassword => "reset_password",
            Self::MagicLink => "magic_link",
            Self::AcceptInvite => "accept_invite",
            Self::LinkAccount => "link_account",
            Self::UpdateEmail => "update_email",
        }
    }

    /// Default TTL recommendation for this action.
    pub fn recommended_ttl(&self) -> Duration {
        match self {
            Self::VerifyEmail => Duration::hours(24),
            Self::ResetPassword => Duration::hours(1),
            Self::MagicLink => Duration::minutes(10),
            Self::AcceptInvite => Duration::days(7),
            Self::LinkAccount => Duration::minutes(10),
            Self::UpdateEmail => Duration::hours(1),
        }
    }
}

/// Action token claims. Signed with the platform ES256 key.
///
/// Note the absence of `roles`, `scopes`, `permissions`, `entitlements` —
/// EIAA invariant is preserved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionTokenClaims {
    /// Unique token id — used for one-time-use enforcement via the nonce store.
    pub jti: String,

    /// Subject (user id this action applies to).
    pub sub: String,

    /// Tenant the action is scoped to.
    pub tenant_id: String,

    /// Issuer — must match `JwtService::get_issuer()`.
    pub iss: String,

    /// Audience — must equal [`ACTION_TOKEN_AUDIENCE`].
    pub aud: String,

    /// Issued-at (unix seconds).
    pub iat: i64,

    /// Expiry (unix seconds).
    pub exp: i64,

    /// Not-before (unix seconds).
    pub nbf: i64,

    /// Action discriminator.
    pub act: ActionCode,

    /// Free-form action-specific payload (e.g. the new email for `UpdateEmail`).
    /// Validated by the action handler; treated as untrusted data here.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub payload: serde_json::Value,
}

/// Sign a fresh action token. Generates a random `jti` and timestamps automatically.
///
/// The caller chooses the TTL (or uses [`ActionCode::recommended_ttl`]).
///
/// # Errors
///
/// Returns `AppError::Internal` if the underlying ES256 signer fails (shouldn't
/// happen with a healthy keystore).
pub fn sign_action_token(
    jwt: &JwtService,
    user_id: &str,
    tenant_id: &str,
    action: ActionCode,
    ttl: Duration,
    payload: serde_json::Value,
) -> Result<(String, ActionTokenClaims)> {
    let now = Utc::now();
    let mut jti_bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut jti_bytes);
    let claims = ActionTokenClaims {
        jti: format!("act_{}", URL_SAFE_NO_PAD.encode(jti_bytes)),
        sub: user_id.to_string(),
        tenant_id: tenant_id.to_string(),
        iss: jwt.get_issuer().to_string(),
        aud: ACTION_TOKEN_AUDIENCE.to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: (now + ttl).timestamp(),
        act: action,
        payload,
    };

    let token = jwt.sign_claims(&claims)?;
    Ok((token, claims))
}

/// Verify an action token's signature, expiry, audience, and (optionally)
/// expected action code.
///
/// **Replay protection is the caller's responsibility** — pass `claims.jti`
/// to your `NonceStore::check_and_mark` after a successful verify.
///
/// # Errors
///
/// - `AppError::Unauthorized` for bad signature, expired, or wrong audience.
/// - `AppError::BadRequest` if `expected_action` is `Some(_)` and the token's
///   `act` does not match — prevents cross-action token confusion attacks
///   (e.g. a `ResetPassword` token presented to a `MagicLink` endpoint).
pub fn verify_action_token(
    jwt: &JwtService,
    token: &str,
    expected_action: Option<ActionCode>,
) -> Result<ActionTokenClaims> {
    // Use verify_token_as<T> which validates iss, exp, nbf, signature.
    // Audience is checked manually below because verify_token_as skips audience.
    let claims: ActionTokenClaims = jwt.verify_token_as(token)?;

    if claims.aud != ACTION_TOKEN_AUDIENCE {
        return Err(AppError::Unauthorized(
            "action token: wrong audience".to_string(),
        ));
    }

    if let Some(expected) = expected_action {
        if claims.act != expected {
            return Err(AppError::BadRequest(format!(
                "action token: expected '{}', got '{}'",
                expected.as_str(),
                claims.act.as_str()
            )));
        }
    }

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_jwt() -> JwtService {
        let private_key = include_str!("../../../.keys/private.pem");
        let public_key = include_str!("../../../.keys/public.pem");
        JwtService::new_ec(
            private_key,
            public_key,
            "https://auth.test.com".to_string(),
            "https://api.test.com".to_string(),
            60,
        )
        .expect("JWT service")
    }

    #[test]
    fn round_trip_ok() {
        let jwt = make_jwt();
        let (token, claims) = sign_action_token(
            &jwt,
            "user_abc",
            "tnt_xyz",
            ActionCode::VerifyEmail,
            ActionCode::VerifyEmail.recommended_ttl(),
            serde_json::Value::Null,
        )
        .unwrap();

        let verified = verify_action_token(&jwt, &token, Some(ActionCode::VerifyEmail)).unwrap();
        assert_eq!(verified.sub, "user_abc");
        assert_eq!(verified.tenant_id, "tnt_xyz");
        assert_eq!(verified.act, ActionCode::VerifyEmail);
        assert_eq!(verified.jti, claims.jti);
        assert!(verified.jti.starts_with("act_"));
    }

    #[test]
    fn wrong_action_rejected() {
        let jwt = make_jwt();
        let (token, _) = sign_action_token(
            &jwt,
            "user_abc",
            "tnt_xyz",
            ActionCode::ResetPassword,
            Duration::minutes(10),
            serde_json::json!({ "force_logout": true }),
        )
        .unwrap();

        let err = verify_action_token(&jwt, &token, Some(ActionCode::MagicLink)).unwrap_err();
        match err {
            AppError::BadRequest(msg) => {
                assert!(msg.contains("magic_link"));
                assert!(msg.contains("reset_password"));
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn expired_rejected() {
        let jwt = make_jwt();
        // Sign with a TTL well beyond the JWT library's default 60s leeway → already expired.
        let (token, _) = sign_action_token(
            &jwt,
            "user_abc",
            "tnt_xyz",
            ActionCode::MagicLink,
            Duration::seconds(-3600),
            serde_json::Value::Null,
        )
        .unwrap();

        let err = verify_action_token(&jwt, &token, Some(ActionCode::MagicLink)).unwrap_err();
        assert!(matches!(err, AppError::Unauthorized(_)));
    }

    #[test]
    fn payload_round_trips() {
        let jwt = make_jwt();
        let payload = serde_json::json!({
            "new_email": "alice@example.com",
            "previous_email_hash": "deadbeef"
        });
        let (token, _) = sign_action_token(
            &jwt,
            "user_abc",
            "tnt_xyz",
            ActionCode::UpdateEmail,
            Duration::hours(1),
            payload.clone(),
        )
        .unwrap();

        let verified = verify_action_token(&jwt, &token, Some(ActionCode::UpdateEmail)).unwrap();
        assert_eq!(verified.payload, payload);
    }

    #[test]
    fn no_expected_action_accepts_any() {
        let jwt = make_jwt();
        let (token, _) = sign_action_token(
            &jwt,
            "user_abc",
            "tnt_xyz",
            ActionCode::AcceptInvite,
            Duration::days(1),
            serde_json::Value::Null,
        )
        .unwrap();

        let verified = verify_action_token(&jwt, &token, None).unwrap();
        assert_eq!(verified.act, ActionCode::AcceptInvite);
    }

    #[test]
    fn action_code_strings_are_stable() {
        // Cross-language interop relies on these stable strings — do not change.
        assert_eq!(ActionCode::VerifyEmail.as_str(), "verify_email");
        assert_eq!(ActionCode::ResetPassword.as_str(), "reset_password");
        assert_eq!(ActionCode::MagicLink.as_str(), "magic_link");
        assert_eq!(ActionCode::AcceptInvite.as_str(), "accept_invite");
        assert_eq!(ActionCode::LinkAccount.as_str(), "link_account");
        assert_eq!(ActionCode::UpdateEmail.as_str(), "update_email");
    }

    #[test]
    fn jti_is_unique_per_call() {
        let jwt = make_jwt();
        let mk = || {
            sign_action_token(
                &jwt,
                "user_abc",
                "tnt_xyz",
                ActionCode::MagicLink,
                Duration::minutes(10),
                serde_json::Value::Null,
            )
            .unwrap()
            .1
            .jti
        };
        // 100 fresh tokens — collision probability ~ 1/2^192, vanishingly small.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            let jti = mk();
            assert!(seen.insert(jti), "jti collided");
        }
    }
}
