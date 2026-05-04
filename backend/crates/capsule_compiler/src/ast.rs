use serde::{Deserialize, Serialize};

/// EIAA AST Version 1.0
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Program {
    #[serde(default = "default_version")]
    pub version: String,
    pub sequence: Vec<Step>,
}

fn default_version() -> String {
    "EIAA-AST-1.0".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    VerifyIdentity {
        source: IdentitySource,
    },
    EvaluateRisk {
        profile: String,
    },
    RequireFactor {
        factor_type: FactorType,
    },
    /// Collect credentials from user (signup)
    CollectCredentials,
    /// Require verification (e.g., email)
    RequireVerification {
        verification_type: String,
    },
    /// T1.1 — Required Actions. Deny/NeedInput if the named action is still
    /// pending for the subject (for example `verify_email`, `configure_mfa`,
    /// `update_password`). The AS/API layer owns action completion; the
    /// capsule decides whether a pending action blocks this flow.
    RequireUserAction {
        code: String,
    },
    #[serde(rename = "if")]
    Conditional {
        condition: Condition,
        #[serde(rename = "then")]
        then_branch: Vec<Step>,
        #[serde(rename = "else")]
        else_branch: Option<Vec<Step>>,
    },
    AuthorizeAction {
        action: String,
        resource: String,
    },
    Allow(bool), // "allow": true
    Deny(bool),  // "deny": true
    /// T4.3 — Composite pattern: aggregate decisions from multiple referenced
    /// sub-capsules using a strategy. The step itself is *terminal-equivalent*:
    /// it produces a final Allow/Deny by combining the children's outcomes,
    /// so it must be the last step in the program (verifier rule R30).
    ///
    /// Sub-capsules are referenced by their canonical AST hash (hex-encoded
    /// SHA-256). The runtime resolves each ref against a signed registry and
    /// re-executes them under the same `RuntimeContext`. A future runtime
    /// extension will add the host import; the current lowering fails closed
    /// with reason `"aggregation_unsupported"` to preserve the fail-closed
    /// invariant until the runtime side ships.
    AggregateDecision {
        strategy: AggregationStrategy,
        sub_capsules: Vec<CapsuleRef>,
    },
    /// T2.7 — Token Mappers. Declare which extra claims the AS should add to
    /// the issued token *if* the capsule reaches an Allow terminal. Pure
    /// metadata: the WASM lowering is a transparent pass-through (no bytes
    /// emitted) and the AS reads the mappings directly from the AST when
    /// building the token.
    ///
    /// EIAA invariant: every mapper sources from server-side facts (user
    /// profile rows, tenant config, attestation), never from request input.
    /// `ClaimMapper::Static { value }` carries values the *capsule signer*
    /// chose at compile time, not the caller — still server-side authority.
    ShapeClaims {
        mappings: Vec<ClaimMapper>,
    },
}

/// T2.7 — Closed enum of built-in claim mappers (Visitor pattern entries).
/// Each variant names a server-side fact that the AS knows how to project
/// into the issued token. New mappers are added here, never via untrusted
/// user input.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClaimMapper {
    /// `email` claim sourced from `users.email`.
    Email,
    /// `email_verified` boolean from `users.email_verified_at IS NOT NULL`.
    EmailVerified,
    /// `name` claim — full display name.
    Name,
    /// `given_name` claim.
    GivenName,
    /// `family_name` claim.
    FamilyName,
    /// `preferred_username` claim.
    PreferredUsername,
    /// `picture` URL claim.
    Picture,
    /// `updated_at` (Unix seconds) — from `users.updated_at`.
    UpdatedAt,
    /// Static literal claim authored by the capsule signer. Allowed because
    /// the value is fixed at policy-signing time, not derived from caller
    /// input. Restricted to JSON scalars (string|number|bool|null).
    Static { name: String, value: serde_json::Value },
}

/// Decision aggregation strategy (T4.3). Modelled on Keycloak's
/// `Affirmative` / `Unanimous` / `Consensus` decision strategies, adapted to
/// the EIAA ternary outcome space (Allow/Deny/NeedInput).
///
/// - `Affirmative` — allow if **any** sub-capsule allows; deny otherwise.
/// - `Unanimous`   — allow only if **all** sub-capsules allow; deny otherwise.
/// - `Consensus`   — allow if strictly more allows than denies; tie → deny.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AggregationStrategy {
    Affirmative,
    Unanimous,
    Consensus,
}

/// Reference to a sub-capsule by its canonical AST SHA-256 hash (hex-encoded,
/// 64 lowercase hex chars). The runtime resolves the hash against a signed
/// capsule registry; this avoids embedding sub-capsule bytes inside the
/// parent AST and keeps the parent's hash stable when sub-capsule WASM is
/// re-lowered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapsuleRef {
    pub ast_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentitySource {
    Primary,
    Federated,
    Device,
    Biometric,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FactorType {
    Otp,
    Passkey,
    Password,
    Biometric,
    HardwareKey,
    /// Any of the listed factors (choice)
    Any(Vec<FactorType>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Condition {
    RiskScore {
        comparator: Comparator,
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<i64>,
    },
    IdentityLevel {
        comparator: Comparator,
        level: IdentityLevel,
    },
    Context {
        key: String,
        comparator: Comparator,
        value: ContextValue,
    },
    AuthzResult {
        comparator: Comparator,
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<i64>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Comparator {
    #[serde(rename = ">")]
    Gt,
    #[serde(rename = ">=")]
    Gte,
    #[serde(rename = "<")]
    Lt,
    #[serde(rename = "<=")]
    Lte,
    #[serde(rename = "==")]
    Eq,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentityLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ContextValue {
    String(String),
    Integer(i64),
    // No float allowed per spec
}
