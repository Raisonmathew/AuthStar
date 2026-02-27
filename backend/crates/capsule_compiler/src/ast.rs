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
    VerifyIdentity { source: IdentitySource },
    EvaluateRisk { profile: String },
    RequireFactor { factor_type: FactorType },
    /// Collect credentials from user (signup)
    CollectCredentials,
    /// Require verification (e.g., email)
    RequireVerification { verification_type: String },
    #[serde(rename = "if")]
    Conditional {
        condition: Condition,
        #[serde(rename = "then")]
        then_branch: Vec<Step>,
        #[serde(rename = "else")]
        else_branch: Option<Vec<Step>>,
    },
    AuthorizeAction { action: String, resource: String },
    Allow(bool), // "allow": true
    Deny(bool),  // "deny": true
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
