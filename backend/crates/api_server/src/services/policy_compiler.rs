//! Policy Storage Service
//!
//! Stores compiled policies to database.
//! Uses capsule_compiler::policy_compiler for compilation logic.

use anyhow::Result;
use sqlx::PgPool;

// Re-export from capsule_compiler for convenience
pub use capsule_compiler::ast::Program;
pub use capsule_compiler::policy_compiler::{LoginMethodsConfig, PolicyCompiler};

/// Extended policy operations with database storage
pub struct PolicyStorage;

impl PolicyStorage {
    /// Store compiled policy in database
    pub async fn store_policy(
        db: &PgPool,
        tenant_id: &str,
        action: &str,
        policy: &Program,
    ) -> Result<String> {
        let policy_id = shared_types::id_generator::generate_id("pol");
        let spec = serde_json::to_value(policy)?;

        // Get next version
        let version: i32 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(version), 0) + 1 FROM eiaa_policies WHERE tenant_id = $1 AND action = $2"
        )
        .bind(tenant_id)
        .bind(action)
        .fetch_one(db)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO eiaa_policies (id, tenant_id, action, version, spec, created_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            "#,
        )
        .bind(&policy_id)
        .bind(tenant_id)
        .bind(action)
        .bind(version)
        .bind(&spec)
        .execute(db)
        .await?;

        tracing::info!(
            tenant_id = %tenant_id,
            action = %action,
            version = %version,
            "Stored compiled policy"
        );

        Ok(policy_id)
    }

    /// Compile and store both login and signup policies
    pub async fn compile_and_store_all(
        db: &PgPool,
        tenant_id: &str,
        login_methods: &LoginMethodsConfig,
        require_email_verification: bool,
    ) -> Result<()> {
        // Compile authentication policy
        let auth_policy = PolicyCompiler::compile_auth_policy(login_methods);
        Self::store_policy(db, tenant_id, "auth:login", &auth_policy).await?;

        // Compile signup policy
        let signup_policy = PolicyCompiler::compile_signup_policy(require_email_verification);
        Self::store_policy(db, tenant_id, "auth:signup", &signup_policy).await?;

        tracing::info!(
            tenant_id = %tenant_id,
            "Compiled and stored all policies"
        );

        Ok(())
    }
}
