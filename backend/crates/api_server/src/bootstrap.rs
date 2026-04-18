use sqlx::PgPool;

/// Seed System Organization and initial policies
pub async fn seed_system_org(db: &PgPool) -> anyhow::Result<()> {
    // Seed System Organization (Provider Authority)
    // Option 1: Explicitly enable AAL3 capabilities (passkey_hardware)
    sqlx::query(
        "INSERT INTO organizations (id, slug, name, enabled_capabilities) 
         VALUES ('system', 'admin', 'IDaaS Provider', '[\"password\", \"totp\", \"passkey_synced\", \"passkey_hardware\"]'::jsonb) 
         ON CONFLICT (id) DO UPDATE SET enabled_capabilities = EXCLUDED.enabled_capabilities"
    )
    .execute(db)
    .await?;
    tracing::info!("System organization verified");

    // Seed Default Organization (For demo/dev)
    sqlx::query(
        "INSERT INTO organizations (id, slug, name, enabled_capabilities) 
         VALUES ('default', 'default', 'Default Organization', '[\"password\", \"totp\", \"passkey_synced\"]'::jsonb) 
         ON CONFLICT (id) DO NOTHING"
    )
    .execute(db)
    .await?;
    tracing::info!("Default organization verified");

    // Seed Admin User (for development/testing)
    // We use a fixed ID 'user_admin' to match the debug bypass in hosted.rs
    // Seed Admin User (for development/testing)
    // We use a fixed ID 'user_admin' to match the debug bypass in hosted.rs

    // 1. Create User
    sqlx::query(
        "INSERT INTO users (id, first_name, last_name, organization_id) 
         VALUES ('user_admin', 'System', 'Admin', 'system') 
         ON CONFLICT (id) DO NOTHING",
    )
    .execute(db)
    .await?;

    // 2. Create Identity (Email)
    sqlx::query(
        "INSERT INTO identities (user_id, type, identifier, verified, organization_id) 
         VALUES ('user_admin', 'email', 'admin@example.com', true, 'system') 
         ON CONFLICT (organization_id, type, identifier) DO NOTHING",
    )
    .execute(db)
    .await?;

    // 3. Create Password (from IDAAS_BOOTSTRAP_PASSWORD env var)
    // Production: MUST be set or startup panics.
    // Development: generates random 24-char password if not set.
    let bootstrap_pw = match std::env::var("IDAAS_BOOTSTRAP_PASSWORD") {
        Ok(pw) => {
            if pw.len() < 8 {
                tracing::warn!("IDAAS_BOOTSTRAP_PASSWORD is too short (min 8 chars) — skipping admin password seed");
                None
            } else {
                Some(pw)
            }
        }
        Err(_) => {
            let is_production = std::env::var("APP_ENV")
                .map(|v| v.eq_ignore_ascii_case("production"))
                .unwrap_or(false);
            if is_production {
                panic!(
                    "IDAAS_BOOTSTRAP_PASSWORD must be set in production (APP_ENV=production). \
                     Set it to a strong password (>=8 chars) for the admin account."
                );
            }
            // Dev mode: generate and print a random password
            use rand::Rng;
            let charset: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%";
            let mut rng = rand::thread_rng();
            let random_pw: String = (0..24)
                .map(|_| {
                    let idx = rng.gen_range(0..charset.len());
                    charset[idx] as char
                })
                .collect();
            tracing::info!("══════════════════════════════════════════════════════");
            tracing::info!("  Generated admin password: {}", random_pw);
            tracing::info!("  Set IDAAS_BOOTSTRAP_PASSWORD to suppress this.");
            tracing::info!("══════════════════════════════════════════════════════");
            Some(random_pw)
        }
    };
    if let Some(pw) = bootstrap_pw {
        let password_hash = auth_core::hash_password(&pw)
            .map_err(|e| anyhow::anyhow!("Failed to hash password: {e}"))?;
        sqlx::query(
            "INSERT INTO passwords (user_id, password_hash) 
             VALUES ('user_admin', $1) 
             ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash",
        )
        .bind(password_hash)
        .execute(db)
        .await?;
        tracing::info!("Admin password set from IDAAS_BOOTSTRAP_PASSWORD");
    }

    // 4. Create Membership in System Org (Provider Admin)
    sqlx::query(
        "INSERT INTO memberships (id, organization_id, user_id, role, permissions, created_at, updated_at) 
         VALUES ('membership_admin_system', 'system', 'user_admin', 'owner', '{}'::jsonb, NOW(), NOW()) 
         ON CONFLICT (organization_id, user_id) DO NOTHING"
    )
    .execute(db)
    .await?;

    // 5. Create Membership in Default Org (For easy testing)
    sqlx::query(
        "INSERT INTO memberships (id, organization_id, user_id, role, permissions, created_at, updated_at) 
         VALUES ('membership_admin_default', 'default', 'user_admin', 'admin', '{}'::jsonb, NOW(), NOW()) 
         ON CONFLICT (organization_id, user_id) DO NOTHING"
    )
    .execute(db)
    .await?;

    tracing::info!("Admin user verified and memberships created");

    // Seed System Organization Policy (EIAA Create Tenant Capsule)
    let create_tenant_policy = r#"{
      "capsule": "CreateTenant",
      "version": 1,
      "rules": [
        { "id": "provider_signup_must_be_enabled", "if": { "equals": [{ "var": "provider_policy.signup_enabled" }, true] }, "then": "continue", "else": { "deny": "provider_signup_disabled" } },
        { "id": "flow_must_be_create_tenant", "if": { "equals": [{ "var": "flow.purpose" }, "create_tenant"] }, "then": "continue", "else": { "deny": "invalid_flow_purpose" } },
        { "id": "must_target_system_org", "if": { "equals": [{ "var": "flow.org_id" }, "system"] }, "then": "continue", "else": { "deny": "invalid_org_target" } },
        { "id": "email_must_be_verified", "if": { "equals": [{ "var": "identity.email_verified" }, true] }, "then": "continue", "else": { "deny": "email_not_verified" } },
        { "id": "password_must_be_strong", "if": { "in": [{ "var": "credentials.password_strength" }, ["strong", "very_strong"]] }, "then": "continue", "else": { "deny": "weak_password" } },
        { "id": "risk_must_be_acceptable", "if": { "in": [{ "var": "risk.overall" }, ["low", "medium"]] }, "then": "continue", "else": { "deny": "risk_too_high" } },
        { "id": "tenant_name_must_exist", "if": { "exists": { "var": "tenant.org_name" } }, "then": "continue", "else": { "deny": "missing_org_name" } },
        { "id": "tenant_name_length", "if": { "and": [{ "gte": [{ "length": { "var": "tenant.org_name" } }, 3] }, { "lte": [{ "length": { "var": "tenant.org_name" } }, 64] }] }, "then": "continue", "else": { "deny": "invalid_org_name_length" } }
      ],
      "final": {
        "allow": { "decision_type": "create_tenant", "initial_role": "OWNER", "require_post_creation_stepup": false }
      }
    }"#;

    sqlx::query(
        "INSERT INTO eiaa_policies (tenant_id, action, version, spec) VALUES ('system', 'create_tenant', 1, $1::jsonb) ON CONFLICT (tenant_id, action, version) DO UPDATE SET spec = $1::jsonb"
    )
    .bind(create_tenant_policy)
    .execute(db)
    .await?;
    tracing::info!("System CreateTenant policy verified");

    // Seed System Organization Policy (EIAA Admin Login Capsule)
    let admin_login_policy = r#"{
      "capsule": "AdminLogin",
      "version": 1,
      "rules": [
        { "id": "flow_must_be_admin_login", "if": { "equals": [{ "var": "flow.purpose" }, "admin_login"] }, "then": "continue", "else": { "deny": "invalid_flow_purpose" } },
        { "id": "auth_admin", "type": "AuthorizeAction", "action": "auth:admin_login", "resource": "platform" },
        { "id": "email_must_be_verified", "if": { "equals": [{ "var": "identity.email_verified" }, true] }, "then": "continue", "else": { "deny": "email_not_verified" } },
        { "id": "must_be_provider_or_tenant_admin", "if": { "or": [{ "equals": [{ "var": "identity.is_provider_admin" }, true] }, { "and": [{ "equals": [{ "var": "membership.exists" }, true] }, { "in": [{ "var": "membership.role" }, ["OWNER", "ADMIN"]] }] }] }, "then": "continue", "else": { "deny": "not_authorized_admin" } },
        { "id": "risk_must_be_acceptable", "if": { "in": [{ "var": "risk.overall" }, ["low", "medium"]] }, "then": "continue", "else": { "require": { "type": "assurance", "level": "AAL3", "acceptable_capabilities": ["passkey"] } } },
        { "id": "assurance_must_meet_provider_policy", "if": { "gte": [{ "var": "assurance.aal" }, { "var": "provider_policy.min_admin_aal" }] }, "then": "continue", "else": { "require": { "type": "assurance", "level": { "var": "provider_policy.min_admin_aal" } } } },
        { "id": "password_admin_login_policy", "if": { "or": [{ "equals": [{ "var": "provider_policy.allow_password_admin" }, true] }, { "not": { "in": ["password", { "var": "assurance.amr" }] } }] }, "then": "continue", "else": { "require": { "type": "assurance", "level": "AAL2", "acceptable_capabilities": ["otp", "passkey"] } } }
      ],
      "final": {
        "allow": { "decision_type": "admin_login", "session_type": "admin", "max_session_ttl": "8h" }
      }
    }"#;

    sqlx::query(
        "INSERT INTO eiaa_policies (tenant_id, action, version, spec) VALUES ('system', 'admin_login', 1, $1::jsonb) ON CONFLICT (tenant_id, action, version) DO UPDATE SET spec = $1::jsonb"
    )
    .bind(admin_login_policy)
    .execute(db)
    .await?;
    tracing::info!("System AdminLogin policy verified");

    // Seed System Organization Policy (EIAA Standard Login - Default for Tenants)
    let standard_login_policy = r#"{
      "capsule": "StandardLogin",
      "version": 1,
      "rules": [
        { "id": "flow_must_be_authenticate", "if": { "equals": [{ "var": "flow.purpose" }, "authenticate"] }, "then": "continue", "else": { "deny": "invalid_flow_purpose" } },
        { "id": "auth_login", "type": "AuthorizeAction", "action": "auth:login", "resource": "app" },
        { "id": "email_must_be_verified", "if": { "equals": [{ "var": "identity.email_verified" }, true] }, "then": "continue", "else": { "deny": "email_not_verified" } },
        
        { "id": "risk_high_block", "if": { "equals": [{ "var": "risk.overall" }, "high"] }, "then": { "deny": "risk_too_high" }, "else": "continue" },
        
        { "id": "admin_requires_aal2", "if": { "and": [{ "equals": [{ "var": "membership.exists" }, true] }, { "in": [{ "var": "membership.role" }, ["OWNER", "ADMIN"]] }] }, "then": { "require": { "type": "assurance", "level": "AAL2", "acceptable_capabilities": ["otp", "passkey"] } }, "else": "continue" },
        
        { "id": "standard_user_aal1", "if": { "in": [{ "var": "risk.overall" }, ["low", "medium"]] }, "then": { "require": { "type": "assurance", "level": "AAL1", "acceptable_capabilities": ["password", "otp", "passkey"] } }, "else": { "require": { "type": "assurance", "level": "AAL2", "acceptable_capabilities": ["otp", "passkey"] } } }
      ],
      "final": {
        "allow": { "decision_type": "authenticate", "session_type": "standard", "max_session_ttl": "24h" }
      }
    }"#;

    sqlx::query(
        "INSERT INTO eiaa_policies (tenant_id, action, version, spec) VALUES ('system', 'auth:login_default', 1, $1::jsonb) ON CONFLICT (tenant_id, action, version) DO UPDATE SET spec = $1::jsonb"
    )
    .bind(standard_login_policy)
    .execute(db)
    .await?;
    tracing::info!("System StandardLogin (Default) policy verified");

    // ── Step-Up Policy ────────────────────────────────────────────────────────
    // Capability-first: the capsule receives the user's actual enrolled factor
    // count/types and makes decisions against that reality rather than assuming
    // any particular factor exists.
    let step_up_policy = r#"{
      "version": "1.0",
      "name": "SystemStepUpPolicy",
      "description": "Capability-first step-up policy — decides based on enrolled factors and risk",
      "action": "auth:step_up",
      "rules": [
        {
          "id": "no_factors_enrolled",
          "if": { "equals": [{ "var": "enrolled_factor_count" }, 0] },
          "then": { "deny": "no_factors_enrolled" },
          "else": "continue"
        },
        {
          "id": "high_risk_passkey_available",
          "if": { "and": [
            { "gt": [{ "var": "risk_score" }, 70] },
            { "equals": [{ "var": "has_passkey_enrolled" }, 1] }
          ]},
          "then": { "require": { "type": "factor", "acceptable_capabilities": ["passkey"], "require_phishing_resistant": true } },
          "else": "continue"
        },
        {
          "id": "high_risk_no_passkey",
          "if": { "gt": [{ "var": "risk_score" }, 70] },
          "then": { "allow": { "decision_type": "step_up", "session_upgrade": "AAL2", "degraded_assurance": true } },
          "else": "continue"
        },
        {
          "id": "standard_step_up",
          "if": { "equals": [{ "var": "factor_verified" }, true] },
          "then": { "allow": { "decision_type": "step_up", "session_upgrade": "AAL2" } },
          "else": { "deny": "factor_not_verified" }
        }
      ],
      "final": {
        "allow": { "decision_type": "step_up", "session_upgrade": "AAL2" }
      }
    }"#;

    sqlx::query(
        "INSERT INTO eiaa_policies (tenant_id, action, version, spec) VALUES ('system', 'auth:step_up', 1, $1::jsonb) ON CONFLICT (tenant_id, action, version) DO UPDATE SET spec = $1::jsonb"
    )
    .bind(step_up_policy)
    .execute(db)
    .await?;
    tracing::info!("System StepUp policy verified");

    Ok(())
}
