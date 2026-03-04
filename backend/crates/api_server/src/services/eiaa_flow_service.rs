//! EIAA Flow Service
//!
//! Orchestrates risk evaluation, assurance computation, and flow management
//! for EIAA-compliant authentication flows.
//!
//! C-1: Flow expiry is enforced at the DB level via `expires_at`.
//! - `init_flow` upserts the row with `expires_at = NOW() + 10 minutes`.
//! - `load_flow_context` checks `expires_at > NOW()` and returns a distinct
//!   `FlowExpiredError` so callers can surface `FLOW_EXPIRED` to the client.
//! - `store_flow_context` adds `AND expires_at > NOW()` to the UPDATE so
//!   writes to expired flows are silently rejected (0 rows affected).

use std::collections::HashSet;
use std::net::IpAddr;

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use shared_types::{AssuranceLevel, Capability, RiskContext, RiskConstraints};
use risk_engine::{RiskEngine, RequestContext, SubjectContext, NetworkInput, WebDeviceInput};

use super::assurance_service::{AssuranceService, CapabilityService};

// ─── Flow Expiry Error ────────────────────────────────────────────────────────

/// Sentinel error returned when a flow's `expires_at` has passed.
/// Route handlers map this to `AppError::BadRequest` with `FLOW_EXPIRED` code
/// so the frontend can show a "session expired, please start over" message.
#[derive(Debug)]
pub struct FlowExpiredError {
    pub flow_id: String,
}

impl std::fmt::Display for FlowExpiredError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FLOW_EXPIRED:{}", self.flow_id)
    }
}

impl std::error::Error for FlowExpiredError {}

/// Flow context with EIAA-specific fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EiaaFlowContext {
    /// Flow ID
    pub flow_id: String,
    /// Organization ID
    pub org_id: String,
    /// Application ID (if app-specific)
    pub app_id: Option<String>,
    
    // === Assurance State ===
    /// Current achieved AAL based on verified capabilities
    pub achieved_aal: AssuranceLevel,
    /// Required AAL (max of org baseline, app requirement, risk requirement)
    pub required_aal: AssuranceLevel,
    /// Capabilities verified so far in this flow
    pub verified_capabilities: Vec<Capability>,
    
    // === Risk State ===
    /// Risk context snapshot from evaluation
    pub risk_context: RiskContext,
    /// Risk-derived constraints
    pub risk_constraints: RiskConstraints,
    
    // === Flow State ===
    /// Acceptable capabilities for next step
    pub acceptable_capabilities: Vec<Capability>,
    /// Whether flow is complete (achieved >= required)
    pub is_complete: bool,
    /// User ID if identified
    pub user_id: Option<String>,
    
    // === Security ===
    /// Hash of the ephemeral flow token required to access this state
    #[serde(default)]
    pub flow_token_hash: String,
}

impl Default for EiaaFlowContext {
    fn default() -> Self {
        Self {
            flow_id: String::new(),
            org_id: String::new(),
            app_id: None,
            achieved_aal: AssuranceLevel::AAL0,
            required_aal: AssuranceLevel::AAL1,
            verified_capabilities: vec![],
            risk_context: RiskContext::default(),
            risk_constraints: RiskConstraints::default(),
            acceptable_capabilities: vec![],
            is_complete: false,
            user_id: None,
            flow_token_hash: String::new(),
        }
    }
}

/// Step result from submitting a credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    /// Whether the step was successful
    pub success: bool,
    /// Capability that was verified (if any)
    pub verified_capability: Option<Capability>,
    /// Updated AAL after this step
    pub achieved_aal: AssuranceLevel,
    /// Whether more steps are needed
    pub needs_more_steps: bool,
    /// Next acceptable capabilities
    pub next_capabilities: Vec<Capability>,
    /// Error message if failed
    pub error: Option<String>,
}

/// EIAA Flow Orchestration Service
#[derive(Clone)]
pub struct EiaaFlowService {
    db: PgPool,
    redis: redis::aio::ConnectionManager,
    email_service: email_service::EmailService,
    risk_engine: RiskEngine,
    assurance_service: AssuranceService,
    capability_service: CapabilityService,
}


impl EiaaFlowService {
    pub fn new(db: PgPool, redis: redis::aio::ConnectionManager, email_service: email_service::EmailService) -> Self {
        Self {
            risk_engine: RiskEngine::new(db.clone()),
            assurance_service: AssuranceService::new(),
            capability_service: CapabilityService::new(),
            db,
            redis,
            email_service,
        }
    }
    
    /// Create with IPLocate client for real IP intelligence
    pub fn with_iplocate(db: PgPool, redis: redis::aio::ConnectionManager, email_service: email_service::EmailService, iplocate: risk_engine::IpLocateClient) -> Self {
        Self {
            risk_engine: RiskEngine::with_iplocate(db.clone(), iplocate),
            assurance_service: AssuranceService::new(),
            capability_service: CapabilityService::new(),
            db,
            redis,
            email_service,
        }
    }
    
    /// Initialize a new EIAA flow with risk evaluation
    pub async fn init_flow(
        &self,
        flow_id: String,
        org_id: String,
        app_id: Option<String>,
        remote_ip: IpAddr,
        user_agent: String,
        device_input: Option<WebDeviceInput>,
    ) -> Result<(EiaaFlowContext, String)> {
        // Generate ephemeral flow token
        let raw_token = shared_types::generate_id("ftk");
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(raw_token.as_bytes());
        let flow_token_hash = hex::encode(hasher.finalize());

        // Build request context
        let request = RequestContext {
            network: NetworkInput {
                remote_ip,
                x_forwarded_for: None,
                user_agent: user_agent.clone(),
                accept_language: None,
                timestamp: Utc::now(),
            },
            device: device_input,
        };
        
        // Evaluate risk (no subject yet - pre-identification)
        let risk_eval = self.risk_engine.evaluate(&request, None, Some(&flow_id)).await;
        
        // Load org/app assurance requirements
        let (org_baseline, app_required, org_enabled) = self.load_requirements(&org_id, app_id.as_deref()).await?;
        
        // Compute required AAL
        let required_aal = self.assurance_service.compute_required_aal(
            org_baseline,
            app_required,
            risk_eval.constraints.required_assurance,
        );
        
        // Compute acceptable capabilities (no user yet, use org defaults)
        let acceptable = self.capability_service.compute_acceptable(
            &org_enabled,
            &org_enabled, // Pre-identification: assume all org capabilities available
            &risk_eval.constraints,
            required_aal,
        );
        
        let ctx = EiaaFlowContext {
            flow_id,
            org_id,
            app_id,
            achieved_aal: AssuranceLevel::AAL0,
            required_aal,
            verified_capabilities: vec![],
            risk_context: risk_eval.risk,
            risk_constraints: risk_eval.constraints,
            acceptable_capabilities: acceptable,
            is_complete: false,
            user_id: None,
            flow_token_hash,
        };
        
        // Store context in flow state
        self.store_flow_context(&ctx).await?;
        
        Ok((ctx, raw_token))
    }
    
    /// Re-evaluate risk after user identification
    pub async fn identify_user(
        &self,
        flow_id: &str,
        user_id: &str,
        remote_ip: IpAddr,
        user_agent: String,
        device_input: Option<WebDeviceInput>,
    ) -> Result<EiaaFlowContext> {
        let mut ctx = self.load_flow_context(flow_id).await?
            .ok_or_else(|| anyhow::anyhow!("Flow not found"))?;
        
        ctx.user_id = Some(user_id.to_string());
        
        // Re-evaluate risk with user context
        let request = RequestContext {
            network: NetworkInput {
                remote_ip,
                x_forwarded_for: None,
                user_agent,
                accept_language: None,
                timestamp: Utc::now(),
            },
            device: device_input,
        };
        
        let subject = SubjectContext {
            subject_id: user_id.to_string(),
            org_id: ctx.org_id.clone(),
        };
        
        let risk_eval = self.risk_engine.evaluate(&request, Some(&subject), Some(flow_id)).await;
        
        // Extract values before moving
        let risk_required_aal = risk_eval.constraints.required_assurance;
        
        // Update risk context
        ctx.risk_context = risk_eval.risk;
        ctx.risk_constraints = risk_eval.constraints;
        
        // Reload requirements with new risk
        let (org_baseline, app_required, org_enabled) = self.load_requirements(&ctx.org_id, ctx.app_id.as_deref()).await?;
        
        // Load user's enrolled factors
        let user_enrolled = self.load_user_factors(user_id).await?;
        
        // Recompute required AAL
        ctx.required_aal = self.assurance_service.compute_required_aal(
            org_baseline,
            app_required,
            risk_required_aal,
        );
        
        // Recompute acceptable capabilities with user factors
        ctx.acceptable_capabilities = self.capability_service.compute_acceptable(
            &org_enabled,
            &user_enrolled,
            &ctx.risk_constraints,
            ctx.required_aal,
        );
        
        self.store_flow_context(&ctx).await?;
        
        Ok(ctx)
    }
    
    /// Record a successful credential verification
    pub async fn record_step(
        &self,
        flow_id: &str,
        capability: Capability,
    ) -> Result<StepResult> {
        let mut ctx = self.load_flow_context(flow_id).await?
            .ok_or_else(|| anyhow::anyhow!("Flow not found"))?;
        
        // Add to verified capabilities
        if !ctx.verified_capabilities.contains(&capability) {
            ctx.verified_capabilities.push(capability);
        }
        
        // Recompute achieved AAL
        ctx.achieved_aal = self.assurance_service.compute_achieved_aal(&ctx.verified_capabilities);
        
        // Check if complete
        let meets_req = self.assurance_service.meets_requirement(ctx.achieved_aal, ctx.required_aal);
        ctx.is_complete = meets_req;
        
        // Compute next capabilities if not complete
        let next_capabilities = if !meets_req {
            self.assurance_service.suggest_next_capabilities(
                ctx.required_aal,
                &ctx.verified_capabilities,
                &ctx.acceptable_capabilities,
            )
        } else {
            vec![]
        };
        
        ctx.acceptable_capabilities = next_capabilities.clone();
        
        self.store_flow_context(&ctx).await?;
        
        // Record security event
        if let Some(user_id) = &ctx.user_id {
            self.record_auth_attempt(user_id, &ctx.org_id, true, Some(capability)).await?;
        }
        
        Ok(StepResult {
            success: true,
            verified_capability: Some(capability),
            achieved_aal: ctx.achieved_aal,
            needs_more_steps: !meets_req,
            next_capabilities,
            error: None,
        })
    }
    
    /// Record a failed credential verification
    pub async fn record_failure(
        &self,
        flow_id: &str,
        capability: Capability,
        reason: &str,
    ) -> Result<StepResult> {
        let ctx = self.load_flow_context(flow_id).await?
            .ok_or_else(|| anyhow::anyhow!("Flow not found"))?;
        
        // Record failed attempt
        if let Some(user_id) = &ctx.user_id {
            self.record_auth_attempt(user_id, &ctx.org_id, false, Some(capability)).await?;
        }
        
        Ok(StepResult {
            success: false,
            verified_capability: None,
            achieved_aal: ctx.achieved_aal,
            needs_more_steps: true,
            next_capabilities: ctx.acceptable_capabilities,
            error: Some(reason.to_string()),
        })
    }
    
    /// Complete flow and create session
    pub async fn complete_flow(
        &self,
        flow_id: &str,
    ) -> Result<EiaaFlowContext> {
        let ctx = self.load_flow_context(flow_id).await?
            .ok_or_else(|| anyhow::anyhow!("Flow not found"))?;
        
        if !ctx.is_complete {
            anyhow::bail!("Flow not complete: achieved {} < required {}", 
                ctx.achieved_aal.as_str(), ctx.required_aal.as_str());
        }
        
        // Apply stabilizing events for verified AAL
        if let Some(user_id) = &ctx.user_id {
            self.risk_engine.on_successful_auth(user_id, ctx.achieved_aal).await;
        }
        
        Ok(ctx)
    }
    
    /// Trigger an Email OTP for the user in this flow
    pub async fn trigger_email_otp(&self, flow_id: &str, user_id: &str) -> Result<()> {
        // Get user's email
        let row = sqlx::query(
            "SELECT identifier FROM identities WHERE user_id = $1 AND type = 'email' LIMIT 1"
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await?;

        let email = match row {
            Some(r) => {
                use sqlx::Row;
                r.try_get::<String, _>("identifier").unwrap_or_default()
            }
            None => return Err(anyhow::anyhow!("No email identity found for user")),
        };

        if email.is_empty() {
            return Err(anyhow::anyhow!("User email is empty"));
        }

        let code_str = {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let code: u32 = rng.gen_range(100_000..=999_999);
            format!("{:06}", code)
        };

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(code_str.as_bytes());
        let hash = hex::encode(hasher.finalize());

        let redis_key = format!("idaas:flow_otp:{}", flow_id);
        let mut conn = self.redis.clone();
        redis::cmd("SETEX").arg(&redis_key).arg(300).arg(hash).query_async::<_, ()>(&mut conn).await
            .map_err(|e| anyhow::anyhow!("Failed to store OTP in Redis: {}", e))?;

        self.email_service.send_verification_code(&email, &code_str).await
            .map_err(|e| anyhow::anyhow!("Failed to send OTP email: {}", e))?;

        Ok(())
    }

    /// Verify an Email OTP submitted for the given flow
    pub async fn verify_email_otp(&self, flow_id: &str, code: &str) -> Result<()> {
        if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
            anyhow::bail!("Invalid OTP format");
        }

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(code.as_bytes());
        let computed_hash = hex::encode(hasher.finalize());

        let redis_key = format!("idaas:flow_otp:{}", flow_id);
        let mut conn = self.redis.clone();
        
        let stored_hash: Option<String> = redis::cmd("GET").arg(&redis_key).query_async(&mut conn).await
            .map_err(|e| anyhow::anyhow!("Redis error: {}", e))?;

        let stored_hash = stored_hash.ok_or_else(|| anyhow::anyhow!("OTP expired or invalid"))?;

        // Constant-time comparison to prevent timing attacks
        use subtle::ConstantTimeEq;
        if stored_hash.as_bytes().ct_eq(computed_hash.as_bytes()).unwrap_u8() == 1 {
            // Success, consume the OTP
            let _: () = redis::cmd("DEL").arg(&redis_key).query_async(&mut conn).await.unwrap_or(());
            Ok(())
        } else {
            anyhow::bail!("Invalid OTP code");
        }
    }
    
    // === Private helpers ===
    
    async fn load_requirements(
        &self,
        org_id: &str,
        app_id: Option<&str>,
    ) -> Result<(AssuranceLevel, Option<AssuranceLevel>, HashSet<Capability>)> {
        // Try to load from database, fallback to defaults
        let row = sqlx::query(
            r#"
            SELECT 
                o.baseline_assurance,
                o.enabled_capabilities,
                a.required_assurance as app_required
            FROM organizations o
            LEFT JOIN apps a ON a.id = $2
            WHERE o.id = $1
            "#
        )
        .bind(org_id)
        .bind(app_id)
        .fetch_optional(&self.db)
        .await?;
        
        let (org_baseline, org_caps, app_required) = match row {
            Some(r) => {
                use sqlx::Row;
                let baseline: String = r.try_get("baseline_assurance").unwrap_or_else(|_| "AAL1".to_string());
                let caps_json: serde_json::Value = r.try_get("enabled_capabilities").unwrap_or_else(|_| serde_json::json!(["password", "totp", "passkey_synced"]));
                let app_req: Option<String> = r.try_get("app_required").ok();
                
                (
                    baseline.parse().unwrap_or(AssuranceLevel::AAL1),
                    CapabilityService::from_json_array(&caps_json),
                    app_req.and_then(|s| s.parse().ok()),
                )
            }
            None => (
                AssuranceLevel::AAL1,
                CapabilityService::default_org_enabled(),
                None,
            ),
        };
        
        Ok((org_baseline, app_required, org_caps))
    }
    
    async fn load_user_factors(&self, user_id: &str) -> Result<HashSet<Capability>> {
        let rows = sqlx::query(
            r#"
            SELECT capability FROM user_factors
            WHERE user_id = $1 AND verified = true
            "#
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await?;
        
        let mut factors = HashSet::new();
        for row in rows {
            use sqlx::Row;
            let cap_str: String = row.get("capability");
            if let Ok(cap) = serde_json::from_value(serde_json::Value::String(cap_str)) {
                factors.insert(cap);
            }
        }
        
        // Always include password as base factor
        factors.insert(Capability::Password);
        
        Ok(factors)
    }
    
    /// C-1: Upsert the flow context row.
    ///
    /// On first call (`init_flow`) the row does not yet exist, so we INSERT it
    /// with `expires_at = NOW() + 10 minutes`.  On subsequent calls we UPDATE
    /// only if the row has not yet expired (`AND expires_at > NOW()`).
    /// If the row is expired the UPDATE affects 0 rows — the write is silently
    /// dropped, and the next `load_flow_context` call will return `FlowExpiredError`.
    async fn store_flow_context(&self, ctx: &EiaaFlowContext) -> Result<()> {
        let ctx_json = serde_json::to_value(ctx)?;

        sqlx::query(
            r#"
            INSERT INTO hosted_auth_flows (flow_id, org_id, app_id, execution_state, expires_at)
            VALUES ($1, $2, $3, $4, NOW() + INTERVAL '10 minutes')
            ON CONFLICT (flow_id) DO UPDATE
                SET execution_state = EXCLUDED.execution_state
                WHERE hosted_auth_flows.expires_at > NOW()
            "#
        )
        .bind(&ctx.flow_id)
        .bind(&ctx.org_id)
        .bind(&ctx.app_id)
        .bind(&ctx_json)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// C-1: Load flow context, enforcing expiry.
    ///
    /// Returns:
    /// - `Ok(Some(ctx))` — flow exists and has not expired
    /// - `Ok(None)`      — flow does not exist at all
    /// - `Err(FlowExpiredError)` — flow exists but `expires_at <= NOW()`
    ///
    /// Route handlers convert `FlowExpiredError` → `AppError::BadRequest`
    /// with `error_code = "FLOW_EXPIRED"` so the frontend can show a
    /// "Your session has expired, please start over" message.
    pub async fn load_flow_context(&self, flow_id: &str) -> Result<Option<EiaaFlowContext>> {
        // Fetch both the state and the expiry timestamp in one query.
        let row = sqlx::query(
            r#"
            SELECT execution_state, expires_at, (expires_at <= NOW()) AS is_expired
            FROM hosted_auth_flows
            WHERE flow_id = $1
            "#
        )
        .bind(flow_id)
        .fetch_optional(&self.db)
        .await?;

        match row {
            None => Ok(None),
            Some(r) => {
                use sqlx::Row;

                // C-1: Reject expired flows with a distinct error so the route
                // handler can return FLOW_EXPIRED instead of a generic 404.
                let is_expired: bool = r.try_get("is_expired").unwrap_or(false);
                if is_expired {
                    return Err(anyhow::Error::new(FlowExpiredError {
                        flow_id: flow_id.to_string(),
                    }));
                }

                let state: serde_json::Value = r.get("execution_state");

                // If state is empty/null, return default context
                if state.is_null() || (state.is_object() && state.as_object().unwrap().is_empty()) {
                    return Ok(Some(EiaaFlowContext {
                        flow_id: flow_id.to_string(),
                        ..Default::default()
                    }));
                }

                let ctx: EiaaFlowContext = serde_json::from_value(state)?;
                Ok(Some(ctx))
            }
        }
    }
    
    async fn record_auth_attempt(
        &self,
        user_id: &str,
        org_id: &str,
        success: bool,
        capability: Option<Capability>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO auth_attempts (id, user_id, org_id, success, failure_reason, created_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            "#
        )
        .bind(shared_types::generate_id("aat"))
        .bind(user_id)
        .bind(org_id)
        .bind(success)
        .bind(if success { None } else { Some(capability.map(|c| c.as_str()).unwrap_or("unknown")) })
        .execute(&self.db)
        .await?;
        
        Ok(())
    }
}
