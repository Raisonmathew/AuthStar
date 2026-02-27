use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use redis::aio::ConnectionManager;
use auth_core::JwtService;
use crate::config::Config;
use std::sync::Arc;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use grpc_api::eiaa::runtime::capsule_runtime_client::CapsuleRuntimeClient;
use keystore::{InMemoryKeystore, KeyId, Keystore};
use tonic::transport::{Channel, Endpoint};
use email_service::{EmailService, EmailServiceConfig};
use identity_engine::services::{VerificationService, MfaService, OAuthService, PasskeyService};
use crate::services::eiaa_flow_service::EiaaFlowService;
use crate::services::{CapsuleCacheService, AuditWriter, AuditWriterBuilder, RuntimeKeyCache, AttestationVerifier, AttestationDecisionCache};
use risk_engine::RiskEngine;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub jwt_service: Arc<JwtService>,
    pub config: Arc<Config>,
    pub runtime_client: CapsuleRuntimeClient<Channel>,
    pub ks: InMemoryKeystore,
    pub compiler_kid: KeyId,
    pub stripe_service: billing_engine::services::StripeService,
    pub webhook_service: billing_engine::services::WebhookService,
    pub app_service: org_manager::services::AppService,
    pub organization_service: org_manager::services::OrganizationService,
    pub user_service: identity_engine::services::UserService,
    pub verification_service: VerificationService,
    pub mfa_service: MfaService,
    pub oauth_service: OAuthService,
    pub passkey_service: PasskeyService,
    pub eiaa_flow_service: EiaaFlowService,
    pub email_service: EmailService,
    // EIAA: Capsule caching and audit trail
    pub capsule_cache: CapsuleCacheService,
    pub audit_writer: AuditWriter,
    // EIAA Remediation: Key cache and attestation verification
    pub runtime_key_cache: RuntimeKeyCache,
    pub attestation_verifier: AttestationVerifier,
    // EIAA: Risk Engine for real-time risk evaluation
    pub risk_engine: RiskEngine,
    // EIAA: Attestation decision cache (frequency matrix)
    pub decision_cache: AttestationDecisionCache,
    // EIAA: User Factor Service for step-up auth
    pub user_factor_service: crate::services::UserFactorService,
}

impl AppState {
    pub async fn new(config: Config) -> anyhow::Result<Self> {
        // Database connection pool
        tracing::info!("Connecting to database...");
        let db = PgPoolOptions::new()
            .max_connections(config.database.max_connections)
            .connect(&config.database.url)
            .await?;
        tracing::info!("Database connected");
        
        Self::new_with_pool(config, db).await
    }

    pub async fn new_with_pool(config: Config, db: PgPool) -> anyhow::Result<Self> {
        // Run database migrations
        tracing::info!("Running database migrations...");
        db_migrations::run_migrations(&db).await
            .map_err(|e| anyhow::anyhow!("Failed to run migrations: {}", e))?;
        tracing::info!("Database migrations applied successfully");

        // Redis connection
        tracing::info!("Connecting to Redis...");
        let redis_client = redis::Client::open(config.redis.url.as_str())?;
        let redis = ConnectionManager::new(redis_client).await?;
        tracing::info!("Redis connected");

        // JWT service (EIAA-compliant, identity-only)
        tracing::info!("Initializing JWT service (ES256)...");
        let jwt_service = Arc::new(JwtService::new_ec(
            &config.jwt.private_key,
            &config.jwt.public_key,
            config.jwt.issuer.clone(),
            config.jwt.audience.clone(),
            config.jwt.expiration_seconds,
        )?);
        tracing::info!("JWT service initialized");

        // EIAA: compiler keystore
        // COMPILER_SK_B64 provides persistent Ed25519 signing key.
        // Without it, keys are ephemeral and all attestations become unverifiable after restart.
        tracing::info!("Initializing keystore...");
        let ks = InMemoryKeystore::ephemeral();
        let compiler_kid = if let Some(sk_b64) = &config.eiaa.compiler_sk_b64 {
            let sk_bytes = URL_SAFE_NO_PAD
                .decode(sk_b64.as_bytes())
                .map_err(|_| anyhow::anyhow!("COMPILER_SK_B64 invalid base64"))?;
            let kid = ks.import_ed25519(&sk_bytes)?;
            tracing::info!("Keystore initialized with persistent key (kid: {:?})", kid);
            kid
        } else {
            let kid = ks.generate_ed25519()?;
            tracing::warn!("⚠️  Keystore using EPHEMERAL key (kid: {:?}) — set COMPILER_SK_B64 for production!", kid);
            kid
        };

        // Runtime gRPC client
        tracing::info!("Connecting to runtime at {}...", config.eiaa.runtime_grpc_addr);
        let channel = Endpoint::from_shared(config.eiaa.runtime_grpc_addr.clone())?
            .connect_lazy();
        let runtime_client = CapsuleRuntimeClient::new(channel);
        tracing::info!("Runtime client connected");


        let stripe_service = billing_engine::services::StripeService::new(db.clone(), config.stripe.secret_key.clone());
        let webhook_service = billing_engine::services::WebhookService::new(db.clone());
        let app_service = org_manager::services::AppService::new(db.clone());
        let organization_service = org_manager::services::OrganizationService::new(db.clone());
        let user_service = identity_engine::services::UserService::new(db.clone());
        let oauth_service = identity_engine::services::OAuthService::new(db.clone());
        
        // Email Service
        let email_config = EmailServiceConfig::from_legacy(
            config.email.sendgrid_api_key.clone(),
            config.email.from_email.clone(),
            config.email.from_name.clone(),
            3,
            1000,
        );
        let email_service = EmailService::new(email_config);

        // Verification Service
        let verification_service = VerificationService::new(db.clone(), email_service.clone());

        // MFA Service
        let mfa_service = MfaService::new(db.clone(), "IDaaS".to_string());

        // Passkey Service (with Redis session storage)
        let rpid = config.passkey_rp_id.clone();
        let origin = config.passkey_origin.clone();
        let passkey_service = PasskeyService::new(db.clone(), redis.clone(), &rpid, &origin)
            .map_err(|e| anyhow::anyhow!("Failed to init passkey service: {}", e))?;

        // EIAA Flow Service (risk + assurance orchestration)
        // Use IPLocate for real IP intelligence when enabled, otherwise use basic constructor
        let eiaa_flow_service = if config.eiaa.iplocate_enabled {
            let iplocate_client = risk_engine::IpLocateClient::new(
                config.eiaa.iplocate_api_key.clone(),
                true,
            );
            EiaaFlowService::with_iplocate(db.clone(), redis.clone(), email_service.clone(), iplocate_client)
        } else {
            EiaaFlowService::new(db.clone(), redis.clone(), email_service.clone())
        };

        // EIAA: Capsule cache service (1 hour TTL)
        let capsule_cache = CapsuleCacheService::new(redis.clone(), 3600);
        tracing::info!("Capsule cache service initialized (1h TTL)");

        // EIAA: Async audit writer for high-throughput logging
        let audit_writer = AuditWriterBuilder::new(db.clone())
            .batch_size(100)
            .flush_interval_ms(100)
            .channel_size(10_000)
            .build();
        tracing::info!("Audit writer initialized");

        // EIAA Remediation: Runtime key cache (5 minute TTL)
        let runtime_key_cache = RuntimeKeyCache::with_ttl(300);
        tracing::info!("Runtime key cache initialized (5m TTL)");

        // EIAA Remediation: Attestation verifier (shares key cache internally)
        let attestation_verifier = AttestationVerifier::new();
        tracing::info!("Attestation verifier initialized");

        // EIAA: Risk Engine for real-time risk evaluation
        let risk_engine = RiskEngine::new(db.clone());
        tracing::info!("Risk Engine initialized");

        // EIAA: Attestation decision cache (frequency matrix)
        let decision_cache = AttestationDecisionCache::new();
        // EIAA: User Factor Service for step-up auth
        let factor_encryption = crate::services::factor_encryption::FactorEncryption::new(
            std::env::var("FACTOR_ENCRYPTION_KEY").ok().as_deref()
        );
        let user_factor_service = crate::services::UserFactorService::with_encryption(db.clone(), factor_encryption);
        tracing::info!("User Factor service initialized");

        Ok(Self {
            db,
            jwt_service,
            config: Arc::new(config),
            runtime_client,
            ks,
            compiler_kid,
            stripe_service,
            webhook_service,
            app_service,
            organization_service,
            user_service,
            verification_service,
            mfa_service,
            oauth_service,
            passkey_service,
            eiaa_flow_service,
            email_service,
            capsule_cache,
            audit_writer,
            runtime_key_cache,
            attestation_verifier,
            risk_engine,
            decision_cache,
            user_factor_service,
        })
    }
}
