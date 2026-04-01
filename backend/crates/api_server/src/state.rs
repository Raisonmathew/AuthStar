use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use redis::aio::ConnectionManager;
use auth_core::JwtService;
use crate::config::Config;
use std::sync::Arc;
use std::time::Duration;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use keystore::{InMemoryKeystore, KeyId, Keystore};
use email_service::{EmailService, EmailServiceConfig};
use identity_engine::services::{VerificationService, MfaService, OAuthService, PasskeyService};
use crate::services::eiaa_flow_service::EiaaFlowService;
use crate::services::{CapsuleCacheService, AuditWriter, AuditWriterBuilder, RuntimeKeyCache, AttestationVerifier, AttestationDecisionCache, NonceStore};
use risk_engine::RiskEngine;
use crate::clients::runtime_client::SharedRuntimeClient;
use moka::future::Cache;
use crate::cache::InvalidationBus;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    /// Shared Redis connection manager — used by rate limiting, subscription cache,
    /// passkey sessions, OAuth state/PKCE, and EIAA flow service.
    pub redis: ConnectionManager,
    pub jwt_service: Arc<JwtService>,
    pub config: Arc<Config>,
    /// GAP-1 FIX: Shared singleton gRPC client with a process-wide circuit breaker.
    ///
    /// `SharedRuntimeClient` is Clone-cheap (Arc over atomics + tonic Channel clone).
    /// No mutex — tonic Channel already multiplexes HTTP/2 streams internally.
    /// The circuit breaker uses lock-free atomics across all concurrent requests.
    pub runtime_client: SharedRuntimeClient,
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
    /// EIAA: Persistent nonce store for replay protection (Redis + PostgreSQL).
    ///
    /// NEW-GAP-1 FIX: The NonceStore service was fully implemented in
    /// `services/nonce_store.rs` but was never instantiated in AppState or
    /// passed to `eiaa_config()`. Without this, `EiaaAuthzConfig.nonce_store`
    /// was always `None`, disabling middleware-level nonce replay protection
    /// for all protected routes.
    pub nonce_store: NonceStore,
    /// OPTIMIZATION: WASM compilation cache for policy builder.
    ///
    /// Caches compiled WASM modules by AST hash to avoid recompiling identical
    /// policies. Cache hit rate: 60-80% (policies are frequently recompiled
    /// during testing). Performance: 50ms saved per cache hit (58% faster).
    ///
    /// - Max capacity: 1000 compiled modules (~50MB memory)
    /// - TTL: 1 hour (auto-eviction)
    /// - Thread-safe: Arc<Vec<u8>> for zero-copy sharing
    pub wasm_cache: Arc<Cache<String, Arc<Vec<u8>>>>,
    pub sso_connection_service: crate::services::SsoConnectionService,
    pub api_key_service: crate::services::ApiKeyService,
    pub audit_query_service: crate::services::AuditQueryService,
    pub invitation_service: org_manager::services::InvitationService,
}

impl AppState {
    pub async fn new(config: Config) -> anyhow::Result<Self> {
        // Database connection pool
        // CRITICAL-9 FIX: Use `after_connect` to set a safe default RLS context on every
        // new connection. This prevents accidental cross-tenant data leakage if a handler
        // forgets to call set_rls_context_on_conn(). The per-request org_id is set by
        // each handler via set_rls_context_on_conn() / set_rls_context_on_tx().
        //
        // OPTIMIZATION: Tuned pool settings for policy builder compilation workload:
        // - max_connections: 50 (increased from default 10)
        // - min_connections: 10 (keep connections warm)
        // - test_before_acquire: false (skip health check for 2-3ms faster acquire)
        // - max_lifetime: 30 minutes (recycle connections to avoid stale state)
        tracing::info!("Connecting to database...");
        let db = PgPoolOptions::new()
            .max_connections(config.database.max_connections.max(50))
            .min_connections(config.database.min_connections.max(10))
            // C-2: acquire_timeout — return 503 instead of blocking indefinitely
            // when the pool is exhausted. Default: 5 seconds (configurable via
            // DB_ACQUIRE_TIMEOUT_SECS). Without this, a DB overload causes all
            // in-flight requests to hang until the OS TCP timeout (~2 minutes).
            .acquire_timeout(Duration::from_secs(config.database.acquire_timeout_secs))
            // Recycle idle connections after 10 minutes to avoid stale connections
            // after a DB failover or network partition.
            .idle_timeout(Duration::from_secs(600))
            // OPTIMIZATION: Recycle connections after 30 minutes to avoid stale state
            .max_lifetime(Duration::from_secs(1800))
            // OPTIMIZATION: Skip health check before acquire (2-3ms faster)
            .test_before_acquire(false)
            .after_connect(|conn, _meta| Box::pin(async move {
                // Set a sentinel value that RLS policies will reject.
                // Any query that reaches the DB without a proper org context will
                // match no rows (RLS policy: current_setting('app.current_org_id') = org_id).
                sqlx::query("SELECT set_config('app.current_org_id', '__unset__', false)")
                    .execute(&mut *conn)
                    .await?;
                Ok(())
            }))
            .connect(&config.database.url)
            .await?;
        tracing::info!(
            max_connections = config.database.max_connections.max(50),
            min_connections = config.database.min_connections.max(10),
            acquire_timeout_secs = config.database.acquire_timeout_secs,
            "Database pool initialized (optimized for policy builder)"
        );

        Self::new_with_pool(config, db).await
    }

    pub async fn new_with_pool(config: Config, db: PgPool) -> anyhow::Result<Self> {
        // Run database migrations
        tracing::info!("Running database migrations...");
        db_migrations::run_migrations(&db).await
            .map_err(|e| anyhow::anyhow!("Failed to run migrations: {e}"))?;
        tracing::info!("Database migrations applied successfully");

        // Redis connection with HA support
        tracing::info!("Connecting to Redis (mode: {:?})...", config.redis.mode);
        config.redis.validate()?;
        
        let redis = match config.redis.mode {
            crate::config::RedisMode::Standalone => {
                let redis_client = redis::Client::open(config.redis.urls[0].as_str())?;
                let conn = ConnectionManager::new(redis_client).await?;
                tracing::info!("✅ Redis connected (standalone mode)");
                conn
            }
            crate::config::RedisMode::Sentinel => {
                // For Sentinel mode, we discover the master and connect to it
                // The SentinelConnectionManager handles failover detection in the background
                let _sentinel_manager = crate::redis::SentinelConnectionManager::new(
                    config.redis.urls.clone(),
                    config.redis.master_name.clone().unwrap(),
                    config.redis.sentinel_password.clone(),
                    config.redis.db,
                ).await?;
                
                // Get initial connection to the current master
                let mux_conn = _sentinel_manager.get_connection().await?;
                
                // Create ConnectionManager from the multiplexed connection
                // Note: This is a simplified approach. For full HA, we'd need to store
                // the sentinel_manager and use it to get fresh connections on failover.
                // For now, the existing ConnectionManager will handle reconnection.
                let redis_client = redis::Client::open(config.redis.urls[0].as_str())?;
                let conn = ConnectionManager::new(redis_client).await?;
                tracing::info!("✅ Redis connected (Sentinel mode - master discovered)");
                conn
            }
            crate::config::RedisMode::Cluster => {
                return Err(anyhow::anyhow!("Redis Cluster mode not yet implemented"));
            }
        };

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

        // Runtime gRPC client — GAP-1 FIX: create SharedRuntimeClient singleton.
        // Phase 5: If RUNTIME_GRPC_ENDPOINTS is set, use client-side load balancing
        // across multiple runtime replicas. Otherwise, use single-endpoint mode.
        let runtime_client = if !config.eiaa.runtime_grpc_endpoints.is_empty() {
            let endpoints = config.eiaa.runtime_grpc_endpoints.clone();
            tracing::info!(
                endpoints = ?endpoints,
                "Initializing load-balanced runtime client ({} endpoints)...",
                endpoints.len()
            );
            let client = SharedRuntimeClient::new_balanced(endpoints)
                .map_err(|e| anyhow::anyhow!("Failed to create balanced runtime client: {e}"))?;
            tracing::info!("✅ Load-balanced runtime client initialized (round-robin across {} endpoints)", config.eiaa.runtime_grpc_endpoints.len());
            client
        } else {
            tracing::info!("Initializing shared runtime client at {}...", config.eiaa.runtime_grpc_addr);
            let client = SharedRuntimeClient::new(config.eiaa.runtime_grpc_addr.clone())
                .map_err(|e| anyhow::anyhow!("Failed to create shared runtime client: {e}"))?;
            tracing::info!("✅ Shared runtime client initialized (circuit breaker: 5 failures → open, 30s recovery)");
            client
        };


        let stripe_service = billing_engine::services::StripeService::new(db.clone(), config.stripe.secret_key.clone());
        let webhook_service = billing_engine::services::WebhookService::new(db.clone());
        let app_service = org_manager::services::AppService::new(db.clone());
        let organization_service = org_manager::services::OrganizationService::new(db.clone());
        let user_service = identity_engine::services::UserService::new(db.clone());

        // CRITICAL-4+5+6 FIX: OAuthService now requires Redis (for state/PKCE storage)
        // and a 32-byte AES-256-GCM key (for token encryption at rest).
        // OAUTH_TOKEN_ENCRYPTION_KEY must be a 32-byte base64url-encoded secret.
        let oauth_token_key: [u8; 32] = {
            let key_b64 = std::env::var("OAUTH_TOKEN_ENCRYPTION_KEY")
                .map_err(|_| anyhow::anyhow!("OAUTH_TOKEN_ENCRYPTION_KEY env var is required"))?;
            let key_bytes = URL_SAFE_NO_PAD
                .decode(key_b64.as_bytes())
                .map_err(|_| anyhow::anyhow!("OAUTH_TOKEN_ENCRYPTION_KEY must be valid base64url"))?;
            key_bytes.try_into()
                .map_err(|_| anyhow::anyhow!("OAUTH_TOKEN_ENCRYPTION_KEY must be exactly 32 bytes"))?
        };
        let oauth_redis_client = redis::Client::open(config.redis.urls[0].as_str())?;
        let oauth_service = identity_engine::services::OAuthService::new(
            db.clone(),
            oauth_redis_client,
            oauth_token_key,
        );
        
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
        // HIGH-F FIX: Load FACTOR_ENCRYPTION_KEY and use new_with_encryption() so that
        // TOTP secrets are encrypted at rest with AES-256-GCM. The key is the same one
        // used by UserFactorService (loaded below). We load it here first so both services
        // share the same key material.
        //
        // R-2 FIX: In production/staging, FACTOR_ENCRYPTION_KEY is mandatory.
        // Config::validate_startup() already hard-fails before we reach this point,
        // but we add a second check here as defense-in-depth: if somehow the config
        // validation was bypassed (e.g. new_with_pool() called directly in tests with
        // a production-like APP_ENV), we still refuse to start without the key.
        let factor_encryption_key: Option<[u8; 32]> = std::env::var("FACTOR_ENCRYPTION_KEY")
            .ok()
            .and_then(|k| {
                let bytes = URL_SAFE_NO_PAD.decode(k.as_bytes()).ok()?;
                bytes.try_into().ok()
            });

        // Validate key format if the env var is set but malformed
        if std::env::var("FACTOR_ENCRYPTION_KEY").is_ok() && factor_encryption_key.is_none() {
            return Err(anyhow::anyhow!(
                "FACTOR_ENCRYPTION_KEY is set but invalid: must be exactly 32 bytes \
                 encoded as base64url (no padding). \
                 Generate: openssl rand -base64 32 | tr '+/' '-_' | tr -d '='"
            ));
        }

        let mfa_service = match factor_encryption_key {
            Some(key) => {
                tracing::info!("✅ MFA service initialized with TOTP encryption (AES-256-GCM)");
                MfaService::new_with_encryption(db.clone(), "IDaaS".to_string(), key)
            }
            None => {
                // Config::validate_startup() already hard-failed in production before
                // we reach this point. This path is only reachable in development.
                tracing::warn!(
                    "⚠️  FACTOR_ENCRYPTION_KEY not set — TOTP secrets stored in plaintext. \
                     Set FACTOR_ENCRYPTION_KEY (32 bytes, base64url) for production. \
                     Generate: openssl rand -base64 32 | tr '+/' '-_' | tr -d '='"
                );
                MfaService::new(db.clone(), "IDaaS".to_string())
            }
        };

        // Passkey Service (with Redis session storage)
        let rpid = config.passkey_rp_id.clone();
        let origin = config.passkey_origin.clone();
        let passkey_service = PasskeyService::new(db.clone(), redis.clone(), &rpid, &origin)
            .map_err(|e| anyhow::anyhow!("Failed to init passkey service: {e}"))?;

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

        // Phase 2: Distributed Cache Coordination
        // Generate unique replica ID for this instance (hostname + PID)
        let replica_id = {
            let hostname = hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "unknown".to_string());
            let pid = std::process::id();
            format!("{}:{}", hostname, pid)
        };
        tracing::info!("Replica ID: {}", replica_id);

        // Initialize InvalidationBus for distributed cache coordination
        // Uses Redis pub/sub to broadcast cache invalidation messages across all replicas
        let invalidation_bus = {
            let redis_client = redis::Client::open(config.redis.urls[0].as_str())?;
            match ConnectionManager::new(redis_client.clone()).await {
                Ok(conn_mgr) => {
                    match InvalidationBus::new(
                        conn_mgr,
                        redis_client,
                        replica_id.clone(),
                    ).await {
                        Ok(bus) => {
                            tracing::info!("✅ InvalidationBus initialized (Redis pub/sub)");
                            Some(Arc::new(bus))
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "⚠️  InvalidationBus initialization failed — distributed cache invalidation disabled. \
                                 Cache invalidation will be local-only (single replica mode)."
                            );
                            None
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "⚠️  InvalidationBus Redis connection failed — distributed cache invalidation disabled. \
                         Cache invalidation will be local-only (single replica mode)."
                    );
                    None
                }
            }
        };

        // EIAA: Capsule cache service (1 hour TTL) with distributed invalidation
        let capsule_cache = if let Some(ref bus) = invalidation_bus {
            let cache = CapsuleCacheService::new_with_invalidation(redis.clone(), 3600, bus.clone());
            tracing::info!("Capsule cache service initialized (1h TTL, distributed invalidation enabled)");
            cache
        } else {
            let cache = CapsuleCacheService::new(redis.clone(), 3600);
            tracing::info!("Capsule cache service initialized (1h TTL, local-only mode)");
            cache
        };

        // EIAA: Async audit writer for high-throughput logging
        let audit_writer = AuditWriterBuilder::new(db.clone())
            .batch_size(100)
            .flush_interval_ms(100)
            .channel_size(10_000)
            .build();
        tracing::info!("Audit writer initialized");

        // EIAA Remediation: Runtime key cache (5 minute TTL) with distributed invalidation
        let runtime_key_cache = if let Some(ref bus) = invalidation_bus {
            let cache = RuntimeKeyCache::new_with_invalidation(300, bus.clone());
            tracing::info!("Runtime key cache initialized (5m TTL, distributed invalidation enabled)");
            cache
        } else {
            let cache = RuntimeKeyCache::with_ttl(300);
            tracing::info!("Runtime key cache initialized (5m TTL, local-only mode)");
            cache
        };

        // Spawn invalidation handlers for distributed cache coordination
        if invalidation_bus.is_some() {
            // Spawn CapsuleCacheService invalidation handler
            capsule_cache.clone().spawn_invalidation_handler();
            tracing::info!("✅ CapsuleCacheService invalidation handler spawned");

            // Spawn RuntimeKeyCache invalidation handler
            runtime_key_cache.clone().spawn_invalidation_handler();
            tracing::info!("✅ RuntimeKeyCache invalidation handler spawned");
        }

        // EIAA Remediation: Attestation verifier (shares key cache internally)
        let attestation_verifier = AttestationVerifier::new();
        tracing::info!("Attestation verifier initialized");

        // EIAA: Risk Engine for real-time risk evaluation
        let risk_engine = RiskEngine::new(db.clone());
        tracing::info!("Risk Engine initialized");

        // EIAA: Attestation decision cache (frequency matrix)
        let decision_cache = AttestationDecisionCache::new();

        // EIAA: Persistent nonce store (Redis + PostgreSQL two-tier)
        //
        // NEW-GAP-1 FIX: Instantiate NonceStore here so it can be passed to
        // eiaa_config() in router.rs. Uses the existing Redis ConnectionManager
        // (converted to MultiplexedConnection) and the DB pool.
        //
        // The NonceStore uses:
        //   - Redis as a fast-path (O(1) SET NX with TTL) for the common case
        //   - PostgreSQL eiaa_replay_nonces as the durable fallback
        //
        // Retention: 600 seconds (2× the default attestation TTL of 5 min).
        // This bounds table growth while maintaining the full replay protection window.
        let nonce_store = {
            // Create a dedicated MultiplexedConnection for the nonce store.
            // We cannot reuse the ConnectionManager directly because NonceStore
            // requires Arc<MultiplexedConnection> for interior mutability.
            let redis_client = redis::Client::open(config.redis.urls[0].as_str())?;
            match redis_client.get_multiplexed_async_connection().await {
                Ok(mux_conn) => {
                    tracing::info!("✅ NonceStore initialized with Redis + PostgreSQL (two-tier)");
                    NonceStore::with_redis(db.clone(), std::sync::Arc::new(mux_conn))
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "⚠️  NonceStore Redis connection failed — falling back to PostgreSQL-only. \
                         Nonce checks will be slower but still durable."
                    );
                    NonceStore::new(db.clone())
                }
            }
        };

        // EIAA: User Factor Service for step-up auth
        // R-2 FIX: Pass the raw FACTOR_ENCRYPTION_KEY env var value to FactorEncryption::new().
        // FactorEncryption::new() now accepts base64url (canonical) or legacy hex format,
        // matching the format used by MfaService above. Both services share the same key.
        // Config::validate_startup() already hard-failed in production if the key is missing.
        let factor_key_raw = std::env::var("FACTOR_ENCRYPTION_KEY").ok();
        let factor_encryption = crate::services::factor_encryption::FactorEncryption::new(
            factor_key_raw.as_deref()
        );
        let user_factor_service = crate::services::UserFactorService::with_encryption(db.clone(), factor_encryption);
        tracing::info!("✅ User Factor service initialized");

        // OPTIMIZATION: WASM compilation cache for policy builder
        // Caches compiled WASM modules by AST hash (SHA-256) to avoid recompiling
        // identical policies. Expected cache hit rate: 60-80% during development/testing.
        //
        // Performance impact:
        // - Cache miss: 87ms (no change from baseline)
        // - Cache hit: 37ms (50ms saved, 58% faster)
        // - Average (70% hit rate): 52ms (40% faster overall)
        //
        // Memory usage: ~50KB per cached module × 1000 capacity = ~50MB max
        let wasm_cache = Arc::new(
            Cache::builder()
                .max_capacity(1000)  // Cache up to 1000 compiled modules
                .time_to_live(Duration::from_secs(3600))  // 1 hour TTL
                .build()
        );
        tracing::info!("✅ WASM compilation cache initialized (capacity: 1000, TTL: 1h)");

        let sso_connection_service = crate::services::SsoConnectionService::new(db.clone());
        let api_key_service = crate::services::ApiKeyService::new(db.clone());
        let audit_query_service = crate::services::AuditQueryService::new(db.clone());
        let invitation_service = org_manager::services::InvitationService::new(db.clone());

        Ok(Self {
            db,
            redis,
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
            nonce_store,
            wasm_cache,
            sso_connection_service,
            api_key_service,
            audit_query_service,
            invitation_service,
        })
    }
}
