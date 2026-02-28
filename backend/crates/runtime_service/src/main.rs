use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use grpc_api::eiaa::runtime::capsule_runtime_server::{CapsuleRuntime, CapsuleRuntimeServer};
use grpc_api::eiaa::runtime::*;
use keystore::{compute_kid, InMemoryKeystore, Keystore, KeyId};
use tonic::{transport::Server, Request, Response, Status};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use sqlx::PgPool;
use chrono::Utc;

use ed25519_dalek::{Signature, VerifyingKey};

use capsule_compiler::{CapsuleMeta as CCMeta, CapsuleSigned as CCSigned};
use capsule_runtime as rt;

/// Build the canonical JSON signing payload for a capsule meta.
///
/// This MUST match the payload construction in `capsule_compiler/src/lib.rs::compile()`.
/// Keys are in lexicographic order (matching serde_json::json! macro insertion order
/// which is alphabetical for the literal keys used there).
///
/// Fields:
///   action, ast_hash, ast_hash_b64, not_after_unix, not_before_unix, tenant_id, wasm_hash
///
/// Note: `ast_hash` is the raw hex SHA-256 of the AST bytes.
///       `ast_hash_b64` is the base64url encoding of that hex string (as stored in CapsuleMeta).
///       `wasm_hash` is the raw hex SHA-256 of the WASM bytes.
///
/// The capsule proto carries `policy_hash_b64` (= ast_hash_b64) and `wasm_hash_b64` (= wasm_hash hex).
/// We reconstruct the payload from those fields.
fn build_compiler_signing_payload(
    action: &str,
    ast_hash_b64: &str,
    not_after_unix: i64,
    not_before_unix: i64,
    tenant_id: &str,
    wasm_hash: &str,
) -> Result<Vec<u8>, Status> {
    // Decode ast_hash_b64 back to the raw hex string (ast_hash).
    // In compile(), ast_hash_b64 = URL_SAFE_NO_PAD.encode(ast_hash.as_bytes())
    // So ast_hash = String::from_utf8(URL_SAFE_NO_PAD.decode(ast_hash_b64))
    let ast_hash_bytes = URL_SAFE_NO_PAD
        .decode(ast_hash_b64.as_bytes())
        .map_err(|_| Status::invalid_argument("invalid ast_hash_b64 encoding"))?;
    let ast_hash = String::from_utf8(ast_hash_bytes)
        .map_err(|_| Status::invalid_argument("ast_hash_b64 decoded to non-UTF8"))?;

    // Build canonical JSON payload — keys in lexicographic order, matching compile().
    let payload = serde_json::json!({
        "action": action,
        "ast_hash": ast_hash,
        "ast_hash_b64": ast_hash_b64,
        "not_after_unix": not_after_unix,
        "not_before_unix": not_before_unix,
        "tenant_id": tenant_id,
        "wasm_hash": wasm_hash,
    });

    serde_json::to_vec(&payload)
        .map_err(|_| Status::internal("failed to serialize compiler signing payload"))
}

/// Persistent nonce store backed by PostgreSQL `eiaa_replay_nonces`.
///
/// MEDIUM-EIAA-8 FIX: Replace the in-memory `HashSet<String>` with a PostgreSQL-backed
/// nonce store. The in-memory store was lost on every service restart, allowing an attacker
/// to replay a captured nonce by restarting the runtime service. The PostgreSQL store
/// persists nonces with a TTL (default 5 minutes, matching the attestation validity window)
/// so replay protection survives restarts.
///
/// Implementation uses `INSERT ... ON CONFLICT DO NOTHING` + row count check:
///   - Returns `true`  if the nonce was freshly inserted (not a replay)
///   - Returns `false` if the nonce already existed (replay detected)
///
/// Expired nonces are cleaned up lazily on each insert (delete WHERE expires_at < NOW())
/// to avoid requiring a separate background job.
#[derive(Clone)]
struct PgNonceStore {
    db: PgPool,
    /// Nonce TTL in seconds (default: 300 = 5 minutes)
    ttl_seconds: i64,
}

impl PgNonceStore {
    fn new(db: PgPool) -> Self {
        Self {
            db,
            ttl_seconds: std::env::var("NONCE_TTL_SECONDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
        }
    }

    /// Check if nonce is fresh and mark it as seen.
    ///
    /// Returns `Ok(true)` if the nonce was freshly inserted (safe to proceed).
    /// Returns `Ok(false)` if the nonce already existed (replay detected).
    /// Returns `Err` on DB failure (caller should fail closed).
    async fn check_and_mark(
        &self,
        nonce_b64: &str,
        tenant_id: Option<&str>,
        action: Option<&str>,
    ) -> anyhow::Result<bool> {
        // Lazy cleanup: purge expired nonces before inserting.
        // This is a best-effort cleanup — failure is non-fatal.
        let _ = sqlx::query(
            "DELETE FROM eiaa_replay_nonces WHERE expires_at < NOW()"
        )
        .execute(&self.db)
        .await;

        let expires_at = Utc::now() + chrono::Duration::seconds(self.ttl_seconds);

        // INSERT ... ON CONFLICT DO NOTHING returns 1 row on fresh insert, 0 on conflict.
        let rows_affected = sqlx::query(
            r#"
            INSERT INTO eiaa_replay_nonces (nonce_b64, seen_at, expires_at, tenant_id, action)
            VALUES ($1, NOW(), $2, $3, $4)
            ON CONFLICT (nonce_b64) DO NOTHING
            "#,
        )
        .bind(nonce_b64)
        .bind(expires_at)
        .bind(tenant_id)
        .bind(action)
        .execute(&self.db)
        .await?
        .rows_affected();

        Ok(rows_affected == 1)
    }
}

#[derive(Clone)]
struct State {
    ks: InMemoryKeystore,
    runtime_kid: KeyId,
    runtime_pk: VerifyingKey,
    compiler_pk: Option<VerifyingKey>,
    /// Persistent nonce store (PostgreSQL-backed).
    /// If None, falls back to fail-open nonce check with a warning (dev mode only).
    nonce_store: Option<PgNonceStore>,
}

struct RuntimeSvc {
    state: State,
}

#[tonic::async_trait]
impl CapsuleRuntime for RuntimeSvc {
    async fn execute(&self, req: Request<ExecuteRequest>) -> Result<Response<ExecuteResponse>, Status> {
        let r = req.into_inner();

        if r.nonce_b64.is_empty() {
            return Err(Status::invalid_argument("missing nonce"));
        }

        // MEDIUM-EIAA-8 FIX: Persistent nonce replay protection via PostgreSQL.
        //
        // Previously used an in-memory HashSet that was cleared on every service restart,
        // allowing an attacker to replay a captured nonce by restarting the runtime.
        // Now uses eiaa_replay_nonces table with TTL-based expiry.
        if let Some(ref nonce_store) = self.state.nonce_store {
            // Extract tenant_id and action from capsule meta for scoped nonce storage.
            let (tenant_id, action) = r.capsule.as_ref()
                .and_then(|c| c.meta.as_ref())
                .map(|m| (m.tenant_id.as_str(), m.action.as_str()))
                .map(|(t, a)| (Some(t), Some(a)))
                .unwrap_or((None, None));

            match nonce_store.check_and_mark(&r.nonce_b64, tenant_id, action).await {
                Ok(true) => {
                    tracing::debug!(nonce = %r.nonce_b64, "Nonce is fresh");
                }
                Ok(false) => {
                    tracing::error!(
                        nonce = %r.nonce_b64,
                        "Replay nonce detected — aborting execution"
                    );
                    return Err(Status::already_exists("replay nonce"));
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        nonce = %r.nonce_b64,
                        "Nonce store DB write failed — failing closed to prevent replay"
                    );
                    return Err(Status::internal(format!("nonce store failure: {}", e)));
                }
            }
        } else {
            // No persistent store configured — warn and continue (dev mode only).
            // In production, RUNTIME_DATABASE_URL must be set.
            tracing::warn!(
                nonce = %r.nonce_b64,
                "No persistent nonce store configured — replay protection DISABLED. \
                 Set RUNTIME_DATABASE_URL to enable."
            );
        }

        // Verify Auth Evidence and Canonical Hash
        if let Some(ev) = &r.auth_evidence {
            use sha2::{Sha256, Digest};
            let expected_data = format!("{}:{}:{}", ev.provider, ev.subject, ev.tenant_id);
            let expected_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(expected_data.as_bytes()));
            
            if expected_hash != ev.evidence_hash_b64 {
                return Err(Status::invalid_argument("evidence hash mismatch"));
            }
            
            if !ev.email_verified {
                let resp = ExecuteResponse {
                    decision: Some(Decision { 
                        allow: false, 
                        reason: "Email not verified at IdP".into(),
                        requirement: None,
                        metadata: None,
                    }),
                    attestation: None,
                };
                return Ok(Response::new(resp));
            }
        }

        // Verify compiler signature if configured.
        //
        // CRITICAL-EIAA-1 FIX: Use canonical JSON (matching capsule_compiler/src/lib.rs::compile())
        // instead of bincode. bincode is Rust-specific, non-portable, and version-unstable.
        // The canonical JSON payload uses lexicographically ordered keys so it can be verified
        // by any language (Rust runtime, JS SDK, Go SDK).
        if let Some(pk) = &self.state.compiler_pk {
            let cap_ref = r.capsule.as_ref().ok_or(Status::invalid_argument("capsule"))?;
            let meta = cap_ref.meta.as_ref().ok_or(Status::invalid_argument("meta"))?;

            let to_sign = build_compiler_signing_payload(
                &meta.action,
                &meta.policy_hash_b64,   // = ast_hash_b64
                meta.not_after_unix,
                meta.not_before_unix,
                &meta.tenant_id,
                &cap_ref.wasm_hash_b64,  // = wasm_hash (raw hex)
            )?;

            let sig_b64 = &cap_ref.compiler_sig_b64;
            let sig_bytes = URL_SAFE_NO_PAD
                .decode(sig_b64.as_bytes())
                .map_err(|_| Status::invalid_argument("compiler sig: invalid base64"))?;
            let sig = Signature::from_bytes(
                &sig_bytes[..].try_into().map_err(|_| Status::invalid_argument("compiler sig: wrong length (expected 64 bytes)"))?,
            );
            pk.verify_strict(&to_sign, &sig)
                .map_err(|_| Status::permission_denied("compiler signature verification failed"))?;
        }

        let cap = r.capsule.ok_or(Status::invalid_argument("capsule"))?;
        let meta = cap.meta.ok_or(Status::invalid_argument("meta"))?;
        let cc_meta = CCMeta {
            tenant_id: meta.tenant_id,
            action: meta.action,
            not_before_unix: meta.not_before_unix,
            not_after_unix: meta.not_after_unix,
            ast_hash_b64: meta.policy_hash_b64,
        };
        let cc_signed = CCSigned {
            meta: cc_meta.clone(),
            ast_bytes: cap.ast_bytes,
            ast_hash: cap.ast_hash_b64.clone(),
            lowering_version: cap.lowering_version.clone(),
            wasm_bytes: cap.wasm_bytes,
            wasm_hash: cap.wasm_hash_b64.clone(),
            compiler_kid: cap.compiler_kid,
            compiler_sig_b64: cap.compiler_sig_b64,
        };

        // Parse input_json to RuntimeContext
        let mut input_ctx: rt::RuntimeContext = serde_json::from_str(&r.input_json)
            .map_err(|e| Status::invalid_argument(format!("input json parse: {}", e)))?;

        if let Some(evidence) = r.auth_evidence {
            input_ctx.auth_evidence = Some(serde_json::to_value(evidence)
                .map_err(|e| Status::invalid_argument(format!("auth_evidence json: {}", e)))?);
        }

        // MEDIUM-EIAA-5 FIX: Capture AAL-relevant fields from input_ctx BEFORE it is
        // moved into rt::execute(). The RuntimeContext now carries assurance_level and
        // verified_capabilities (HIGH-EIAA-2 fix in wasm_host.rs), so we can derive
        // the attestation body fields from the actual session context rather than
        // guessing from authz_result.
        //
        // Factor type → capability name mapping (matches lowerer.rs encoding):
        //   0 = OTP (totp)
        //   1 = Passkey
        //   2 = Biometric
        //   3 = HardwareKey
        //   4 = Password
        //
        // AAL derivation from factors_satisfied (NIST SP 800-63B):
        //   AAL3 = hardware key (3) present
        //   AAL2 = passkey (1) OR biometric (2) OR OTP (0) present
        //   AAL1 = password (4) present
        //   AAL0 = no factors
        //
        // If assurance_level is already set on the context (populated by eiaa_authz.rs
        // from the session DB), use that directly — it is more authoritative than
        // deriving from factors_satisfied.
        let (achieved_aal, verified_capabilities) = {
            let factor_to_name = |f: i32| -> &'static str {
                match f {
                    0 => "totp",
                    1 => "passkey",
                    2 => "biometric",
                    3 => "hardware_key",
                    4 => "password",
                    _ => "unknown",
                }
            };

            // Build capability list from factors_satisfied
            let mut caps: Vec<String> = input_ctx.factors_satisfied
                .iter()
                .map(|&f| factor_to_name(f).to_string())
                .collect();

            // Merge in verified_capabilities from the context (set by eiaa_authz.rs)
            for cap in &input_ctx.verified_capabilities {
                if !caps.contains(cap) {
                    caps.push(cap.clone());
                }
            }

            // Derive AAL: prefer the session-level assurance_level if set (> 0),
            // otherwise derive from factors_satisfied.
            let aal = if input_ctx.assurance_level > 0 {
                format!("aal{}", input_ctx.assurance_level)
            } else {
                let factors = &input_ctx.factors_satisfied;
                if factors.contains(&3) {
                    // Hardware key → AAL3
                    "aal3".to_string()
                } else if factors.contains(&1) || factors.contains(&2) || factors.contains(&0) {
                    // Passkey, biometric, or OTP → AAL2
                    "aal2".to_string()
                } else if factors.contains(&4) {
                    // Password only → AAL1
                    "aal1".to_string()
                } else {
                    "aal0".to_string()
                }
            };

            (aal, caps)
        };

        let runtime_kid = self.state.runtime_kid.0.clone();
        let sign_fn = |msg: &[u8]| self.state.ks.sign(&self.state.runtime_kid, msg).map_err(|_| anyhow::anyhow!("sign"));

        // Enforce Integrity
        let expected_ast = Some(cc_signed.ast_hash.as_str());
        let expected_wasm = Some(cc_signed.wasm_hash.as_str());

        let (decision_output, att) = rt::execute(
            &cc_signed,
            input_ctx,
            &runtime_kid,
            &sign_fn,
            r.now_unix,
            r.expires_at_unix,
            &r.nonce_b64,
            expected_ast,
            expected_wasm,
        ).map_err(|e| Status::internal(format!("exec: {}", e)))?;

        // Compute risk snapshot hash from the risk score in the decision output.
        // This provides a tamper-evident record of the risk score at decision time.
        let risk_snapshot_hash = {
            use sha2::{Sha256, Digest};
            let risk_data = format!("risk_score:{}", decision_output.risk_score);
            let hash = Sha256::digest(risk_data.as_bytes());
            URL_SAFE_NO_PAD.encode(hash)
        };

        let resp = ExecuteResponse {
            decision: Some(Decision {
                allow: decision_output.decision == 1,
                reason: decision_output.reason.unwrap_or_default(),
                requirement: None,
                metadata: None,
            }),
            attestation: Some(Attestation {
                body: Some(AttestationBody {
                    capsule_hash_b64: att.body.capsule_hash_b64,
                    decision_hash_b64: att.body.decision_hash_b64,
                    executed_at_unix: att.body.executed_at_unix,
                    expires_at_unix: att.body.expires_at_unix,
                    nonce_b64: att.body.nonce_b64,
                    runtime_kid: att.body.runtime_kid,
                    ast_hash_b64: cc_signed.ast_hash.clone(),
                    wasm_hash_b64: cc_signed.wasm_hash.clone(),
                    lowering_version: cc_signed.lowering_version.clone(),
                    achieved_aal,
                    verified_capabilities,
                    risk_snapshot_hash,
                }),
                signature_b64: att.signature_b64,
            }),
        };

        Ok(Response::new(resp))
    }

    async fn get_public_keys(&self, _req: Request<GetPublicKeysRequest>) -> Result<Response<GetPublicKeysResponse>, Status> {
        let pk_b64 = rt::encode_runtime_pk(&self.state.runtime_pk);
        let kid = compute_kid(&self.state.runtime_pk).0;
        Ok(Response::new(GetPublicKeysResponse {
            keys: vec![PublicKey { kid, pk_b64 }],
        }))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,runtime_service=debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let listen: SocketAddr = std::env::var("RUNTIME_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:50061".to_string()).parse().expect("listen addr");

    let ks = InMemoryKeystore::ephemeral();
    let runtime_kid = ks.generate_ed25519()?;
    let pk = ks.public_key(&runtime_kid)?.key;

    let compiler_pk = match std::env::var("RUNTIME_COMPILER_PK_B64") {
        Ok(v) if !v.is_empty() => {
            let bytes = URL_SAFE_NO_PAD.decode(v.as_bytes()).expect("compiler pk b64");
            Some(VerifyingKey::from_bytes(&bytes[..].try_into().expect("pk len")).expect("invalid pk"))
        }
        _ => None,
    };

    // MEDIUM-EIAA-8 FIX: Connect to PostgreSQL for persistent nonce storage.
    // RUNTIME_DATABASE_URL is optional — if absent, nonce replay protection is disabled
    // (acceptable in development, not in production).
    let nonce_store = match std::env::var("RUNTIME_DATABASE_URL").ok().filter(|v| !v.is_empty()) {
        Some(db_url) => {
            match PgPool::connect(&db_url).await {
                Ok(pool) => {
                    tracing::info!("Connected to PostgreSQL for persistent nonce storage");
                    Some(PgNonceStore::new(pool))
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "Failed to connect to PostgreSQL for nonce storage — replay protection DISABLED"
                    );
                    None
                }
            }
        }
        None => {
            tracing::warn!(
                "RUNTIME_DATABASE_URL not set — persistent nonce replay protection DISABLED. \
                 This is only acceptable in development environments."
            );
            None
        }
    };

    let svc = RuntimeSvc {
        state: State { ks, runtime_kid, runtime_pk: pk, compiler_pk, nonce_store },
    };

    tracing::info!("runtime listening on {}", listen);

    Server::builder()
        .add_service(CapsuleRuntimeServer::new(svc))
        .serve(listen)
        .await?;

    Ok(())
}
