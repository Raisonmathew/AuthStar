use std::{collections::HashSet, net::SocketAddr, sync::Arc};

use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use grpc_api::eiaa::runtime::capsule_runtime_server::{CapsuleRuntime, CapsuleRuntimeServer};
use grpc_api::eiaa::runtime::*;
use keystore::{compute_kid, InMemoryKeystore, Keystore, KeyId};
use tokio::sync::RwLock;
use tonic::{transport::Server, Request, Response, Status};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use ed25519_dalek::{Signature, VerifyingKey};

use capsule_compiler::{CapsuleMeta as CCMeta, CapsuleSigned as CCSigned};
use capsule_runtime as rt;

#[derive(Clone)]
struct State {
    ks: InMemoryKeystore,
    runtime_kid: KeyId,
    runtime_pk: VerifyingKey,
    compiler_pk: Option<VerifyingKey>,
    nonces: Arc<RwLock<HashSet<String>>>,
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

        // Replay protection (process lifetime)
        {
            let mut s = self.state.nonces.write().await;
            if s.contains(&r.nonce_b64) {
                return Err(Status::already_exists("replay nonce"));
            }
            s.insert(r.nonce_b64.clone());
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

        // Verify compiler signature if configured
        if let Some(pk) = &self.state.compiler_pk {
            let meta = &r.capsule.as_ref().ok_or(Status::invalid_argument("capsule"))?.meta.as_ref().ok_or(Status::invalid_argument("meta"))?;
            let cc_meta = CCMeta {
                tenant_id: meta.tenant_id.clone(),
                action: meta.action.clone(),
                not_before_unix: meta.not_before_unix,
                not_after_unix: meta.not_after_unix,
                ast_hash_b64: meta.policy_hash_b64.clone(),
            };
            let to_sign = bincode::serialize(&cc_meta).map_err(|_| Status::internal("serialize"))?;
            let sig_b64 = &r.capsule.as_ref().unwrap().compiler_sig_b64;
            let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64.as_bytes()).map_err(|_| Status::invalid_argument("sig b64"))?;
            let sig = Signature::from_bytes(&sig_bytes[..].try_into().map_err(|_| Status::invalid_argument("sig len"))?);
            pk.verify_strict(&to_sign, &sig).map_err(|_| Status::permission_denied("compiler sig"))?;
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

        // Construct Proto Response
        let resp = ExecuteResponse {
            decision: Some(Decision { 
                allow: decision_output.decision == 1, 
                reason: decision_output.reason.unwrap_or_default(),
                // EIAA: Add requirement and metadata (will be populated by capsule in future)
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
                    // EIAA: Additional audit fields
                    achieved_aal: String::new(),
                    verified_capabilities: vec![],
                    risk_snapshot_hash: String::new(),
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

    let svc = RuntimeSvc {
        state: State { ks, runtime_kid, runtime_pk: pk, compiler_pk, nonces: Arc::new(RwLock::new(HashSet::new())) },
    };

    tracing::info!("runtime listening on {}", listen);

    Server::builder()
        .add_service(CapsuleRuntimeServer::new(svc))
        .serve(listen)
        .await?;

    Ok(())
}
