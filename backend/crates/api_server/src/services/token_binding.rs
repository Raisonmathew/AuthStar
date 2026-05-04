//! T2.3 — Token Binding (RFC 9449 DPoP + RFC 8705 mTLS).
//!
//! Token binding cryptographically ties an issued OAuth access token to a
//! key the legitimate client controls (DPoP) or a TLS client certificate
//! (mTLS). When the token is presented to a resource server, the request
//! must demonstrate possession of that same key/cert, so a stolen bearer
//! token cannot be replayed by a third party.
//!
//! Strict EIAA fit: the `cnf` claim is *binding metadata*, not authority.
//! It tells the middleware to refuse a request that fails proof-of-possession
//! before the capsule even runs. The capsule still owns authorization.
//!
//! ## Design
//!
//! Decorator/Chain pattern over the existing JWT extractor:
//!
//! ```text
//!   Request
//!     ▼
//!   verify_token_as<OAuthAccessTokenClaims>   (existing)
//!     ▼ on success
//!   TokenBindingChain.verify(claims, request)  (new — this module)
//!     ▼ on success
//!   handler
//! ```
//!
//! Each [`TokenBinding`] implementation handles exactly one binding kind.
//! The chain dispatches based on which `cnf` member is populated. Tokens
//! issued without a `cnf` claim short-circuit through the chain (no binding
//! requested → nothing to verify).

use auth_core::{Confirmation, OAuthAccessTokenClaims};
use axum::http::HeaderMap;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};
use shared_types::{AppError, Result};
use std::sync::Arc;

/// Where the binding proof comes from for a given inbound request.
///
/// Bundled together so every `TokenBinding::verify` call has a uniform
/// signature regardless of whether it needs an HTTP method+URI (DPoP) or
/// a client cert (mTLS) or neither.
#[derive(Debug, Clone, Default)]
pub struct BindingRequest<'a> {
    /// HTTP method, uppercase ("GET", "POST", …).
    pub http_method: &'a str,
    /// Absolute request URI without query/fragment, per RFC 9449 §4.2:
    /// scheme + host + path. The DPoP proof's `htu` is matched against this.
    pub http_uri: &'a str,
    /// Value of the `DPoP` request header, if present.
    pub dpop_header: Option<&'a str>,
    /// Hash of the access token (`ath`) that must appear in the DPoP proof
    /// payload. The middleware computes this once per request from the raw
    /// access-token string.
    pub access_token: Option<&'a str>,
    /// PEM-encoded client X.509 certificate forwarded by the TLS terminator
    /// (typically via `X-SSL-Client-Cert` or similar header). mTLS-only.
    pub client_cert_pem: Option<&'a str>,
}

/// Build an OAuth `cnf` claim from token-endpoint request headers. DPoP uses
/// the embedded JWK thumbprint (`jkt`); mTLS uses the SHA-256 thumbprint of the
/// forwarded client certificate (`x5t#S256`). If neither proof type is present,
/// returns `Ok(None)` so the AS can issue a normal bearer token.
pub fn confirmation_from_headers(headers: &HeaderMap) -> Result<Option<Confirmation>> {
    let mut cnf = Confirmation::default();
    if let Some(proof) = header_str(headers, "dpop") {
        cnf.jkt = Some(dpop_jkt_from_proof(proof)?);
    }
    if let Some(pem) =
        header_str(headers, "x-ssl-client-cert").or_else(|| header_str(headers, "x-client-cert"))
    {
        let pem = urlencoding::decode(pem).map_err(|_| {
            AppError::Unauthorized("client certificate header is not URL encoded".into())
        })?;
        cnf.x5t_s256 = Some(mtls_x5t_s256_from_pem(&pem)?);
    }
    if cnf.jkt.is_none() && cnf.x5t_s256.is_none() {
        Ok(None)
    } else {
        Ok(Some(cnf))
    }
}

pub fn dpop_jkt_from_proof(proof: &str) -> Result<String> {
    let first = proof
        .split('.')
        .next()
        .ok_or_else(|| AppError::Unauthorized("malformed DPoP proof".into()))?;
    let header_bytes = URL_SAFE_NO_PAD
        .decode(first)
        .map_err(|_| AppError::Unauthorized("DPoP header not base64url".into()))?;
    let header: DpopProtectedHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| AppError::Unauthorized("DPoP header is not JSON".into()))?;
    if header.typ != "dpop+jwt" {
        return Err(AppError::Unauthorized(
            "DPoP proof typ must be \"dpop+jwt\"".into(),
        ));
    }
    jwk_thumbprint_sha256(&header.jwk)
}

pub fn mtls_x5t_s256_from_pem(pem: &str) -> Result<String> {
    let der = pem_to_der(pem)?;
    Ok(sha256_b64url(&der))
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
}

/// Strategy interface — each implementation handles exactly one `cnf` kind.
#[async_trait::async_trait]
pub trait TokenBinding: Send + Sync {
    /// Discriminator name for logs/metrics ("dpop", "mtls").
    fn binding_kind(&self) -> &'static str;

    /// Returns `Ok(())` if this binding applies and is satisfied for the
    /// request. Returns `Err` to refuse the request.
    async fn verify(&self, claims: &OAuthAccessTokenClaims, req: &BindingRequest<'_>)
        -> Result<()>;
}

/// Chain pattern: dispatches to whichever binding matches the token's
/// confirmation method. A token with no `cnf` is allowed through (the AS
/// chose not to bind it).
pub struct TokenBindingChain {
    dpop: Arc<DpopBinding>,
    mtls: Arc<MtlsBinding>,
}

impl TokenBindingChain {
    pub fn new(dpop: Arc<DpopBinding>, mtls: Arc<MtlsBinding>) -> Self {
        Self { dpop, mtls }
    }

    pub async fn verify(
        &self,
        claims: &OAuthAccessTokenClaims,
        req: &BindingRequest<'_>,
    ) -> Result<()> {
        let cnf = match &claims.cnf {
            Some(c) => c,
            // Unbound token — nothing to verify. The AS made an explicit
            // policy choice not to bind, so we honour it.
            None => return Ok(()),
        };
        // Exactly one of `jkt` or `x5t#S256` should be set; the AS guarantees
        // this at issue time. Defensive: try both and require at least one
        // to match. If both are present we require both (defence-in-depth).
        let mut tried = false;
        if cnf.jkt.is_some() {
            tried = true;
            tracing::debug!(
                binding = self.dpop.binding_kind(),
                "verifying token binding"
            );
            self.dpop.verify(claims, req).await?;
        }
        if cnf.x5t_s256.is_some() {
            tried = true;
            tracing::debug!(
                binding = self.mtls.binding_kind(),
                "verifying token binding"
            );
            self.mtls.verify(claims, req).await?;
        }
        if !tried {
            return Err(AppError::Unauthorized(
                "token cnf claim is empty — refusing".into(),
            ));
        }
        Ok(())
    }
}

// ─────────────────────────── DPoP (RFC 9449) ───────────────────────────

/// Maximum age of a DPoP proof's `iat` claim. RFC 9449 §11.1 leaves this to
/// the resource server; 60 seconds matches the recommended PAR TTL and is
/// strict enough that a stolen proof has a tiny replay window even if jti
/// tracking failed.
pub const DPOP_PROOF_MAX_AGE_SECS: i64 = 60;

/// DPoP binding implementation (RFC 9449 §4-§7).
pub struct DpopBinding {
    nonce_store: crate::services::NonceStore,
}

impl DpopBinding {
    pub fn new(nonce_store: crate::services::NonceStore) -> Self {
        Self { nonce_store }
    }
}

/// Minimal protected-header view for a DPoP JWS proof. We only need the
/// fields RFC 9449 §4.2 mandates for verification.
#[derive(Debug, serde::Deserialize)]
struct DpopProtectedHeader {
    typ: String,
    alg: String,
    jwk: serde_json::Value,
}

/// Minimal payload view. Fields are per RFC 9449 §4.2.
#[derive(Debug, serde::Deserialize)]
struct DpopPayload {
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
    /// Required for protected-resource access (RFC 9449 §4.3).
    #[serde(default)]
    ath: Option<String>,
}

#[async_trait::async_trait]
impl TokenBinding for DpopBinding {
    fn binding_kind(&self) -> &'static str {
        "dpop"
    }

    async fn verify(
        &self,
        claims: &OAuthAccessTokenClaims,
        req: &BindingRequest<'_>,
    ) -> Result<()> {
        let proof = req
            .dpop_header
            .ok_or_else(|| AppError::Unauthorized("missing DPoP proof header".into()))?;
        let cnf_jkt = claims
            .cnf
            .as_ref()
            .and_then(|c| c.jkt.as_deref())
            .ok_or_else(|| AppError::Unauthorized("token has no cnf.jkt".into()))?;

        // 1) Split the JWS compact form (header.payload.signature).
        let parts: Vec<&str> = proof.split('.').collect();
        if parts.len() != 3 {
            return Err(AppError::Unauthorized("malformed DPoP proof".into()));
        }
        let header_bytes = URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| AppError::Unauthorized("DPoP header not base64url".into()))?;
        let header: DpopProtectedHeader = serde_json::from_slice(&header_bytes)
            .map_err(|_| AppError::Unauthorized("DPoP header is not JSON".into()))?;
        if header.typ != "dpop+jwt" {
            return Err(AppError::Unauthorized(
                "DPoP proof typ must be \"dpop+jwt\"".into(),
            ));
        }

        // 2) Compute the JWK thumbprint (RFC 7638) of the embedded key and
        //    compare with cnf.jkt. This MUST match before we trust the
        //    embedded key for signature verification.
        let computed_jkt = jwk_thumbprint_sha256(&header.jwk)?;
        if computed_jkt != cnf_jkt {
            return Err(AppError::Unauthorized(
                "DPoP proof key thumbprint does not match token cnf.jkt".into(),
            ));
        }

        // 3) Verify the JWS signature using the embedded JWK.
        let alg = parse_alg(&header.alg)?;
        let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(header.jwk.clone())
            .map_err(|_| AppError::Unauthorized("DPoP header jwk is not a valid JWK".into()))?;
        let key = jsonwebtoken::DecodingKey::from_jwk(&jwk).map_err(|_| {
            AppError::Unauthorized("cannot derive DecodingKey from DPoP jwk".into())
        })?;
        let mut validation = jsonwebtoken::Validation::new(alg);
        // DPoP proofs do not have iss/aud/exp by default — disable those.
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_aud = false;
        let proof_data = jsonwebtoken::decode::<DpopPayload>(proof, &key, &validation)
            .map_err(|e| AppError::Unauthorized(format!("DPoP signature invalid: {e}")))?;
        let payload = proof_data.claims;

        // 4) Validate htm / htu.
        if !payload.htm.eq_ignore_ascii_case(req.http_method) {
            return Err(AppError::Unauthorized("DPoP htm mismatch".into()));
        }
        if payload.htu != req.http_uri {
            return Err(AppError::Unauthorized("DPoP htu mismatch".into()));
        }

        // 5) iat must be recent.
        let now = chrono::Utc::now().timestamp();
        if (now - payload.iat).abs() > DPOP_PROOF_MAX_AGE_SECS {
            return Err(AppError::Unauthorized("DPoP proof iat too old".into()));
        }

        // 6) ath (access token hash) — required for protected-resource use.
        if let Some(token) = req.access_token {
            let expected_ath = sha256_b64url(token.as_bytes());
            match payload.ath.as_deref() {
                Some(ath) if ath == expected_ath => {}
                Some(_) => {
                    return Err(AppError::Unauthorized(
                        "DPoP ath does not match access token".into(),
                    ))
                }
                None => {
                    return Err(AppError::Unauthorized(
                        "DPoP proof missing ath claim".into(),
                    ))
                }
            }
        }

        // 7) Replay protection — jti must be single-use within the proof's
        //    validity window. The NonceStore stores it with a TTL slightly
        //    larger than the proof age limit so a replay between the two
        //    can't sneak through.
        let jti_key = format!("dpop:{}", payload.jti);
        let fresh = self
            .nonce_store
            .check_and_mark(&jti_key)
            .await
            .map_err(|e| AppError::Internal(format!("DPoP nonce store failure: {e}")))?;
        if !fresh {
            return Err(AppError::Unauthorized("DPoP proof jti replay".into()));
        }

        Ok(())
    }
}

fn parse_alg(alg: &str) -> Result<jsonwebtoken::Algorithm> {
    match alg {
        "ES256" => Ok(jsonwebtoken::Algorithm::ES256),
        "ES384" => Ok(jsonwebtoken::Algorithm::ES384),
        "EdDSA" => Ok(jsonwebtoken::Algorithm::EdDSA),
        "RS256" => Ok(jsonwebtoken::Algorithm::RS256),
        "PS256" => Ok(jsonwebtoken::Algorithm::PS256),
        other => Err(AppError::Unauthorized(format!(
            "unsupported DPoP alg: {other}"
        ))),
    }
}

fn sha256_b64url(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    URL_SAFE_NO_PAD.encode(digest)
}

/// RFC 7638 JWK thumbprint over the canonical lexicographic JSON. We support
/// the two key types the OAuth ecosystem actually uses for DPoP today:
/// `EC` (members `crv`, `kty`, `x`, `y`) and `OKP` (members `crv`, `kty`,
/// `x`). RSA support can be added later if a client demands it.
pub fn jwk_thumbprint_sha256(jwk: &serde_json::Value) -> Result<String> {
    let obj = jwk
        .as_object()
        .ok_or_else(|| AppError::Unauthorized("jwk is not a JSON object".into()))?;
    let kty = obj
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Unauthorized("jwk missing kty".into()))?;
    let canonical = match kty {
        "EC" => {
            let crv = obj
                .get("crv")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AppError::Unauthorized("EC jwk missing crv".into()))?;
            let x = obj
                .get("x")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AppError::Unauthorized("EC jwk missing x".into()))?;
            let y = obj
                .get("y")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AppError::Unauthorized("EC jwk missing y".into()))?;
            // Members must appear in lexicographic order with no whitespace.
            format!("{{\"crv\":\"{crv}\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}")
        }
        "OKP" => {
            let crv = obj
                .get("crv")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AppError::Unauthorized("OKP jwk missing crv".into()))?;
            let x = obj
                .get("x")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AppError::Unauthorized("OKP jwk missing x".into()))?;
            format!("{{\"crv\":\"{crv}\",\"kty\":\"OKP\",\"x\":\"{x}\"}}")
        }
        other => {
            return Err(AppError::Unauthorized(format!(
                "unsupported jwk kty for thumbprint: {other}"
            )))
        }
    };
    Ok(sha256_b64url(canonical.as_bytes()))
}

// ─────────────────────────── mTLS (RFC 8705) ───────────────────────────

/// mTLS binding (certificate-bound access tokens, RFC 8705 §3).
///
/// Verifies that the SHA-256 fingerprint of the client X.509 certificate
/// presented in the TLS handshake matches the token's `cnf.x5t#S256`.
///
/// The cert is forwarded by the TLS terminator (nginx / envoy) as a header
/// like `X-SSL-Client-Cert` containing the PEM body URL-encoded. Wiring up
/// that terminator is operations config — the binding here just trusts the
/// header that the framework chooses to populate `client_cert_pem` with.
pub struct MtlsBinding;

#[async_trait::async_trait]
impl TokenBinding for MtlsBinding {
    fn binding_kind(&self) -> &'static str {
        "mtls"
    }

    async fn verify(
        &self,
        claims: &OAuthAccessTokenClaims,
        req: &BindingRequest<'_>,
    ) -> Result<()> {
        let expected = claims
            .cnf
            .as_ref()
            .and_then(|c| c.x5t_s256.as_deref())
            .ok_or_else(|| AppError::Unauthorized("token has no cnf.x5t#S256".into()))?;
        let pem = req
            .client_cert_pem
            .ok_or_else(|| AppError::Unauthorized("no client certificate forwarded".into()))?;
        // PEM → DER: strip header/footer/whitespace, base64-decode.
        let der = pem_to_der(pem)?;
        let computed = sha256_b64url(&der);
        if computed != expected {
            return Err(AppError::Unauthorized(
                "client cert thumbprint mismatch".into(),
            ));
        }
        Ok(())
    }
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>()
        .split_whitespace()
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|_| AppError::Unauthorized("client cert PEM is not valid base64".into()))
}

// ────────────────────────────── Tests ──────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ec_p256_thumbprint_matches_rfc7638_example() {
        // RFC 7638 §3.1 worked example (RSA), adapted: build an EC P-256 jwk
        // and verify the thumbprint deterministically equals SHA-256 over the
        // canonical JSON. Uses a known fixture so the test catches accidental
        // canonicalisation regressions.
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "use": "sig",
            "kid": "ignored-by-thumbprint"
        });
        let canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}";
        let expected = sha256_b64url(canonical.as_bytes());
        let got = jwk_thumbprint_sha256(&jwk).expect("thumbprint");
        assert_eq!(got, expected);
    }

    #[test]
    fn okp_ed25519_thumbprint_omits_y() {
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        });
        let canonical =
            "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";
        let expected = sha256_b64url(canonical.as_bytes());
        assert_eq!(jwk_thumbprint_sha256(&jwk).unwrap(), expected);
    }

    #[test]
    fn unsupported_kty_rejected() {
        let jwk = serde_json::json!({
            "kty": "RSA",
            "n": "abc",
            "e": "AQAB"
        });
        assert!(jwk_thumbprint_sha256(&jwk).is_err());
    }

    #[test]
    fn ath_is_sha256_b64url_of_token() {
        // Spot check the helper used to compute the `ath` value the DPoP
        // proof must carry for protected-resource access.
        let token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";
        // base64url(no-pad) of SHA-256 of the bytes above. Computed with
        // openssl: `printf '%s' '<token>' | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '='`.
        let expected = "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo";
        assert_eq!(sha256_b64url(token.as_bytes()), expected);
    }
}
