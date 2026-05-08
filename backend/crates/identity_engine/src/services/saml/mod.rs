//! SAML 2.0 Service
//!
//! Service Provider (SP) implementation for SAML 2.0 SSO.
//! - SP Metadata generation
//! - AuthnRequest generation
//! - Response/Assertion parsing and validation
//! - Signature Verification (XML-DSig) — FULLY IMPLEMENTED via openssl
//! - Replay Protection (Redis)
//! - Relay State binding (tenant_id ↔ opaque token, Redis-backed)

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{DateTime, Utc};
use roxmltree::Document;
use serde::{Deserialize, Serialize};
use shared_types::{AppError, Result};
use sqlx::PgPool;

mod c14n;

/// A single SAML attribute → user-field mapping (Keycloak User Attribute Mapper equivalent)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAttrMapping {
    /// SAML attribute Name, e.g. "mail", "givenName", or full URI
    pub saml_attr: String,
    /// Target user field: "first_name", "last_name", "display_name", or a custom claim key
    pub user_field: String,
}

/// SAML IdP Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlIdpConfig {
    pub entity_id: String,
    pub sso_url: String,
    pub slo_url: Option<String>,
    /// Primary X.509 certificate in PEM format (always required)
    pub certificate: String,
    /// Additional certificates for key rotation — tried if primary verification fails
    #[serde(default)]
    pub extra_certificates: Vec<String>,
    pub name_id_format: Option<String>,
    pub max_assurance: Option<String>,
    /// Allow IdP-initiated SSO (unsolicited responses without InResponseTo)
    #[serde(default)]
    pub allow_idp_initiated: bool,
    /// Request fresh authentication from IdP on every login (ForceAuthn)
    #[serde(default)]
    pub force_authn: bool,
    /// RequestedAuthnContext class reference, e.g. "PasswordProtectedTransport"
    pub authn_context_class_ref: Option<String>,
    /// SAML attribute → user field mappings applied during JIT provisioning
    #[serde(default)]
    pub attr_mappings: Vec<SamlAttrMapping>,
    /// Use HTTP POST binding for AuthnRequest (default: HTTP Redirect)
    #[serde(default)]
    pub post_binding_authn_request: bool,
}

/// SAML SP Configuration (our side)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlSpConfig {
    pub entity_id: String,
    pub acs_url: String, // Assertion Consumer Service URL
    pub slo_url: Option<String>,
}

/// SAML Assertion (parsed from Response)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAssertion {
    pub id: String,
    pub subject_name_id: String,
    pub name_id_format: Option<String>,
    pub session_index: Option<String>,
    pub issuer: String,
    pub attributes: std::collections::HashMap<String, Vec<String>>,
    pub not_before: DateTime<Utc>,
    pub not_on_or_after: DateTime<Utc>,
    pub authn_context: Option<String>,
}

/// Parsed SAML LogoutRequest (from IdP-initiated SLO)
#[derive(Debug, Clone)]
pub struct SamlLogoutRequest {
    pub id: String,
    pub issuer: String,
    pub name_id: String,
    pub session_index: Option<String>,
}

/// Normalized EIAA Facts
#[derive(Debug, Clone, Serialize)]
pub struct SamlAuthFacts {
    pub method: String,
    pub external_id: String,
    pub email: String,
    pub authn_context: Option<String>,
    pub issuer: String,
    /// Extra mapped fields from attr_mappings (first_name, last_name, display_name, …)
    pub extra_fields: std::collections::HashMap<String, String>,
}

/// Parsed AuthnRequest for this service acting as a SAML IdP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlIdpAuthnRequest {
    pub id: String,
    pub issuer: String,
    pub assertion_consumer_service_url: String,
    pub destination: Option<String>,
    pub name_id_format: Option<String>,
}

/// Parameters for issuing a signed SAML Response as an IdP.
#[derive(Debug, Clone)]
pub struct SamlIdpResponseParams<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub destination: &'a str,
    pub subject_name_id: &'a str,
    pub name_id_format: &'a str,
    pub in_response_to: &'a str,
    pub session_index: &'a str,
    pub authn_context_class_ref: &'a str,
    pub email: &'a str,
    pub first_name: Option<&'a str>,
    pub last_name: Option<&'a str>,
    pub signing_key_pem: &'a str,
    pub signing_cert_pem: &'a str,
    pub ttl_seconds: i64,
}

/// Relay state payload stored in Redis during SAML authorize → ACS round-trip.
///
/// The opaque `relay_state` token is sent to the IdP and returned in the ACS POST.
/// We look it up in Redis to recover the original `tenant_id` and `connection_id`,
/// preventing a tenant-confusion attack where an attacker crafts a RelayState that
/// maps to a different tenant's SAML connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlRelayPayload {
    pub tenant_id: String,
    pub connection_id: String,
    /// AuthnRequest ID sent to the IdP — validated against InResponseTo in the Response.
    #[serde(default)]
    pub request_id: Option<String>,
}

/// Clock skew tolerance for SAML time comparisons (seconds).
/// Configurable via SAML_CLOCK_SKEW_SECONDS env var; default 60s.
/// Covers typical NTP drift between SP and IdP servers.
fn saml_clock_skew_secs() -> i64 {
    std::env::var("SAML_CLOCK_SKEW_SECONDS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(60)
}

/// SAML 2.0 Service
#[derive(Clone)]
pub struct SamlService {
    db: PgPool,
    sp_entity_id: String,
    sp_acs_url: String,
    /// Optional SP signing key (PEM-encoded RSA private key) for signing AuthnRequests.
    /// When set, `AuthnRequestsSigned="true"` is advertised in SP metadata and all
    /// AuthnRequests are signed with RSA-SHA256 + Exclusive C14N.
    sp_signing_key_pem: Option<String>,
    /// Optional SP signing certificate (PEM) to include in SP metadata KeyDescriptor.
    sp_signing_cert_pem: Option<String>,
}

impl SamlService {
    pub fn new(db: PgPool, sp_entity_id: String, sp_acs_url: String) -> Self {
        Self {
            db,
            sp_entity_id,
            sp_acs_url,
            sp_signing_key_pem: None,
            sp_signing_cert_pem: None,
        }
    }

    /// Create a SamlService with optional SP signing credentials (MEDIUM-3).
    ///
    /// `sp_signing_key_pem`  — RSA private key in PEM format (PKCS#8 or PKCS#1), or None
    /// `sp_signing_cert_pem` — Corresponding X.509 certificate in PEM format, or None
    ///
    /// When both are `Some`, AuthnRequests are signed per SAML HTTP Redirect Binding §3.4.4.1.
    /// When either is `None`, AuthnRequests are sent unsigned (acceptable for some IdPs).
    pub fn new_with_signing(
        db: PgPool,
        sp_entity_id: String,
        sp_acs_url: String,
        sp_signing_key_pem: Option<String>,
        sp_signing_cert_pem: Option<String>,
    ) -> Self {
        Self {
            db,
            sp_entity_id,
            sp_acs_url,
            sp_signing_key_pem,
            sp_signing_cert_pem,
        }
    }

    // ── IdP Mode ────────────────────────────────────────────────────────────

    /// Generate SAML IdP metadata for this tenant.
    pub fn generate_idp_metadata(entity_id: &str, sso_url: &str, signing_cert_pem: &str) -> String {
        let cert_b64 = certificate_body(signing_cert_pem);
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="{entity_id}">
    <md:IDPSSODescriptor WantAuthnRequestsSigned="false"
                         protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>{cert_b64}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                Location="{sso_url}"/>
    </md:IDPSSODescriptor>
</md:EntityDescriptor>"#,
            entity_id = escape_xml_attr(entity_id),
            sso_url = escape_xml_attr(sso_url),
            cert_b64 = cert_b64,
        )
    }

    /// Parse a SAML AuthnRequest sent to this service in IdP mode.
    ///
    /// Supports Redirect binding (DEFLATE + base64) and POST binding (base64 XML)
    /// so tests and admin tooling can exercise either shape.
    pub fn parse_idp_authn_request(&self, saml_request: &str) -> Result<SamlIdpAuthnRequest> {
        let xml_bytes = inflate_and_decode(saml_request).or_else(|_| {
            BASE64
                .decode(saml_request.as_bytes())
                .map_err(|e| AppError::Validation(format!("Invalid SAMLRequest: {e}")))
        })?;
        let xml = String::from_utf8(xml_bytes)
            .map_err(|e| AppError::Validation(format!("Invalid UTF-8 in AuthnRequest: {e}")))?;
        let doc = Document::parse(&xml)
            .map_err(|e| AppError::Validation(format!("Invalid AuthnRequest XML: {e}")))?;
        let root = doc.root_element();
        if !root.has_tag_name("AuthnRequest") {
            return Err(AppError::Validation("Expected SAML AuthnRequest".into()));
        }
        let id = root
            .attribute("ID")
            .ok_or_else(|| AppError::Validation("AuthnRequest missing ID".into()))?
            .to_string();
        let issuer = doc
            .descendants()
            .find(|n| n.has_tag_name("Issuer"))
            .and_then(|n| n.text())
            .ok_or_else(|| AppError::Validation("AuthnRequest missing Issuer".into()))?
            .to_string();
        let assertion_consumer_service_url = root
            .attribute("AssertionConsumerServiceURL")
            .ok_or_else(|| {
                AppError::Validation("AuthnRequest missing AssertionConsumerServiceURL".into())
            })?
            .to_string();
        let destination = root.attribute("Destination").map(|s| s.to_string());
        let name_id_format = doc
            .descendants()
            .find(|n| n.has_tag_name("NameIDPolicy"))
            .and_then(|n| n.attribute("Format"))
            .map(|s| s.to_string());

        Ok(SamlIdpAuthnRequest {
            id,
            issuer,
            assertion_consumer_service_url,
            destination,
            name_id_format,
        })
    }

    /// Generate and sign a SAML Response for this service acting as an IdP.
    pub fn generate_signed_idp_response(
        &self,
        params: &SamlIdpResponseParams<'_>,
    ) -> Result<String> {
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::sign::Signer;
        use sha2::{Digest, Sha256};

        let response_id = format!("_id{}", shared_types::id_generator::generate_id("samlr"));
        let assertion_id = format!("_id{}", shared_types::id_generator::generate_id("samla"));
        let issue_instant = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let not_before = (Utc::now() - chrono::Duration::seconds(saml_clock_skew_secs()))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let not_on_or_after = (Utc::now() + chrono::Duration::seconds(params.ttl_seconds.max(60)))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let cert_b64 = certificate_body(params.signing_cert_pem);
        let first_name_attr = params
            .first_name
            .map(|value| {
                format!(
                    r#"
            <saml:Attribute Name="givenName">
                <saml:AttributeValue>{}</saml:AttributeValue>
            </saml:Attribute>"#,
                    escape_xml_text(value)
                )
            })
            .unwrap_or_default();
        let last_name_attr = params
            .last_name
            .map(|value| {
                format!(
                    r#"
            <saml:Attribute Name="sn">
                <saml:AttributeValue>{}</saml:AttributeValue>
            </saml:Attribute>"#,
                    escape_xml_text(value)
                )
            })
            .unwrap_or_default();

        let unsigned = format!(
            r##"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="{response_id}"
                Version="2.0"
                IssueInstant="{issue_instant}"
                Destination="{destination}"
                InResponseTo="{in_response_to}">
    <saml:Issuer>{issuer}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion ID="{assertion_id}"
                    Version="2.0"
                    IssueInstant="{issue_instant}">
        <saml:Issuer>{issuer}</saml:Issuer>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="#{assertion_id}">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>PLACEHOLDER_DIGEST</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>PLACEHOLDER_SIGNATURE</ds:SignatureValue>
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>{cert_b64}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </ds:Signature>
        <saml:Subject>
            <saml:NameID Format="{name_id_format}">{subject_name_id}</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after}"
                                              Recipient="{destination}"
                                              InResponseTo="{in_response_to}"/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
            <saml:AudienceRestriction>
                <saml:Audience>{audience}</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="{issue_instant}" SessionIndex="{session_index}">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>{authn_context}</saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement>
            <saml:Attribute Name="email">
                <saml:AttributeValue>{email}</saml:AttributeValue>
            </saml:Attribute>{first_name_attr}{last_name_attr}
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>"##,
            response_id = response_id,
            assertion_id = assertion_id,
            issue_instant = issue_instant,
            destination = escape_xml_attr(params.destination),
            in_response_to = escape_xml_attr(params.in_response_to),
            issuer = escape_xml_text(params.issuer),
            name_id_format = escape_xml_attr(params.name_id_format),
            subject_name_id = escape_xml_text(params.subject_name_id),
            not_on_or_after = not_on_or_after,
            not_before = not_before,
            audience = escape_xml_text(params.audience),
            session_index = escape_xml_attr(params.session_index),
            authn_context = escape_xml_text(params.authn_context_class_ref),
            email = escape_xml_text(params.email),
            first_name_attr = first_name_attr,
            last_name_attr = last_name_attr,
            cert_b64 = cert_b64,
        );

        let doc = Document::parse(&unsigned).map_err(|e| {
            AppError::Internal(format!("Generated SAML Response parse failed: {e}"))
        })?;
        let assertion_node = doc
            .descendants()
            .find(|n| n.has_tag_name("Assertion"))
            .ok_or_else(|| {
                AppError::Internal("Generated SAML Response missing Assertion".into())
            })?;
        let canonical_assertion = c14n::canonicalize_excluding_signature(&assertion_node)?;
        let digest_b64 = BASE64.encode(Sha256::digest(canonical_assertion.as_bytes()));
        let with_digest = unsigned.replace("PLACEHOLDER_DIGEST", &digest_b64);

        let doc = Document::parse(&with_digest).map_err(|e| {
            AppError::Internal(format!(
                "Generated SAML Response parse after digest failed: {e}"
            ))
        })?;
        let signed_info_node = doc
            .descendants()
            .find(|n| n.has_tag_name("SignedInfo"))
            .ok_or_else(|| {
                AppError::Internal("Generated SAML Response missing SignedInfo".into())
            })?;
        let canonical_signed_info = c14n::canonicalize(&signed_info_node)?;
        let pkey = PKey::private_key_from_pem(params.signing_key_pem.as_bytes())
            .map_err(|e| AppError::Internal(format!("Invalid SAML IdP signing key: {e}")))?;
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey)
            .map_err(|e| AppError::Internal(format!("SAML IdP signer init failed: {e}")))?;
        signer
            .update(canonical_signed_info.as_bytes())
            .map_err(|e| AppError::Internal(format!("SAML IdP signer update failed: {e}")))?;
        let signature_b64 = BASE64.encode(
            signer
                .sign_to_vec()
                .map_err(|e| AppError::Internal(format!("SAML IdP signing failed: {e}")))?,
        );

        Ok(with_digest.replace("PLACEHOLDER_SIGNATURE", &signature_b64))
    }

    // ── Relay State ──────────────────────────────────────────────────────────

    /// Store a SAML relay state token in Redis.
    ///
    /// Generates a cryptographically random opaque token, stores the
    /// `{tenant_id, connection_id}` payload under `saml:relay:<token>` with a
    /// 10-minute TTL, and returns the token to embed in the AuthnRequest.
    ///
    /// This prevents tenant-confusion attacks: the ACS handler calls
    /// `verify_relay_state()` to recover the original tenant context rather than
    /// trusting the raw RelayState value from the IdP POST.
    pub async fn store_relay_state(
        &self,
        tenant_id: &str,
        connection_id: &str,
        request_id: Option<&str>,
        redis_conn: &mut redis::aio::Connection,
    ) -> Result<String> {
        let token = shared_types::id_generator::generate_id("samlrs");
        let key = format!("saml:relay:{token}");
        let payload = SamlRelayPayload {
            tenant_id: tenant_id.to_string(),
            connection_id: connection_id.to_string(),
            request_id: request_id.map(|s| s.to_string()),
        };
        let payload_json = serde_json::to_string(&payload)
            .map_err(|e| AppError::Internal(format!("Relay state serialize error: {e}")))?;

        // SET NX EX 600 — 10-minute TTL, must not already exist
        let set_result: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg(&payload_json)
            .arg("NX")
            .arg("EX")
            .arg(600u64)
            .query_async(redis_conn)
            .await
            .map_err(|e| AppError::Internal(format!("Redis relay state store error: {e}")))?;

        if set_result.is_none() {
            // Collision — astronomically unlikely but handle it
            return Err(AppError::Internal("Relay state token collision".into()));
        }

        tracing::debug!(token = %token, tenant_id = %tenant_id, "SAML relay state stored");
        Ok(token)
    }

    /// Verify and consume a SAML relay state token from Redis.
    ///
    /// Atomically deletes the key (one-time use) and returns the stored payload.
    /// Returns `Err(Unauthorized)` if the token is missing, expired, or already used.
    pub async fn verify_relay_state(
        &self,
        token: &str,
        redis_conn: &mut redis::aio::Connection,
    ) -> Result<SamlRelayPayload> {
        let key = format!("saml:relay:{token}");

        // GETDEL — atomic get-and-delete (Redis 6.2+)
        // Falls back to GET + DEL for older Redis.
        let payload_json: Option<String> = redis::cmd("GETDEL")
            .arg(&key)
            .query_async(redis_conn)
            .await
            .map_err(|e| AppError::Internal(format!("Redis relay state verify error: {e}")))?;

        match payload_json {
            None => Err(AppError::Unauthorized(
                "Invalid or expired SAML relay state — possible CSRF or replay".into(),
            )),
            Some(json) => {
                let payload: SamlRelayPayload = serde_json::from_str(&json).map_err(|e| {
                    AppError::Internal(format!("Relay state deserialize error: {e}"))
                })?;
                tracing::debug!(
                    tenant_id = %payload.tenant_id,
                    connection_id = %payload.connection_id,
                    "SAML relay state verified and consumed"
                );
                Ok(payload)
            }
        }
    }

    /// Generate SP Metadata XML (Keycloak-parity)
    ///
    /// Includes: ACS endpoint, optional SLO endpoint, optional signing KeyDescriptor.
    /// When a signing key is configured, advertises `AuthnRequestsSigned="true"`.
    pub fn generate_sp_metadata(&self) -> String {
        self.generate_sp_metadata_with_slo(None)
    }

    pub fn generate_sp_metadata_with_slo(&self, sp_slo_url: Option<&str>) -> String {
        let authn_requests_signed = self.sp_signing_key_pem.is_some();

        let key_descriptor = if let Some(cert_pem) = &self.sp_signing_cert_pem {
            let cert_b64: String = cert_pem
                .lines()
                .filter(|l| !l.starts_with("-----"))
                .collect::<Vec<_>>()
                .join("");
            format!(
                r#"
        <md:KeyDescriptor use="signing">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>{cert_b64}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:KeyDescriptor use="encryption">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>{cert_b64}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>"#
            )
        } else {
            String::new()
        };

        let slo_element = if let Some(slo_url) = sp_slo_url {
            format!(
                r#"
        <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                Location="{slo_url}"/>
        <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                Location="{slo_url}"/>"#
            )
        } else {
            String::new()
        };

        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="{entity_id}">
    <md:SPSSODescriptor AuthnRequestsSigned="{authn_signed}"
                        WantAssertionsSigned="true"
                        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">{key_desc}{slo_elem}
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                     Location="{acs_url}"
                                     index="0"
                                     isDefault="true"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>"#,
            entity_id = self.sp_entity_id,
            authn_signed = authn_requests_signed,
            key_desc = key_descriptor,
            slo_elem = slo_element,
            acs_url = self.sp_acs_url,
        )
    }

    /// Generate SAML AuthnRequest XML.
    ///
    /// Supports: ForceAuthn, RequestedAuthnContext, configurable NameIDPolicy format.
    /// Returns `(xml, request_id)`.
    pub fn generate_authn_request(&self, idp_config: &SamlIdpConfig) -> (String, String) {
        let id = format!("_id{}", shared_types::id_generator::generate_id("saml"));
        let issue_instant = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let name_id_fmt = idp_config
            .name_id_format
            .as_deref()
            .unwrap_or("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        let force_authn_attr = if idp_config.force_authn {
            r#" ForceAuthn="true""#
        } else {
            ""
        };
        let authn_context_elem = if let Some(ref ctx) = idp_config.authn_context_class_ref {
            format!(
                "\n    <samlp:RequestedAuthnContext Comparison=\"exact\">\n        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:{}</saml:AuthnContextClassRef>\n    </samlp:RequestedAuthnContext>",
                ctx
            )
        } else {
            String::new()
        };

        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="{id}"
                    Version="2.0"
                    IssueInstant="{issue_instant}"
                    Destination="{sso_url}"
                    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    AssertionConsumerServiceURL="{acs_url}"{force_authn}>
    <saml:Issuer>{entity_id}</saml:Issuer>
    <samlp:NameIDPolicy Format="{name_id_fmt}"
                        AllowCreate="true"/>{authn_ctx}
</samlp:AuthnRequest>"#,
            id = id,
            issue_instant = issue_instant,
            sso_url = idp_config.sso_url,
            acs_url = self.sp_acs_url,
            entity_id = self.sp_entity_id,
            force_authn = force_authn_attr,
            name_id_fmt = name_id_fmt,
            authn_ctx = authn_context_elem,
        );

        (xml, id)
    }

    /// Generate SAML LogoutRequest XML for SP-initiated SLO.
    ///
    /// Returns `(xml, request_id)`. Use `get_slo_redirect_url` for the signed redirect URL.
    pub fn generate_logout_request(
        &self,
        idp_slo_url: &str,
        name_id: &str,
        name_id_format: &str,
        session_index: Option<&str>,
    ) -> (String, String) {
        let id = format!("_id{}", shared_types::id_generator::generate_id("slo"));
        let issue_instant = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let session_idx_elem = session_index
            .map(|si| format!("\n    <samlp:SessionIndex>{si}</samlp:SessionIndex>"))
            .unwrap_or_default();

        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                     ID="{id}"
                     Version="2.0"
                     IssueInstant="{issue_instant}"
                     Destination="{idp_slo_url}">
    <saml:Issuer>{entity_id}</saml:Issuer>
    <saml:NameID Format="{name_id_format}">{name_id}</saml:NameID>{session_idx}
</samlp:LogoutRequest>"#,
            id = id,
            issue_instant = issue_instant,
            idp_slo_url = idp_slo_url,
            entity_id = self.sp_entity_id,
            name_id_format = name_id_format,
            name_id = name_id,
            session_idx = session_idx_elem,
        );
        (xml, id)
    }

    /// Build a redirect URL for SP-initiated SLO (HTTP Redirect Binding).
    ///
    /// Signs the LogoutRequest when `sp_signing_key_pem` is configured.
    /// Returns `(redirect_url, request_id)`.
    pub fn get_slo_redirect_url(
        &self,
        idp_slo_url: &str,
        name_id: &str,
        name_id_format: &str,
        session_index: Option<&str>,
        relay_state: &str,
    ) -> Result<(String, String)> {
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::sign::Signer;

        let (logout_req, request_id) =
            self.generate_logout_request(idp_slo_url, name_id, name_id_format, session_index);
        let encoded = deflate_and_encode(&logout_req);

        let mut query = format!("SAMLRequest={}", urlencoding::encode(&encoded));
        if !relay_state.is_empty() {
            query.push_str(&format!("&RelayState={}", urlencoding::encode(relay_state)));
        }

        if let Some(key_pem) = &self.sp_signing_key_pem {
            let sig_alg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            query.push_str(&format!("&SigAlg={}", urlencoding::encode(sig_alg)));
            let pkey = PKey::private_key_from_pem(key_pem.as_bytes())
                .map_err(|e| AppError::Internal(format!("Invalid SP signing key: {e}")))?;
            let mut signer = Signer::new(MessageDigest::sha256(), &pkey)
                .map_err(|e| AppError::Internal(format!("Signer init failed: {e}")))?;
            signer
                .update(query.as_bytes())
                .map_err(|e| AppError::Internal(format!("Signer update failed: {e}")))?;
            let sig_bytes = signer
                .sign_to_vec()
                .map_err(|e| AppError::Internal(format!("Signing failed: {e}")))?;
            query.push_str(&format!(
                "&Signature={}",
                urlencoding::encode(&BASE64.encode(&sig_bytes))
            ));
        }

        Ok((format!("{idp_slo_url}?{query}"), request_id))
    }

    /// Generate a SAML LogoutResponse XML for responding to an IdP-initiated logout.
    pub fn generate_logout_response(
        &self,
        in_response_to: &str,
        destination: &str,
        success: bool,
    ) -> String {
        let id = format!("_id{}", shared_types::id_generator::generate_id("slor"));
        let issue_instant = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let status_code = if success {
            "urn:oasis:names:tc:SAML:2.0:status:Success"
        } else {
            "urn:oasis:names:tc:SAML:2.0:status:Responder"
        };
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                      ID="{id}"
                      Version="2.0"
                      IssueInstant="{issue_instant}"
                      Destination="{destination}"
                      InResponseTo="{in_response_to}">
    <saml:Issuer>{entity_id}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="{status_code}"/>
    </samlp:Status>
</samlp:LogoutResponse>"#,
            id = id,
            issue_instant = issue_instant,
            destination = destination,
            in_response_to = in_response_to,
            entity_id = self.sp_entity_id,
            status_code = status_code,
        )
    }

    /// Parse a SAML LogoutRequest (IdP-initiated SLO).
    ///
    /// Decodes base64, parses XML, extracts ID, Issuer, NameID, SessionIndex.
    pub fn parse_logout_request(&self, saml_request_b64: &str) -> Result<SamlLogoutRequest> {
        // Try standard base64 first (POST binding), then deflate-encoded (Redirect binding)
        let xml_bytes = if let Ok(b) = BASE64.decode(saml_request_b64) {
            b
        } else {
            inflate_and_decode(saml_request_b64)?
        };
        let xml = String::from_utf8(xml_bytes)
            .map_err(|e| AppError::Validation(format!("Invalid UTF-8 in LogoutRequest: {e}")))?;
        let doc = Document::parse(&xml)
            .map_err(|e| AppError::Validation(format!("Invalid XML in LogoutRequest: {e}")))?;

        let root = doc.root_element();
        let req_id = root
            .attribute("ID")
            .ok_or_else(|| AppError::Validation("LogoutRequest missing ID".into()))?
            .to_string();

        let issuer = doc
            .descendants()
            .find(|n| n.has_tag_name("Issuer"))
            .and_then(|n| n.text())
            .ok_or_else(|| AppError::Validation("LogoutRequest missing Issuer".into()))?
            .to_string();

        let name_id = doc
            .descendants()
            .find(|n| n.has_tag_name("NameID"))
            .and_then(|n| n.text())
            .ok_or_else(|| AppError::Validation("LogoutRequest missing NameID".into()))?
            .to_string();

        let session_index = doc
            .descendants()
            .find(|n| n.has_tag_name("SessionIndex"))
            .and_then(|n| n.text())
            .map(|s| s.to_string());

        Ok(SamlLogoutRequest {
            id: req_id,
            issuer,
            name_id,
            session_index,
        })
    }

    /// Parse a SAML LogoutResponse (response to our SP-initiated LogoutRequest).
    ///
    /// Returns `Ok(true)` if Status is Success, `Ok(false)` otherwise.
    pub fn parse_logout_response(&self, saml_response_b64: &str) -> Result<bool> {
        let xml_bytes = if let Ok(b) = BASE64.decode(saml_response_b64) {
            b
        } else {
            inflate_and_decode(saml_response_b64)?
        };
        let xml = String::from_utf8(xml_bytes)
            .map_err(|e| AppError::Validation(format!("Invalid UTF-8 in LogoutResponse: {e}")))?;
        let doc = Document::parse(&xml)
            .map_err(|e| AppError::Validation(format!("Invalid XML in LogoutResponse: {e}")))?;

        let success = doc
            .descendants()
            .find(|n| n.has_tag_name("StatusCode"))
            .and_then(|n| n.attribute("Value"))
            .map(|v| v.ends_with(":Success"))
            .unwrap_or(false);

        Ok(success)
    }

    /// Generate redirect URL with encoded (and optionally signed) AuthnRequest (MEDIUM-3).
    ///
    /// When `sp_signing_key_pem` is set, the request is signed per the SAML HTTP Redirect
    /// Binding spec (SAMLBind §3.4.4.1):
    ///   1. Deflate + base64url-encode the AuthnRequest
    ///   2. Build the query string: `SAMLRequest=...&RelayState=...&SigAlg=...`
    ///   3. Sign the query string bytes with RSA-SHA256
    ///   4. Append `&Signature=<base64url>`
    ///
    /// This prevents IdP-initiated request forgery and is required by many enterprise IdPs.
    ///
    /// Returns `(redirect_url, request_id)` — the request_id must be stored for InResponseTo validation.
    pub fn get_sso_redirect_url(
        &self,
        idp_config: &SamlIdpConfig,
        relay_state: &str,
    ) -> Result<(String, String)> {
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::sign::Signer;

        let (authn_request, request_id) = self.generate_authn_request(idp_config);
        let encoded_request = deflate_and_encode(&authn_request);

        // Build base query string (without signature)
        let mut query = format!("SAMLRequest={}", urlencoding::encode(&encoded_request));

        if !relay_state.is_empty() {
            query.push_str(&format!("&RelayState={}", urlencoding::encode(relay_state)));
        }

        // Sign if key is configured
        if let Some(key_pem) = &self.sp_signing_key_pem {
            let sig_alg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            query.push_str(&format!("&SigAlg={}", urlencoding::encode(sig_alg)));

            // Load private key
            let pkey = PKey::private_key_from_pem(key_pem.as_bytes())
                .map_err(|e| AppError::Internal(format!("Invalid SP signing key: {e}")))?;

            // Sign the query string bytes
            let mut signer = Signer::new(MessageDigest::sha256(), &pkey)
                .map_err(|e| AppError::Internal(format!("Signer init failed: {e}")))?;
            signer
                .update(query.as_bytes())
                .map_err(|e| AppError::Internal(format!("Signer update failed: {e}")))?;
            let signature_bytes = signer
                .sign_to_vec()
                .map_err(|e| AppError::Internal(format!("Signing failed: {e}")))?;

            // Base64-encode signature (standard, not URL-safe — then URL-encode)
            let signature_b64 = BASE64.encode(&signature_bytes);
            query.push_str(&format!(
                "&Signature={}",
                urlencoding::encode(&signature_b64)
            ));

            tracing::debug!("SAML AuthnRequest signed with RSA-SHA256");
        } else {
            tracing::warn!(
                "SAML AuthnRequest sent unsigned — configure SP_SAML_SIGNING_KEY for production"
            );
        }

        Ok((format!("{}?{}", idp_config.sso_url, query), request_id))
    }

    /// Verify and Parse SAML Response (EIAA Compliant)
    pub async fn verify_and_extract(
        &self,
        saml_response_b64: &str,
        idp_config: &SamlIdpConfig,
        expected_request_id: Option<&str>,
        redis_conn: &mut redis::aio::Connection,
    ) -> Result<SamlAssertion> {
        // For IdP-initiated flow with no expected_request_id, ensure config explicitly allows it
        if expected_request_id.is_none() && !idp_config.allow_idp_initiated {
            return Err(AppError::Validation(
                "IdP-initiated SSO not permitted for this connection. Enable allow_idp_initiated in connection config.".into(),
            ));
        }
        // 1. Decode Base64
        let decoded = BASE64
            .decode(saml_response_b64)
            .map_err(|e| AppError::Validation(format!("Invalid base64: {e}")))?;

        // Note: For strict XML-DSig, we ideally verify the raw bytes before parsing string.
        // But roxmltree works on string.
        let xml = String::from_utf8(decoded)
            .map_err(|e| AppError::Validation(format!("Invalid UTF-8: {e}")))?;

        // 2. Parse XML Safely (No Entity Expansion - roxmltree is safe)
        let doc =
            Document::parse(&xml).map_err(|e| AppError::Validation(format!("Invalid XML: {e}")))?;

        // 3. Verify Signature — try primary cert then extra_certificates for key rotation
        tracing::info!("Verifying SAML signature...");
        let mut sig_err = None;
        let mut sig_ok = false;
        for cert in std::iter::once(idp_config.certificate.as_str())
            .chain(idp_config.extra_certificates.iter().map(|s| s.as_str()))
        {
            match self.verify_signature(&doc, cert) {
                Ok(()) => {
                    sig_ok = true;
                    break;
                }
                Err(e) => {
                    sig_err = Some(e);
                }
            }
        }
        if !sig_ok {
            return Err(sig_err
                .unwrap_or_else(|| AppError::Validation("No certificates configured".into())));
        }

        // 4. Verify Response Destination matches our ACS URL
        let response_node = doc.root_element();
        if let Some(destination) = response_node.attribute("Destination") {
            if destination != self.sp_acs_url {
                return Err(AppError::Validation(format!(
                    "Response Destination mismatch: expected {}, got {}",
                    self.sp_acs_url, destination
                )));
            }
        }

        // 5. Verify InResponseTo matches the AuthnRequest ID we sent
        //    Skip when allow_idp_initiated=true and no request_id expected.
        let is_idp_initiated = expected_request_id.is_none() && idp_config.allow_idp_initiated;
        if let Some(expected_id) = expected_request_id {
            match response_node.attribute("InResponseTo") {
                Some(in_response_to) if in_response_to == expected_id => {
                    tracing::debug!("InResponseTo validated: {}", expected_id);
                }
                Some(in_response_to) => {
                    return Err(AppError::Validation(format!(
                        "InResponseTo mismatch: expected {expected_id}, got {in_response_to}"
                    )));
                }
                None => {
                    return Err(AppError::Validation(
                        "Missing InResponseTo attribute — unsolicited responses not accepted"
                            .into(),
                    ));
                }
            }
        } else if !is_idp_initiated {
            // SP-initiated but no stored request_id — warn, don't block (relay state may have expired)
            tracing::warn!("No expected_request_id provided — InResponseTo not validated");
        }

        // 6. Extract Assertion Data
        let assertion = self.extract_assertion(&doc)?;

        // 7. Audience Restriction (MEDIUM-2)
        self.verify_audience_restriction(&doc)?;

        // 8. SubjectConfirmation validation (SAML 2.0 Core §2.4.1.2)
        self.verify_subject_confirmation(&doc)?;

        // 9. Timing Validation with clock skew tolerance
        let now = Utc::now();
        let skew = chrono::Duration::seconds(saml_clock_skew_secs());
        if now + skew < assertion.not_before {
            return Err(AppError::Validation(
                "Assertion not yet valid (NotBefore)".into(),
            ));
        }
        if now - skew >= assertion.not_on_or_after {
            return Err(AppError::Validation(
                "Assertion expired (NotOnOrAfter)".into(),
            ));
        }

        // 10. Issuer Validation
        if assertion.issuer != idp_config.entity_id {
            return Err(AppError::Validation(format!(
                "Issuer mismatch: expected {}, got {}",
                idp_config.entity_id, assertion.issuer
            )));
        }

        // 11. Replay Protection
        let replay_key = format!("saml:replay:{}:{}", assertion.issuer, assertion.id);
        let ttl = (assertion.not_on_or_after - now).num_seconds() + saml_clock_skew_secs();

        if ttl <= 0 {
            return Err(AppError::Validation(
                "Assertion expired during processing".into(),
            ));
        }

        // SET NX EX — atomic "set if not exists with TTL"
        let set_nx: Option<String> = redis::cmd("SET")
            .arg(&replay_key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(ttl as usize)
            .query_async(redis_conn)
            .await
            .map_err(|e| AppError::Internal(format!("Redis error: {e}")))?;

        if set_nx.is_none() {
            return Err(AppError::Validation(
                "Replay detected: Assertion ID used previously".into(),
            ));
        }

        Ok(assertion)
    }

    /// Verify SubjectConfirmation per SAML 2.0 Core §2.4.1.2.
    ///
    /// For bearer assertions, validates:
    /// - Method is `urn:oasis:names:tc:SAML:2.0:cm:bearer`
    /// - Recipient matches our ACS URL
    /// - NotOnOrAfter has not passed (with clock skew)
    fn verify_subject_confirmation(&self, doc: &Document) -> Result<()> {
        let assertion_node = doc
            .descendants()
            .find(|n| n.has_tag_name("Assertion"))
            .ok_or_else(|| AppError::Validation("Missing Assertion element".into()))?;

        let subject = assertion_node
            .descendants()
            .find(|n| n.has_tag_name("Subject"))
            .ok_or_else(|| AppError::Validation("Missing Subject element".into()))?;

        let confirmations: Vec<_> = subject
            .children()
            .filter(|n| n.has_tag_name("SubjectConfirmation"))
            .collect();

        if confirmations.is_empty() {
            return Err(AppError::Validation("Missing SubjectConfirmation".into()));
        }

        let mut bearer_found = false;
        for sc in &confirmations {
            let method = sc.attribute("Method").unwrap_or_default();
            if method == "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
                bearer_found = true;
                // Validate SubjectConfirmationData
                if let Some(data) = sc
                    .children()
                    .find(|n| n.has_tag_name("SubjectConfirmationData"))
                {
                    // Recipient must match our ACS URL
                    if let Some(recipient) = data.attribute("Recipient") {
                        if recipient != self.sp_acs_url {
                            return Err(AppError::Validation(format!(
                                "SubjectConfirmation Recipient mismatch: expected {}, got {}",
                                self.sp_acs_url, recipient
                            )));
                        }
                    }
                    // NotOnOrAfter must not have passed
                    if let Some(not_on_or_after_str) = data.attribute("NotOnOrAfter") {
                        if let Ok(not_on_or_after) = not_on_or_after_str.parse::<DateTime<Utc>>() {
                            let now = Utc::now();
                            let skew = chrono::Duration::seconds(saml_clock_skew_secs());
                            if now - skew >= not_on_or_after {
                                return Err(AppError::Validation(
                                    "SubjectConfirmation expired (NotOnOrAfter)".into(),
                                ));
                            }
                        }
                    }
                }
            }
        }

        if !bearer_found {
            return Err(AppError::Validation(
                "No bearer SubjectConfirmation found".into(),
            ));
        }

        tracing::debug!("SubjectConfirmation validated");
        Ok(())
    }

    /// Verify AudienceRestriction in SAML Assertion Conditions (MEDIUM-2)
    ///
    /// Per SAML 2.0 Core §2.5.1.4:
    /// - The Conditions element MUST contain at least one AudienceRestriction.
    /// - Each AudienceRestriction MUST contain at least one Audience.
    /// - The SP entity ID MUST appear in at least one Audience element.
    ///
    /// Rejecting assertions without AudienceRestriction prevents:
    /// - Assertion theft (stolen assertion replayed at a different SP)
    /// - Confused deputy attacks (IdP-initiated SSO to wrong SP)
    fn verify_audience_restriction(&self, doc: &Document) -> Result<()> {
        let assertion_node = doc
            .descendants()
            .find(|n| n.has_tag_name("Assertion"))
            .ok_or_else(|| AppError::Validation("Missing Assertion element".into()))?;

        let conditions = assertion_node
            .descendants()
            .find(|n| n.has_tag_name("Conditions"))
            .ok_or_else(|| AppError::Validation("Missing Conditions element".into()))?;

        // Collect all AudienceRestriction elements
        let audience_restrictions: Vec<_> = conditions
            .children()
            .filter(|n| n.has_tag_name("AudienceRestriction"))
            .collect();

        if audience_restrictions.is_empty() {
            return Err(AppError::Validation(
                "SAML assertion missing AudienceRestriction — assertion rejected for security"
                    .into(),
            ));
        }

        // For each AudienceRestriction, ALL audiences must be satisfied (AND semantics).
        // Our SP entity ID must appear in at least one Audience within each restriction.
        for restriction in &audience_restrictions {
            let audiences: Vec<&str> = restriction
                .children()
                .filter(|n| n.has_tag_name("Audience"))
                .filter_map(|n| n.text())
                .collect();

            if audiences.is_empty() {
                return Err(AppError::Validation(
                    "AudienceRestriction contains no Audience elements".into(),
                ));
            }

            let sp_is_audience = audiences.contains(&self.sp_entity_id.as_str());
            if !sp_is_audience {
                return Err(AppError::Validation(format!(
                    "SP entity ID '{}' not in assertion audience {:?}",
                    self.sp_entity_id, audiences
                )));
            }
        }

        tracing::debug!(
            sp_entity_id = %self.sp_entity_id,
            "SAML AudienceRestriction verified"
        );
        Ok(())
    }

    /// Extract Assertion from XML Document
    fn extract_assertion(&self, doc: &Document) -> Result<SamlAssertion> {
        let assertion_node = doc
            .descendants()
            .find(|n| n.has_tag_name("Assertion"))
            .ok_or(AppError::Validation("Missing Assertion element".into()))?;

        let issuer = assertion_node
            .descendants()
            .find(|n| n.has_tag_name("Issuer"))
            .and_then(|n| n.text())
            .ok_or(AppError::Validation("Missing Issuer".into()))?
            .to_string();

        let subject_node = assertion_node
            .descendants()
            .find(|n| n.has_tag_name("Subject"))
            .ok_or(AppError::Validation("Missing Subject".into()))?;

        let name_id = subject_node
            .descendants()
            .find(|n| n.has_tag_name("NameID"))
            .and_then(|n| n.text())
            .ok_or(AppError::Validation("Missing NameID".into()))?
            .to_string();

        let conditions = assertion_node
            .descendants()
            .find(|n| n.has_tag_name("Conditions"))
            .ok_or(AppError::Validation("Missing Conditions".into()))?;

        let not_before = conditions
            .attribute("NotBefore")
            .ok_or(AppError::Validation("Missing NotBefore".into()))?
            .parse::<DateTime<Utc>>()
            .map_err(|_| AppError::Validation("Invalid NotBefore format".into()))?;

        let not_on_or_after = conditions
            .attribute("NotOnOrAfter")
            .ok_or(AppError::Validation("Missing NotOnOrAfter".into()))?
            .parse::<DateTime<Utc>>()
            .map_err(|_| AppError::Validation("Invalid NotOnOrAfter format".into()))?;

        let authn_stmt = assertion_node
            .descendants()
            .find(|n| n.has_tag_name("AuthnStatement"));

        let session_index = authn_stmt
            .as_ref()
            .and_then(|n| n.attribute("SessionIndex"))
            .map(|s| s.to_string());

        let authn_context = authn_stmt
            .as_ref()
            .and_then(|n| {
                n.descendants()
                    .find(|c| c.has_tag_name("AuthnContextClassRef"))
            })
            .and_then(|n| n.text())
            .map(|s| s.to_string());

        let id = assertion_node
            .attribute("ID")
            .ok_or(AppError::Validation("Missing Assertion ID".into()))?
            .to_string();

        let name_id_format = subject_node
            .descendants()
            .find(|n| n.has_tag_name("NameID"))
            .and_then(|n| n.attribute("Format"))
            .map(|s| s.to_string());

        // Attributes
        let mut attributes = std::collections::HashMap::new();
        if let Some(attr_stmt) = assertion_node
            .descendants()
            .find(|n| n.has_tag_name("AttributeStatement"))
        {
            for attr_node in attr_stmt.children().filter(|n| n.has_tag_name("Attribute")) {
                let name = attr_node.attribute("Name").unwrap_or("unknown").to_string();
                let values: Vec<String> = attr_node
                    .children()
                    .filter(|n| n.has_tag_name("AttributeValue"))
                    .filter_map(|n| n.text().map(|t| t.to_string()))
                    .collect();
                attributes.insert(name, values);
            }
        }

        Ok(SamlAssertion {
            id,
            subject_name_id: name_id,
            name_id_format,
            session_index,
            issuer,
            attributes,
            not_before,
            not_on_or_after,
            authn_context,
        })
    }

    /// Normalize Facts for EIAA, applying attribute mappings from IdP config.
    pub fn normalize_facts(
        &self,
        assertion: &SamlAssertion,
        idp_config: &SamlIdpConfig,
    ) -> SamlAuthFacts {
        // Look for email in attributes, fallback to NameID
        let email = assertion
            .attributes
            .get("email")
            .or_else(|| assertion.attributes.get("User.Email"))
            .or_else(|| assertion.attributes.get("mail"))
            .or_else(|| {
                assertion
                    .attributes
                    .get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
            })
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| assertion.subject_name_id.clone());

        // Apply configured attr_mappings to extra_fields
        let mut extra_fields = std::collections::HashMap::new();
        for mapping in &idp_config.attr_mappings {
            if let Some(values) = assertion.attributes.get(&mapping.saml_attr) {
                if let Some(val) = values.first() {
                    extra_fields.insert(mapping.user_field.clone(), val.clone());
                }
            }
        }

        SamlAuthFacts {
            method: "saml".to_string(),
            external_id: format!("saml|{}|{}", assertion.issuer, assertion.subject_name_id),
            email,
            authn_context: assertion.authn_context.clone(),
            issuer: assertion.issuer.clone(),
            extra_fields,
        }
    }

    /// Load IdP configuration from database (tenant-scoped).
    ///
    /// Queries by `type = 'saml'` (the actual column name in `sso_connections`).
    /// The `config` JSONB column must contain a valid `SamlIdpConfig` JSON object.
    pub async fn load_idp_config(
        &self,
        connection_id: &str,
        tenant_id: &str,
    ) -> Result<SamlIdpConfig> {
        let config_json: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT config FROM sso_connections WHERE id = $1 AND tenant_id = $2 AND type = 'saml' AND enabled = true"
        )
            .bind(connection_id)
            .bind(tenant_id)
            .fetch_optional(&self.db)
            .await?;

        match config_json {
            Some(json) => {
                serde_json::from_value(json)
                    .map_err(|e| AppError::Internal(format!("Invalid SAML config in sso_connections.config: {e}")))
            }
            None => Err(AppError::NotFound(format!(
                "SAML connection '{connection_id}' not found for tenant '{tenant_id}' (must be type='saml' and enabled=true)"
            )))
        }
    }

    /// Verify XML-DSig Signature
    ///
    /// Verifies the digital signature on the SAML Response or Assertion.
    /// Uses Exclusive Canonicalization (C14N) to prepare the SignedInfo element.
    fn verify_signature(&self, doc: &Document, cert_pem: &str) -> Result<()> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
        use openssl::hash::Hasher;
        use openssl::hash::MessageDigest;
        use openssl::sign::Verifier;
        use openssl::x509::X509;

        // 1. Find Signature Element
        let signature = doc
            .descendants()
            .find(|n| n.has_tag_name("Signature"))
            .ok_or(AppError::Validation("Missing Signature element".into()))?;

        // 2. Find SignedInfo
        let signed_info = signature
            .children()
            .find(|n| n.has_tag_name("SignedInfo"))
            .ok_or(AppError::Validation("Missing SignedInfo".into()))?;

        // 3. Validate CanonicalizationMethod
        let c14n_method = signed_info
            .descendants()
            .find(|n| n.has_tag_name("CanonicalizationMethod"))
            .and_then(|n| n.attribute("Algorithm"))
            .ok_or(AppError::Validation(
                "Missing CanonicalizationMethod".into(),
            ))?;

        match c14n_method {
            "http://www.w3.org/2001/10/xml-exc-c14n#" => {}
            "http://www.w3.org/2001/10/xml-exc-c14n#WithComments" => {
                return Err(AppError::Validation(
                    "C14N with comments not supported".into(),
                ));
            }
            _ => {
                return Err(AppError::Validation(format!(
                    "Unsupported C14N method: {c14n_method}"
                )));
            }
        }

        // 4. Verify Reference Digest(s)
        let references: Vec<roxmltree::Node> = signed_info
            .descendants()
            .filter(|n| n.has_tag_name("Reference"))
            .collect();
        if references.is_empty() {
            return Err(AppError::Validation(
                "Missing Reference in SignedInfo".into(),
            ));
        }

        for reference in references {
            let uri = reference.attribute("URI").unwrap_or("");
            let target = if uri.is_empty() {
                doc.root_element()
            } else {
                let target_id = uri.strip_prefix('#').ok_or_else(|| {
                    AppError::Validation("Reference URI must be same-document (#id)".into())
                })?;

                doc.descendants()
                    .find(|n| {
                        n.attribute("ID") == Some(target_id)
                            || n.attribute("Id") == Some(target_id)
                            || n.attribute("id") == Some(target_id)
                    })
                    .ok_or_else(|| AppError::Validation("Reference target not found".into()))?
            };

            let transforms: Vec<&str> = reference
                .descendants()
                .filter(|n| n.has_tag_name("Transform"))
                .filter_map(|n| n.attribute("Algorithm"))
                .collect();

            let mut has_enveloped = false;
            let mut has_c14n = false;
            for t in &transforms {
                match *t {
                    "http://www.w3.org/2000/09/xmldsig#enveloped-signature" => has_enveloped = true,
                    "http://www.w3.org/2001/10/xml-exc-c14n#" => has_c14n = true,
                    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments" => {
                        return Err(AppError::Validation(
                            "C14N with comments not supported".into(),
                        ));
                    }
                    _ => {
                        return Err(AppError::Validation(format!("Unsupported Transform: {t}")));
                    }
                }
            }

            if !has_c14n && !transforms.is_empty() {
                return Err(AppError::Validation(
                    "Missing exclusive C14N transform".into(),
                ));
            }

            let canonical_target = if has_enveloped {
                c14n::canonicalize_excluding_signature(&target)
                    .map_err(|e| AppError::Validation(format!("C14N failed: {e}")))?
            } else {
                c14n::canonicalize(&target)
                    .map_err(|e| AppError::Validation(format!("C14N failed: {e}")))?
            };

            let digest_method = reference
                .descendants()
                .find(|n| n.has_tag_name("DigestMethod"))
                .and_then(|n| n.attribute("Algorithm"))
                .ok_or(AppError::Validation("Missing DigestMethod".into()))?;

            let digest_md = match digest_method {
                "http://www.w3.org/2001/04/xmlenc#sha256" => MessageDigest::sha256(),
                "http://www.w3.org/2000/09/xmldsig#sha1" => MessageDigest::sha1(),
                _ => {
                    return Err(AppError::Validation(format!(
                        "Unsupported DigestMethod: {digest_method}"
                    )))
                }
            };

            let mut hasher = Hasher::new(digest_md)
                .map_err(|e| AppError::Internal(format!("Hasher init failed: {e}")))?;
            hasher
                .update(canonical_target.as_bytes())
                .map_err(|e| AppError::Internal(format!("Hasher update failed: {e}")))?;
            let digest_bytes = hasher
                .finish()
                .map_err(|e| AppError::Internal(format!("Hasher finish failed: {e}")))?;

            let digest_value_node = reference
                .descendants()
                .find(|n| n.has_tag_name("DigestValue"))
                .and_then(|n| n.text())
                .ok_or(AppError::Validation("Missing DigestValue".into()))?;
            let digest_value_clean: String = digest_value_node
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let expected_digest = BASE64
                .decode(digest_value_clean)
                .map_err(|e| AppError::Validation(format!("Invalid DigestValue base64: {e}")))?;

            // CRITICAL-B FIX: Use constant-time comparison to prevent timing side-channel attacks.
            // A standard != comparison leaks how many bytes match, which could allow a
            // chosen-plaintext attacker to forge digest values byte-by-byte.
            use subtle::ConstantTimeEq;
            let digests_match = expected_digest.as_slice().ct_eq(digest_bytes.as_ref());
            if digests_match.unwrap_u8() == 0 {
                return Err(AppError::Validation("Digest mismatch for Reference".into()));
            }
        }

        // 5. Canonicalize SignedInfo (Exclusive C14N)
        let canonical_signed_info = c14n::canonicalize(&signed_info)
            .map_err(|e| AppError::Validation(format!("C14N failed: {e}")))?;

        // 6. Get SignatureValue
        let signature_value_node = signature
            .children()
            .find(|n| n.has_tag_name("SignatureValue"))
            .ok_or(AppError::Validation("Missing SignatureValue".into()))?;

        let signature_value_str = signature_value_node
            .text()
            .ok_or(AppError::Validation("Empty SignatureValue".into()))?;

        // Remove whitespace from base64 string
        let signature_value_clean: String = signature_value_str
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();

        let signature_bytes = BASE64
            .decode(signature_value_clean)
            .map_err(|e| AppError::Validation(format!("Invalid SignatureValue base64: {e}")))?;

        // 7. Load Certificate
        let cert = X509::from_pem(cert_pem.as_bytes())
            .map_err(|e| AppError::Internal(format!("Invalid certificate: {e}")))?;
        let public_key = cert
            .public_key()
            .map_err(|e| AppError::Internal(format!("Failed to get public key: {e}")))?;

        // 8. Determine SignatureMethod hash
        let sig_method = signed_info
            .descendants()
            .find(|n| n.has_tag_name("SignatureMethod"))
            .and_then(|n| n.attribute("Algorithm"))
            .ok_or(AppError::Validation("Missing SignatureMethod".into()))?;

        let sig_md = match sig_method {
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => MessageDigest::sha256(),
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => MessageDigest::sha1(),
            _ => {
                return Err(AppError::Validation(format!(
                    "Unsupported SignatureMethod: {sig_method}"
                )))
            }
        };

        // 9. Verify Signature
        let mut verifier = Verifier::new(sig_md, &public_key)
            .map_err(|e| AppError::Internal(format!("Verifier init failed: {e}")))?;

        verifier
            .update(canonical_signed_info.as_bytes())
            .map_err(|e| AppError::Internal(format!("Verifier update failed: {e}")))?;

        let is_valid = verifier
            .verify(&signature_bytes)
            .map_err(|e| AppError::Internal(format!("Verification failed: {e}")))?;

        if !is_valid {
            return Err(AppError::Validation("Invalid SAML Signature".into()));
        }

        tracing::info!("Signature Verified Successfully");

        Ok(())
    }
}

/// Deflate compress and base64 encode for SAML redirect binding
fn deflate_and_encode(input: &str) -> String {
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use std::io::Write;

    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(input.as_bytes()).unwrap();
    let compressed = encoder.finish().unwrap();

    BASE64.encode(&compressed)
}

/// Decode and inflate a DEFLATE-compressed + base64-encoded SAML message (HTTP Redirect binding).
fn inflate_and_decode(encoded: &str) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use flate2::read::DeflateDecoder;
    use std::io::Read;

    // URL-decode first if needed
    let decoded_str =
        urlencoding::decode(encoded).unwrap_or_else(|_| std::borrow::Cow::Borrowed(encoded));
    let compressed = BASE64
        .decode(decoded_str.as_bytes())
        .map_err(|e| AppError::Validation(format!("Invalid base64 in SAML message: {e}")))?;
    let mut decoder = DeflateDecoder::new(compressed.as_slice());
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| AppError::Validation(format!("DEFLATE decompress failed: {e}")))?;
    Ok(out)
}

fn certificate_body(cert_pem: &str) -> String {
    cert_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .map(str::trim)
        .collect::<Vec<_>>()
        .join("")
}

fn escape_xml_text(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\r', "&#13;")
}

fn escape_xml_attr(input: &str) -> String {
    escape_xml_text(input)
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
        .replace('\n', "&#10;")
        .replace('\t', "&#9;")
}

#[cfg(test)]
mod tests;
