//! SAML 2.0 Service
//!
//! Service Provider (SP) implementation for SAML 2.0 SSO.
//! - SP Metadata generation
//! - AuthnRequest generation  
//! - Response/Assertion parsing and validation
//! - Signature Verification (XML-DSig)
//! - Replay Protection (Redis)

use sqlx::PgPool;
use shared_types::{AppError, Result};
use serde::{Deserialize, Serialize};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Utc};
use roxmltree::Document;
// use openssl::x509::X509;
// use openssl::pkey::PKey;
// use openssl::sign::Verifier;
// use openssl::hash::MessageDigest;

mod c14n;

/// SAML IdP Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlIdpConfig {
    pub entity_id: String,
    pub sso_url: String,
    pub slo_url: Option<String>,
    pub certificate: String,  // PEM format
    pub name_id_format: Option<String>,
    pub max_assurance: Option<String>,
}

/// SAML SP Configuration (our side)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlSpConfig {
    pub entity_id: String,
    pub acs_url: String,  // Assertion Consumer Service URL
    pub slo_url: Option<String>,
}

/// SAML Assertion (parsed from Response)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAssertion {
    pub id: String,
    pub subject_name_id: String,
    pub session_index: Option<String>,
    pub issuer: String,
    pub attributes: std::collections::HashMap<String, Vec<String>>,
    pub not_before: DateTime<Utc>,
    pub not_on_or_after: DateTime<Utc>,
    pub authn_context: Option<String>,
}

/// Normalized EIAA Facts
#[derive(Debug, Clone, Serialize)]
pub struct SamlAuthFacts {
    pub method: String,
    pub external_id: String,
    pub email: String,
    pub authn_context: Option<String>,
    pub issuer: String,
}

/// SAML 2.0 Service
#[derive(Clone)]
pub struct SamlService {
    db: PgPool,
    sp_entity_id: String,
    sp_acs_url: String,
    // Redis connection is passed per request or we keep a pool here? 
    // Usually AppState has the pool. We'll take a connection for methods needing it.
}

impl SamlService {
    pub fn new(db: PgPool, sp_entity_id: String, sp_acs_url: String) -> Self {
        Self { db, sp_entity_id, sp_acs_url }
    }
    
    /// Generate SP Metadata XML
    pub fn generate_sp_metadata(&self) -> String {
        format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="{}">
    <md:SPSSODescriptor AuthnRequestsSigned="false" 
                        WantAssertionsSigned="true"
                        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                     Location="{}"
                                     index="0"
                                     isDefault="true"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>"#, 
            self.sp_entity_id,
            self.sp_acs_url,
        )
    }
    
    /// Generate SAML AuthnRequest
    pub fn generate_authn_request(&self, idp_config: &SamlIdpConfig) -> String {
        let id = format!("_id{}", shared_types::id_generator::generate_id("saml"));
        let issue_instant = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        
        // MVP: Not signing authentication requests yet (SP-initiated).
        // Enterprise usually requires signed requests.
        
        let authn_request = format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="{}"
                    Version="2.0"
                    IssueInstant="{}"
                    Destination="{}"
                    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    AssertionConsumerServiceURL="{}">
    <saml:Issuer>{}</saml:Issuer>
    <samlp:NameIDPolicy Format="{}"
                        AllowCreate="true"/>
</samlp:AuthnRequest>"#,
            id,
            issue_instant,
            idp_config.sso_url,
            self.sp_acs_url,
            self.sp_entity_id,
            idp_config.name_id_format.as_deref().unwrap_or("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
        );
        
        authn_request
    }
    
    /// Generate redirect URL with encoded AuthnRequest
    pub fn get_sso_redirect_url(&self, idp_config: &SamlIdpConfig, relay_state: &str) -> String {
        let authn_request = self.generate_authn_request(idp_config);
        
        // Deflate and encode
        let encoded = deflate_and_encode(&authn_request);
        
        let mut url = format!("{}?SAMLRequest={}", 
            idp_config.sso_url,
            urlencoding::encode(&encoded)
        );
        
        if !relay_state.is_empty() {
            url.push_str(&format!("&RelayState={}", urlencoding::encode(relay_state)));
        }
        
        url
    }
    
    /// Verify and Parse SAML Response (EIAA Compliant)
    pub async fn verify_and_extract(
        &self, 
        saml_response_b64: &str, 
        idp_config: &SamlIdpConfig,
        redis_conn: &mut redis::aio::Connection
    ) -> Result<SamlAssertion> {
        // 1. Decode Base64
        let decoded = BASE64.decode(saml_response_b64)
            .map_err(|e| AppError::Validation(format!("Invalid base64: {}", e)))?;
        
        // Note: For strict XML-DSig, we ideally verify the raw bytes before parsing string.
        // But roxmltree works on string.
        let xml = String::from_utf8(decoded)
            .map_err(|e| AppError::Validation(format!("Invalid UTF-8: {}", e)))?;
            
        // 2. Parse XML Safely (No Entity Expansion - roxmltree is safe)
        let doc = Document::parse(&xml)
            .map_err(|e| AppError::Validation(format!("Invalid XML: {}", e)))?;
            
        // 3. Verify Signature
        // We verify:
        // - CanonicalizationMethod (Exclusive C14N)
        // - Reference digest(s) with transforms (enveloped-signature + exc-c14n)
        // - SignatureValue using the IdP certificate and SignatureMethod
        
        tracing::info!("Verifying SAML signature...");
        self.verify_signature(&doc, &idp_config.certificate)?; 
        
        // 4. Extract Assertion Data
        let assertion = self.extract_assertion(&doc)?;
        
        // 5. Audience Restriction
        // extract Audience from Conditions
        
        // 6. Timing Validation
        let now = Utc::now();
        if now < assertion.not_before {
            return Err(AppError::Validation("Assertion not yet valid (NotBefore)".into()));
        }
        if now >= assertion.not_on_or_after {
            return Err(AppError::Validation("Assertion expired (NotOnOrAfter)".into()));
        }
        
        // 7. Issuer Validation
        if assertion.issuer != idp_config.entity_id {
            return Err(AppError::Validation(format!("Issuer mismatch: expected {}, got {}", idp_config.entity_id, assertion.issuer)));
        }
        
        // 8. Replay Protection
        let replay_key = format!("saml:replay:{}:{}", assertion.issuer, assertion.id);
        let ttl = (assertion.not_on_or_after - now).num_seconds();
        
        if ttl <= 0 {
             return Err(AppError::Validation("Assertion expired during processing".into()));
        }
        
        // SET NX EX
        let set_nx: Option<String> = redis::cmd("SET")
            .arg(&replay_key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(ttl as usize)
            .query_async(redis_conn)
            .await
            .map_err(|e| AppError::Internal(format!("Redis error: {}", e)))?;
            
        if set_nx.is_none() {
            return Err(AppError::Validation("Replay detected: Assertion ID used previously".into()));
        }
        
        Ok(assertion)
    }
    
    /// Extract Assertion from XML Document
    fn extract_assertion(&self, doc: &Document) -> Result<SamlAssertion> {
        let assertion_node = doc.descendants()
            .find(|n| n.has_tag_name("Assertion"))
            .ok_or(AppError::Validation("Missing Assertion element".into()))?;
            
        let issuer = assertion_node.descendants()
            .find(|n| n.has_tag_name("Issuer"))
            .and_then(|n| n.text())
            .ok_or(AppError::Validation("Missing Issuer".into()))?
            .to_string();
            
        let subject_node = assertion_node.descendants()
            .find(|n| n.has_tag_name("Subject"))
            .ok_or(AppError::Validation("Missing Subject".into()))?;
            
        let name_id = subject_node.descendants()
            .find(|n| n.has_tag_name("NameID"))
            .and_then(|n| n.text())
            .ok_or(AppError::Validation("Missing NameID".into()))?
            .to_string();
            
        let conditions = assertion_node.descendants()
            .find(|n| n.has_tag_name("Conditions"))
            .ok_or(AppError::Validation("Missing Conditions".into()))?;
            
        let not_before = conditions.attribute("NotBefore")
            .ok_or(AppError::Validation("Missing NotBefore".into()))?
            .parse::<DateTime<Utc>>()
            .map_err(|_| AppError::Validation("Invalid NotBefore format".into()))?;
            
        let not_on_or_after = conditions.attribute("NotOnOrAfter")
            .ok_or(AppError::Validation("Missing NotOnOrAfter".into()))?
            .parse::<DateTime<Utc>>()
            .map_err(|_| AppError::Validation("Invalid NotOnOrAfter format".into()))?;
            
        let authn_stmt = assertion_node.descendants()
            .find(|n| n.has_tag_name("AuthnStatement"));
            
        let session_index = authn_stmt.as_ref()
            .and_then(|n| n.attribute("SessionIndex"))
            .map(|s| s.to_string());
            
        let authn_context = authn_stmt.as_ref()
            .and_then(|n| n.descendants().find(|c| c.has_tag_name("AuthnContextClassRef")))
            .and_then(|n| n.text())
            .map(|s| s.to_string());
            
        let id = assertion_node.attribute("ID")
            .ok_or(AppError::Validation("Missing Assertion ID".into()))?
            .to_string();
            
        // Attributes
        let mut attributes = std::collections::HashMap::new();
        if let Some(attr_stmt) = assertion_node.descendants().find(|n| n.has_tag_name("AttributeStatement")) {
            for attr_node in attr_stmt.children().filter(|n| n.has_tag_name("Attribute")) {
                let name = attr_node.attribute("Name").unwrap_or("unknown").to_string();
                let values: Vec<String> = attr_node.children()
                    .filter(|n| n.has_tag_name("AttributeValue"))
                    .filter_map(|n| n.text().map(|t| t.to_string()))
                    .collect();
                attributes.insert(name, values);
            }
        }
        
        Ok(SamlAssertion {
            id,
            subject_name_id: name_id,
            session_index,
            issuer,
            attributes,
            not_before,
            not_on_or_after,
            authn_context,
        })
    }
    
    /// Normalize Facts for EIAA
    pub fn normalize_facts(&self, assertion: &SamlAssertion) -> SamlAuthFacts {
        // Look for email in attributes, fallback to NameID
        let email = assertion.attributes.get("email")
            .or_else(|| assertion.attributes.get("User.Email"))
            .or_else(|| assertion.attributes.get("mail"))
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| assertion.subject_name_id.clone());
            
        SamlAuthFacts {
            method: "saml".to_string(),
            external_id: format!("saml|{}|{}", assertion.issuer, assertion.subject_name_id),
            email,
            authn_context: assertion.authn_context.clone(),
            issuer: assertion.issuer.clone(),
        }
    }
    
    /// Load IdP configuration from database (tenant-scoped)
    pub async fn load_idp_config(&self, connection_id: &str, tenant_id: &str) -> Result<SamlIdpConfig> {
        let config_json: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT config FROM sso_connections WHERE id = $1 AND tenant_id = $2 AND protocol = 'saml' AND enabled = true"
        )
            .bind(connection_id)
            .bind(tenant_id)
            .fetch_optional(&self.db)
            .await?;
        
        match config_json {
            Some(json) => {
                serde_json::from_value(json)
                    .map_err(|e| AppError::Internal(format!("Invalid SAML config: {}", e)))
            }
            None => Err(AppError::NotFound("SAML connection not found for tenant".into()))
        }
    }

    /// Verify XML-DSig Signature
    /// 
    /// Verifies the digital signature on the SAML Response or Assertion.
    /// Uses Exclusive Canonicalization (C14N) to prepare the SignedInfo element.
    fn verify_signature(&self, doc: &Document, cert_pem: &str) -> Result<()> {
        use openssl::x509::X509;
        use openssl::hash::MessageDigest;
        use openssl::hash::Hasher;
        use openssl::sign::Verifier;
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

        // 1. Find Signature Element
        let signature = doc.descendants()
            .find(|n| n.has_tag_name("Signature"))
            .ok_or(AppError::Validation("Missing Signature element".into()))?;

        // 2. Find SignedInfo
        let signed_info = signature.children()
            .find(|n| n.has_tag_name("SignedInfo"))
            .ok_or(AppError::Validation("Missing SignedInfo".into()))?;

        // 3. Validate CanonicalizationMethod
        let c14n_method = signed_info.descendants()
            .find(|n| n.has_tag_name("CanonicalizationMethod"))
            .and_then(|n| n.attribute("Algorithm"))
            .ok_or(AppError::Validation("Missing CanonicalizationMethod".into()))?;

        match c14n_method {
            "http://www.w3.org/2001/10/xml-exc-c14n#" => {}
            "http://www.w3.org/2001/10/xml-exc-c14n#WithComments" => {
                return Err(AppError::Validation("C14N with comments not supported".into()));
            }
            _ => {
                return Err(AppError::Validation(format!("Unsupported C14N method: {}", c14n_method)));
            }
        }

        // 4. Verify Reference Digest(s)
        let references: Vec<roxmltree::Node> = signed_info.descendants()
            .filter(|n| n.has_tag_name("Reference"))
            .collect();
        if references.is_empty() {
            return Err(AppError::Validation("Missing Reference in SignedInfo".into()));
        }

        for reference in references {
            let uri = reference.attribute("URI").unwrap_or("");
            let target = if uri.is_empty() {
                doc.root_element()
            } else {
                let target_id = uri.strip_prefix('#')
                    .ok_or_else(|| AppError::Validation("Reference URI must be same-document (#id)".into()))?;

                doc.descendants().find(|n| {
                    n.attribute("ID") == Some(target_id)
                        || n.attribute("Id") == Some(target_id)
                        || n.attribute("id") == Some(target_id)
                }).ok_or_else(|| AppError::Validation("Reference target not found".into()))?
            };

            let transforms: Vec<&str> = reference.descendants()
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
                        return Err(AppError::Validation("C14N with comments not supported".into()));
                    }
                    _ => {
                        return Err(AppError::Validation(format!("Unsupported Transform: {}", t)));
                    }
                }
            }

            if !has_c14n && !transforms.is_empty() {
                return Err(AppError::Validation("Missing exclusive C14N transform".into()));
            }

            let canonical_target = if has_enveloped {
                c14n::canonicalize_excluding_signature(&target)
                    .map_err(|e| AppError::Validation(format!("C14N failed: {}", e)))?
            } else {
                c14n::canonicalize(&target)
                    .map_err(|e| AppError::Validation(format!("C14N failed: {}", e)))?
            };

            let digest_method = reference.descendants()
                .find(|n| n.has_tag_name("DigestMethod"))
                .and_then(|n| n.attribute("Algorithm"))
                .ok_or(AppError::Validation("Missing DigestMethod".into()))?;

            let digest_md = match digest_method {
                "http://www.w3.org/2001/04/xmlenc#sha256" => MessageDigest::sha256(),
                "http://www.w3.org/2000/09/xmldsig#sha1" => MessageDigest::sha1(),
                _ => return Err(AppError::Validation(format!("Unsupported DigestMethod: {}", digest_method))),
            };

            let mut hasher = Hasher::new(digest_md)
                .map_err(|e| AppError::Internal(format!("Hasher init failed: {}", e)))?;
            hasher.update(canonical_target.as_bytes())
                .map_err(|e| AppError::Internal(format!("Hasher update failed: {}", e)))?;
            let digest_bytes = hasher.finish()
                .map_err(|e| AppError::Internal(format!("Hasher finish failed: {}", e)))?;

            let digest_value_node = reference.descendants()
                .find(|n| n.has_tag_name("DigestValue"))
                .and_then(|n| n.text())
                .ok_or(AppError::Validation("Missing DigestValue".into()))?;
            let digest_value_clean: String = digest_value_node.chars().filter(|c| !c.is_whitespace()).collect();
            let expected_digest = BASE64.decode(digest_value_clean)
                .map_err(|e| AppError::Validation(format!("Invalid DigestValue base64: {}", e)))?;

            if expected_digest.as_slice() != digest_bytes.as_ref() {
                return Err(AppError::Validation("Digest mismatch for Reference".into()));
            }
        }

        // 5. Canonicalize SignedInfo (Exclusive C14N)
        let canonical_signed_info = c14n::canonicalize(&signed_info)
            .map_err(|e| AppError::Validation(format!("C14N failed: {}", e)))?;

        // 6. Get SignatureValue
        let signature_value_node = signature.children()
            .find(|n| n.has_tag_name("SignatureValue"))
            .ok_or(AppError::Validation("Missing SignatureValue".into()))?;
        
        let signature_value_str = signature_value_node.text()
            .ok_or(AppError::Validation("Empty SignatureValue".into()))?;
            
        // Remove whitespace from base64 string
        let signature_value_clean: String = signature_value_str
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();

        let signature_bytes = BASE64.decode(signature_value_clean)
            .map_err(|e| AppError::Validation(format!("Invalid SignatureValue base64: {}", e)))?;

        // 7. Load Certificate
        let cert = X509::from_pem(cert_pem.as_bytes())
            .map_err(|e| AppError::Internal(format!("Invalid certificate: {}", e)))?;
        let public_key = cert.public_key()
            .map_err(|e| AppError::Internal(format!("Failed to get public key: {}", e)))?;

        // 8. Determine SignatureMethod hash
        let sig_method = signed_info.descendants()
            .find(|n| n.has_tag_name("SignatureMethod"))
            .and_then(|n| n.attribute("Algorithm"))
            .ok_or(AppError::Validation("Missing SignatureMethod".into()))?;

        let sig_md = match sig_method {
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => MessageDigest::sha256(),
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => MessageDigest::sha1(),
            _ => return Err(AppError::Validation(format!("Unsupported SignatureMethod: {}", sig_method))),
        };

        // 9. Verify Signature
        let mut verifier = Verifier::new(sig_md, &public_key)
            .map_err(|e| AppError::Internal(format!("Verifier init failed: {}", e)))?;
        
        verifier.update(canonical_signed_info.as_bytes())
            .map_err(|e| AppError::Internal(format!("Verifier update failed: {}", e)))?;
            
        let is_valid = verifier.verify(&signature_bytes)
            .map_err(|e| AppError::Internal(format!("Verification failed: {}", e)))?;

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
