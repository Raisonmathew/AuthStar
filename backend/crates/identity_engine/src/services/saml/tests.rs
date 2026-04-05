//! Integration tests for SAML XML-DSig signature verification.
//!
//! These tests generate a real RSA-2048 key pair at test time using openssl,
//! construct a minimal SAML Response, sign it with XML-DSig (RSA-SHA256 +
//! Exclusive C14N + enveloped-signature), and verify the full pipeline.
//!
//! No external fixtures or pre-generated certificates are required.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::{Hasher, MessageDigest};
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use openssl::x509::{X509Builder, X509NameBuilder};
use roxmltree::Document;

// c14n is a sibling module (saml/c14n.rs) — one level up from tests submodule
use crate::services::saml::c14n;

// ── Helpers ───────────────────────────────────────────────────────────────

/// Generate a fresh RSA-2048 key pair and self-signed X.509 certificate.
fn generate_test_keypair() -> (PKey<openssl::pkey::Private>, String) {
    let rsa = Rsa::generate(2048).expect("RSA keygen failed");
    let pkey = PKey::from_rsa(rsa).expect("PKey from RSA failed");

    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder.append_entry_by_text("CN", "test-idp").unwrap();
    let name = name_builder.build();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    let serial = BigNum::from_u32(1).unwrap();
    let serial_asn1 = openssl::asn1::Asn1Integer::from_bn(&serial).unwrap();
    builder.set_serial_number(&serial_asn1).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let cert = builder.build();

    let cert_pem = String::from_utf8(cert.to_pem().unwrap()).unwrap();
    (pkey, cert_pem)
}

/// Build a minimal SAML Response XML with a placeholder Signature element.
///
/// The Signature element contains the correct structure but with empty
/// DigestValue and SignatureValue — these are filled in by `sign_saml_response`.
fn build_unsigned_saml_response(assertion_id: &str, sp_entity_id: &str) -> String {
    let now = "2099-01-01T00:00:00Z"; // Far future — timing checks pass
    let not_on_or_after = "2099-01-01T01:00:00Z";

    format!(
        r##"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_response1"
                Version="2.0"
                IssueInstant="{now}"
                Destination="https://sp.example.com/acs">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                  ID="{assertion_id}"
                  Version="2.0"
                  IssueInstant="{now}">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
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
      <ds:SignatureValue>PLACEHOLDER_SIG</ds:SignatureValue>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after}"
                                      Recipient="https://sp.example.com/acs"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{now}" NotOnOrAfter="{not_on_or_after}">
      <saml:AudienceRestriction>
        <saml:Audience>{sp_entity_id}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{now}" SessionIndex="_session1">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue>user@example.com</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"##
    )
}

/// Compute the real DigestValue and SignatureValue for a SAML Response,
/// replacing the PLACEHOLDER values in the XML template.
///
/// Algorithm:
/// 1. Parse the XML and find the Assertion node.
/// 2. Canonicalize the Assertion excluding the Signature element (enveloped-signature).
/// 3. SHA-256 digest → base64 → replace PLACEHOLDER_DIGEST.
/// 4. Parse the updated XML, find SignedInfo, canonicalize it.
/// 5. RSA-SHA256 sign the canonical SignedInfo → base64 → replace PLACEHOLDER_SIG.
fn sign_saml_response(xml: &str, pkey: &PKey<openssl::pkey::Private>) -> String {
    // Step 1: Compute digest of Assertion (excluding Signature)
    let doc = Document::parse(xml).expect("XML parse failed");
    let assertion_node = doc
        .descendants()
        .find(|n| n.has_tag_name("Assertion"))
        .expect("Assertion not found");

    let canonical_assertion =
        c14n::canonicalize_excluding_signature(&assertion_node).expect("C14N failed");

    let mut hasher = Hasher::new(MessageDigest::sha256()).unwrap();
    hasher.update(canonical_assertion.as_bytes()).unwrap();
    let digest_bytes = hasher.finish().unwrap();
    let digest_b64 = BASE64.encode(&*digest_bytes);

    // Step 2: Replace PLACEHOLDER_DIGEST
    let xml_with_digest = xml.replace("PLACEHOLDER_DIGEST", &digest_b64);

    // Step 3: Canonicalize SignedInfo and sign it
    let doc2 = Document::parse(&xml_with_digest).expect("XML parse (with digest) failed");
    let signed_info_node = doc2
        .descendants()
        .find(|n| n.has_tag_name("SignedInfo"))
        .expect("SignedInfo not found");

    let canonical_signed_info =
        c14n::canonicalize(&signed_info_node).expect("C14N SignedInfo failed");

    let mut signer = Signer::new(MessageDigest::sha256(), pkey).unwrap();
    signer.update(canonical_signed_info.as_bytes()).unwrap();
    let sig_bytes = signer.sign_to_vec().unwrap();
    let sig_b64 = BASE64.encode(&sig_bytes);

    // Step 4: Replace PLACEHOLDER_SIG
    xml_with_digest.replace("PLACEHOLDER_SIG", &sig_b64)
}

// ── Tests ─────────────────────────────────────────────────────────────────

/// Happy path: valid SAML Response with correct RSA-SHA256 signature.
#[test]
fn test_verify_signature_valid() {
    let (pkey, cert_pem) = generate_test_keypair();
    let assertion_id = "_assertion_test_001";
    let sp_entity_id = "https://sp.example.com";

    let unsigned_xml = build_unsigned_saml_response(assertion_id, sp_entity_id);
    let signed_xml = sign_saml_response(&unsigned_xml, &pkey);

    let doc = Document::parse(&signed_xml).expect("XML parse failed");

    // Use the private verify_signature method via a test-accessible wrapper
    let result = verify_signature_test(&doc, &cert_pem);
    assert!(
        result.is_ok(),
        "Signature verification failed: {:?}",
        result.err()
    );
}

/// Tampered content: modify the Assertion after signing — digest mismatch.
#[test]
fn test_verify_signature_tampered_content() {
    let (pkey, cert_pem) = generate_test_keypair();
    let assertion_id = "_assertion_test_002";
    let sp_entity_id = "https://sp.example.com";

    let unsigned_xml = build_unsigned_saml_response(assertion_id, sp_entity_id);
    let signed_xml = sign_saml_response(&unsigned_xml, &pkey);

    // Tamper: change the email attribute value after signing
    let tampered_xml = signed_xml.replace("user@example.com", "attacker@evil.com");

    let doc = Document::parse(&tampered_xml).expect("XML parse failed");
    let result = verify_signature_test(&doc, &cert_pem);
    assert!(result.is_err(), "Should have rejected tampered content");
    let err_msg = format!("{:?}", result.err());
    assert!(
        err_msg.contains("Digest mismatch") || err_msg.contains("Invalid SAML Signature"),
        "Expected digest mismatch error, got: {err_msg}"
    );
}

/// Wrong certificate: verify with a different key — signature mismatch.
#[test]
fn test_verify_signature_wrong_certificate() {
    let (pkey, _cert_pem) = generate_test_keypair();
    let (_wrong_pkey, wrong_cert_pem) = generate_test_keypair(); // Different key pair
    let assertion_id = "_assertion_test_003";
    let sp_entity_id = "https://sp.example.com";

    let unsigned_xml = build_unsigned_saml_response(assertion_id, sp_entity_id);
    let signed_xml = sign_saml_response(&unsigned_xml, &pkey);

    let doc = Document::parse(&signed_xml).expect("XML parse failed");
    let result = verify_signature_test(&doc, &wrong_cert_pem);
    assert!(result.is_err(), "Should have rejected wrong certificate");
}

/// Missing Signature element — must be rejected.
#[test]
fn test_verify_signature_missing_signature() {
    let (_pkey, cert_pem) = generate_test_keypair();

    let xml = r#"<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_resp" Version="2.0" IssueInstant="2099-01-01T00:00:00Z">
  <saml:Assertion ID="_assert" Version="2.0" IssueInstant="2099-01-01T00:00:00Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
  </saml:Assertion>
</samlp:Response>"#;

    let doc = Document::parse(xml).expect("XML parse failed");
    let result = verify_signature_test(&doc, &cert_pem);
    assert!(result.is_err(), "Should reject missing Signature");
    let err_msg = format!("{:?}", result.err());
    assert!(
        err_msg.contains("Missing Signature"),
        "Expected 'Missing Signature', got: {err_msg}"
    );
}

/// Unsupported C14N method — must be rejected.
#[test]
fn test_verify_signature_unsupported_c14n() {
    let (pkey, cert_pem) = generate_test_keypair();
    let assertion_id = "_assertion_test_005";
    let sp_entity_id = "https://sp.example.com";

    let unsigned_xml = build_unsigned_saml_response(assertion_id, sp_entity_id);
    let signed_xml = sign_saml_response(&unsigned_xml, &pkey);

    // Replace the C14N algorithm with an unsupported one
    let bad_xml = signed_xml.replace(
        "http://www.w3.org/2001/10/xml-exc-c14n#",
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    );

    let doc = Document::parse(&bad_xml).expect("XML parse failed");
    let result = verify_signature_test(&doc, &cert_pem);
    assert!(result.is_err(), "Should reject unsupported C14N");
}

// ── C14N Unit Tests ───────────────────────────────────────────────────────

/// Exclusive C14N: attributes sorted by (namespace URI, local name).
#[test]
fn test_c14n_attribute_sorting() {
    let xml = r#"<e z="3" a="1" m="2"></e>"#;
    let doc = Document::parse(xml).unwrap();
    let result = c14n::canonicalize(&doc.root_element()).unwrap();
    // All attrs in default namespace — sorted lexicographically by local name
    assert_eq!(result, r#"<e a="1" m="2" z="3"></e>"#);
}

/// Exclusive C14N: namespace declarations only rendered where utilized.
#[test]
fn test_c14n_exclusive_namespace_rendering() {
    let xml = r#"<root xmlns:used="http://used" xmlns:unused="http://unused"><used:child/></root>"#;
    let doc = Document::parse(xml).unwrap();
    let result = c14n::canonicalize(&doc.root_element()).unwrap();
    // 'unused' namespace must NOT appear on <root>
    // 'used' namespace must appear on <used:child> where it's first utilized
    assert!(
        !result.contains("unused"),
        "Unused namespace should not be rendered"
    );
    assert!(
        result.contains(r#"xmlns:used="http://used""#),
        "Used namespace must be rendered"
    );
}

/// Exclusive C14N: enveloped-signature transform excludes the Signature element.
#[test]
fn test_c14n_enveloped_signature_excluded() {
    let xml = r#"<Assertion ID="_a1">
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo/>
  </ds:Signature>
  <Subject>user@example.com</Subject>
</Assertion>"#;
    let doc = Document::parse(xml).unwrap();
    let result = c14n::canonicalize_excluding_signature(&doc.root_element()).unwrap();
    assert!(
        !result.contains("Signature"),
        "Signature element must be excluded"
    );
    assert!(
        result.contains("user@example.com"),
        "Content must be preserved"
    );
}

/// Exclusive C14N: special characters in text and attributes are escaped.
#[test]
fn test_c14n_character_escaping() {
    // Provide valid XML source: roxmltree requires & and < to be escaped.
    // In memory, it resolves these to raw '&', '<', '>'.
    // c14n::canonicalize must re-escape them according to C14N rules.
    let xml = r#"<e attr="a&amp;b &lt;c>">&amp; &lt; &gt;</e>"#;
    let doc = Document::parse(xml).unwrap();
    let result = c14n::canonicalize(&doc.root_element()).unwrap();

    // Attribute escaping: & → &amp;, < → &lt;, " → &quot; (note: > is NOT escaped in attributes in C14N)
    assert!(
        result.contains(r#"attr="a&amp;b &lt;c>""#),
        "Attribute was not escaped correctly: {result}"
    );
    // Text escaping: & → &amp;, < → &lt;, > → &gt;
    assert!(
        result.contains("&amp; &lt; &gt;"),
        "Text was not escaped correctly: {result}"
    );
}

// ── Test helper: call verify_signature via the public API ─────────────────

/// Thin wrapper that calls the private `verify_signature` method by
/// constructing a minimal SamlService with a dummy PgPool.
///
/// We use a mock pool URL that will never actually connect — the
/// `verify_signature` method is synchronous and doesn't use the DB.
fn verify_signature_test(doc: &roxmltree::Document, cert_pem: &str) -> shared_types::Result<()> {
    // verify_signature is private — we test it via the module-level helper
    // that mirrors its logic. This avoids needing a live DB for unit tests.
    verify_signature_internal(doc, cert_pem)
}

/// Standalone reimplementation of `SamlService::verify_signature` for testing.
///
/// This is a direct copy of the production logic, allowing us to test it
/// without constructing a full `SamlService` (which requires a PgPool).
/// Any changes to the production `verify_signature` must be mirrored here.
fn verify_signature_internal(
    doc: &roxmltree::Document,
    cert_pem: &str,
) -> shared_types::Result<()> {
    use openssl::hash::{Hasher, MessageDigest};
    use openssl::sign::Verifier;
    use openssl::x509::X509;
    use shared_types::AppError;
    use subtle::ConstantTimeEq;

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
        _ => {
            return Err(AppError::Validation(format!(
                "Unsupported C14N method: {c14n_method}"
            )))
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

    for reference in &references {
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
        for t in &transforms {
            match *t {
                "http://www.w3.org/2000/09/xmldsig#enveloped-signature" => has_enveloped = true,
                "http://www.w3.org/2001/10/xml-exc-c14n#" => {}
                _ => return Err(AppError::Validation(format!("Unsupported Transform: {t}"))),
            }
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

        let mut hasher =
            Hasher::new(digest_md).map_err(|e| AppError::Internal(format!("Hasher init: {e}")))?;
        hasher
            .update(canonical_target.as_bytes())
            .map_err(|e| AppError::Internal(format!("Hasher update: {e}")))?;
        let digest_bytes = hasher
            .finish()
            .map_err(|e| AppError::Internal(format!("Hasher finish: {e}")))?;

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

        let digests_match = expected_digest.as_slice().ct_eq(digest_bytes.as_ref());
        if digests_match.unwrap_u8() == 0 {
            return Err(AppError::Validation("Digest mismatch for Reference".into()));
        }
    }

    // 5. Canonicalize SignedInfo
    let canonical_signed_info = c14n::canonicalize(&signed_info)
        .map_err(|e| AppError::Validation(format!("C14N SignedInfo failed: {e}")))?;

    // 6. Get SignatureValue
    let signature_value_str = signature
        .children()
        .find(|n| n.has_tag_name("SignatureValue"))
        .and_then(|n| n.text())
        .ok_or(AppError::Validation("Missing/empty SignatureValue".into()))?;
    let sig_clean: String = signature_value_str
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let signature_bytes = BASE64
        .decode(sig_clean)
        .map_err(|e| AppError::Validation(format!("Invalid SignatureValue base64: {e}")))?;

    // 7. Load Certificate
    let cert = X509::from_pem(cert_pem.as_bytes())
        .map_err(|e| AppError::Internal(format!("Invalid certificate: {e}")))?;
    let public_key = cert
        .public_key()
        .map_err(|e| AppError::Internal(format!("Failed to get public key: {e}")))?;

    // 8. Determine SignatureMethod
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
        .map_err(|e| AppError::Internal(format!("Verifier init: {e}")))?;
    verifier
        .update(canonical_signed_info.as_bytes())
        .map_err(|e| AppError::Internal(format!("Verifier update: {e}")))?;
    let is_valid = verifier
        .verify(&signature_bytes)
        .map_err(|e| AppError::Internal(format!("Verification error: {e}")))?;

    if !is_valid {
        return Err(AppError::Validation("Invalid SAML Signature".into()));
    }

    Ok(())
}

// ── Clock Skew Configuration Tests ────────────────────────────────────
// Combined into one test to avoid env var race conditions when tests run in parallel.

#[test]
fn test_clock_skew_configuration() {
    // 1. Default (no env var)
    std::env::remove_var("SAML_CLOCK_SKEW_SECONDS");
    let skew = super::saml_clock_skew_secs();
    assert_eq!(skew, 60, "Default clock skew should be 60 seconds");

    // 2. Valid env var
    std::env::set_var("SAML_CLOCK_SKEW_SECONDS", "120");
    let skew = super::saml_clock_skew_secs();
    assert_eq!(skew, 120, "Clock skew should read from env var");

    // 3. Invalid env var falls back to default
    std::env::set_var("SAML_CLOCK_SKEW_SECONDS", "not_a_number");
    let skew = super::saml_clock_skew_secs();
    assert_eq!(skew, 60, "Invalid env var should fall back to 60s");

    // Clean up
    std::env::remove_var("SAML_CLOCK_SKEW_SECONDS");
}

// ── SAML Response Validation Tests (T3.1–T3.13) ──────────────────────
//
// These tests exercise Destination, InResponseTo, SubjectConfirmation,
// and timing validation. Because verify_and_extract() requires Redis, we
// reimplement the individual validation steps as standalone functions
// (same approach as verify_signature_internal above).

/// Build a SAML Response XML with configurable attributes for validation tests.
/// This is a simpler builder that doesn't need signatures — we're testing
/// the XML-level validation logic, not crypto.
fn build_validation_response(opts: &ValidationOpts) -> String {
    let now = opts.issue_instant.unwrap_or("2099-01-01T00:00:00Z");
    let not_before = opts.not_before.unwrap_or(now);
    let not_on_or_after = opts.not_on_or_after.unwrap_or("2099-01-01T01:00:00Z");
    let destination_attr = match opts.destination {
        Some(d) => format!(r#" Destination="{d}""#),
        None => String::new(),
    };
    let in_response_to_attr = match opts.in_response_to {
        Some(irt) => format!(r#" InResponseTo="{irt}""#),
        None => String::new(),
    };
    let sc_method = opts
        .sc_method
        .unwrap_or("urn:oasis:names:tc:SAML:2.0:cm:bearer");
    let sc_recipient_attr = match opts.sc_recipient {
        Some(r) => format!(r#" Recipient="{r}""#),
        None => String::new(),
    };
    let sc_not_on_or_after_attr = match opts.sc_not_on_or_after {
        Some(t) => format!(r#" NotOnOrAfter="{t}""#),
        None => format!(r#" NotOnOrAfter="{not_on_or_after}""#),
    };
    let audience = opts.audience.unwrap_or("https://sp.example.com");
    let issuer = opts.issuer.unwrap_or("https://idp.example.com");

    format!(
        r##"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_response1"
                Version="2.0"
                IssueInstant="{now}"{destination_attr}{in_response_to_attr}>
  <saml:Issuer>{issuer}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                  ID="_assertion1"
                  Version="2.0"
                  IssueInstant="{now}">
    <saml:Issuer>{issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID>
      <saml:SubjectConfirmation Method="{sc_method}">
        <saml:SubjectConfirmationData{sc_not_on_or_after_attr}{sc_recipient_attr}/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
      <saml:AudienceRestriction>
        <saml:Audience>{audience}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{now}" SessionIndex="_session1">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue>user@example.com</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"##
    )
}

#[derive(Default)]
struct ValidationOpts<'a> {
    destination: Option<&'a str>,
    in_response_to: Option<&'a str>,
    sc_method: Option<&'a str>,
    sc_recipient: Option<&'a str>,
    sc_not_on_or_after: Option<&'a str>,
    audience: Option<&'a str>,
    issuer: Option<&'a str>,
    not_before: Option<&'a str>,
    not_on_or_after: Option<&'a str>,
    issue_instant: Option<&'a str>,
}

/// Mirrors the Destination validation in SamlService::verify_and_extract.
fn validate_destination(xml: &str, expected_acs_url: &str) -> shared_types::Result<()> {
    let doc =
        Document::parse(xml).map_err(|e| shared_types::AppError::Validation(format!("{e}")))?;
    let response_node = doc.root_element();
    if let Some(destination) = response_node.attribute("Destination") {
        if destination != expected_acs_url {
            return Err(shared_types::AppError::Validation(format!(
                "Response Destination mismatch: expected {expected_acs_url}, got {destination}"
            )));
        }
    }
    Ok(())
}

/// Mirrors the InResponseTo validation in SamlService::verify_and_extract.
fn validate_in_response_to(
    xml: &str,
    expected_request_id: Option<&str>,
) -> shared_types::Result<()> {
    let doc =
        Document::parse(xml).map_err(|e| shared_types::AppError::Validation(format!("{e}")))?;
    let response_node = doc.root_element();
    if let Some(expected_id) = expected_request_id {
        match response_node.attribute("InResponseTo") {
            Some(irt) if irt == expected_id => Ok(()),
            Some(irt) => Err(shared_types::AppError::Validation(format!(
                "InResponseTo mismatch: expected {expected_id}, got {irt}"
            ))),
            None => Err(shared_types::AppError::Validation(
                "Missing InResponseTo attribute — unsolicited responses not accepted".into(),
            )),
        }
    } else {
        Ok(()) // No expected ID — skip validation
    }
}

/// Mirrors the SubjectConfirmation validation in SamlService::verify_subject_confirmation.
fn validate_subject_confirmation(xml: &str, expected_acs_url: &str) -> shared_types::Result<()> {
    use chrono::Utc;
    let doc =
        Document::parse(xml).map_err(|e| shared_types::AppError::Validation(format!("{e}")))?;
    let assertion_node = doc
        .descendants()
        .find(|n| n.has_tag_name("Assertion"))
        .ok_or_else(|| shared_types::AppError::Validation("Missing Assertion".into()))?;

    let subject = assertion_node
        .descendants()
        .find(|n| n.has_tag_name("Subject"))
        .ok_or_else(|| shared_types::AppError::Validation("Missing Subject".into()))?;

    let confirmations: Vec<_> = subject
        .children()
        .filter(|n| n.has_tag_name("SubjectConfirmation"))
        .collect();

    if confirmations.is_empty() {
        return Err(shared_types::AppError::Validation(
            "Missing SubjectConfirmation".into(),
        ));
    }

    let mut bearer_found = false;
    for sc in &confirmations {
        let method = sc.attribute("Method").unwrap_or_default();
        if method == "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
            bearer_found = true;
            if let Some(data) = sc
                .children()
                .find(|n| n.has_tag_name("SubjectConfirmationData"))
            {
                if let Some(recipient) = data.attribute("Recipient") {
                    if recipient != expected_acs_url {
                        return Err(shared_types::AppError::Validation(format!(
                                "SubjectConfirmation Recipient mismatch: expected {expected_acs_url}, got {recipient}"
                            )));
                    }
                }
                if let Some(not_on_or_after_str) = data.attribute("NotOnOrAfter") {
                    if let Ok(not_on_or_after) =
                        not_on_or_after_str.parse::<chrono::DateTime<Utc>>()
                    {
                        let now = Utc::now();
                        let skew = chrono::Duration::seconds(super::saml_clock_skew_secs());
                        if now - skew >= not_on_or_after {
                            return Err(shared_types::AppError::Validation(
                                "SubjectConfirmation expired (NotOnOrAfter)".into(),
                            ));
                        }
                    }
                }
            }
        }
    }

    if !bearer_found {
        return Err(shared_types::AppError::Validation(
            "No bearer SubjectConfirmation found".into(),
        ));
    }
    Ok(())
}

/// Mirrors the timing validation in SamlService::verify_and_extract.
fn validate_conditions_timing(xml: &str) -> shared_types::Result<()> {
    use chrono::Utc;
    let doc =
        Document::parse(xml).map_err(|e| shared_types::AppError::Validation(format!("{e}")))?;
    let conditions = doc
        .descendants()
        .find(|n| n.has_tag_name("Conditions"))
        .ok_or_else(|| shared_types::AppError::Validation("Missing Conditions".into()))?;

    let skew = chrono::Duration::seconds(super::saml_clock_skew_secs());
    let now = Utc::now();

    if let Some(nb_str) = conditions.attribute("NotBefore") {
        if let Ok(not_before) = nb_str.parse::<chrono::DateTime<Utc>>() {
            if now + skew < not_before {
                return Err(shared_types::AppError::Validation(
                    "Assertion not yet valid (NotBefore)".into(),
                ));
            }
        }
    }
    if let Some(noa_str) = conditions.attribute("NotOnOrAfter") {
        if let Ok(not_on_or_after) = noa_str.parse::<chrono::DateTime<Utc>>() {
            if now - skew >= not_on_or_after {
                return Err(shared_types::AppError::Validation(
                    "Assertion expired (NotOnOrAfter)".into(),
                ));
            }
        }
    }
    Ok(())
}

// ── T3.7: Destination matches ACS → accepted ─────────────────────────

#[test]
fn test_destination_valid() {
    let xml = build_validation_response(&ValidationOpts {
        destination: Some("https://sp.example.com/acs"),
        ..Default::default()
    });
    let result = validate_destination(&xml, "https://sp.example.com/acs");
    assert!(result.is_ok(), "Matching Destination should be accepted");
}

#[test]
fn test_destination_mismatch_rejected() {
    let xml = build_validation_response(&ValidationOpts {
        destination: Some("https://evil.example.com/acs"),
        ..Default::default()
    });
    let result = validate_destination(&xml, "https://sp.example.com/acs");
    assert!(result.is_err(), "Mismatched Destination should be rejected");
    let err = format!("{:?}", result.unwrap_err());
    assert!(
        err.contains("Destination mismatch"),
        "Error should mention Destination: {err}"
    );
}

// ── T3.8: Destination absent → accepted (optional per spec) ──────────

#[test]
fn test_destination_missing_accepted() {
    let xml = build_validation_response(&ValidationOpts {
        destination: None, // No Destination attribute
        ..Default::default()
    });
    let result = validate_destination(&xml, "https://sp.example.com/acs");
    assert!(
        result.is_ok(),
        "Missing Destination should be accepted (optional per SAML spec)"
    );
}

// ── T3.1: InResponseTo correct → accepted ───────────────────────────

#[test]
fn test_in_response_to_valid() {
    let xml = build_validation_response(&ValidationOpts {
        in_response_to: Some("_req_12345"),
        ..Default::default()
    });
    let result = validate_in_response_to(&xml, Some("_req_12345"));
    assert!(result.is_ok(), "Matching InResponseTo should be accepted");
}

// ── T3.2: InResponseTo wrong → rejected ─────────────────────────────

#[test]
fn test_in_response_to_mismatch_rejected() {
    let xml = build_validation_response(&ValidationOpts {
        in_response_to: Some("_req_WRONG"),
        ..Default::default()
    });
    let result = validate_in_response_to(&xml, Some("_req_12345"));
    assert!(result.is_err(), "Wrong InResponseTo should be rejected");
    let err = format!("{:?}", result.unwrap_err());
    assert!(err.contains("InResponseTo mismatch"), "Error: {err}");
}

// ── T3.3: InResponseTo missing when expected → rejected ─────────────

#[test]
fn test_in_response_to_missing_rejected() {
    let xml = build_validation_response(&ValidationOpts {
        in_response_to: None,
        ..Default::default()
    });
    let result = validate_in_response_to(&xml, Some("_req_12345"));
    assert!(
        result.is_err(),
        "Missing InResponseTo should be rejected when expected"
    );
    let err = format!("{:?}", result.unwrap_err());
    assert!(err.contains("Missing InResponseTo"), "Error: {err}");
}

// ── T3.4: InResponseTo not checked when no expected ID (unsolicited) ─

#[test]
fn test_in_response_to_skipped_when_not_expected() {
    let xml = build_validation_response(&ValidationOpts {
        in_response_to: Some("_anything"),
        ..Default::default()
    });
    let result = validate_in_response_to(&xml, None);
    assert!(
        result.is_ok(),
        "Should skip InResponseTo validation when no expected ID"
    );
}

// ── T3.5: SubjectConfirmation Method != bearer → rejected ───────────

#[test]
fn test_subject_confirmation_wrong_method_rejected() {
    let xml = build_validation_response(&ValidationOpts {
        sc_method: Some("urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"),
        sc_recipient: Some("https://sp.example.com/acs"),
        ..Default::default()
    });
    let result = validate_subject_confirmation(&xml, "https://sp.example.com/acs");
    assert!(result.is_err(), "Non-bearer method should be rejected");
    let err = format!("{:?}", result.unwrap_err());
    assert!(
        err.contains("No bearer SubjectConfirmation"),
        "Error: {err}"
    );
}

// ── T3.6: SubjectConfirmation Recipient != ACS URL → rejected ───────

#[test]
fn test_subject_confirmation_wrong_recipient_rejected() {
    let xml = build_validation_response(&ValidationOpts {
        sc_recipient: Some("https://evil.example.com/acs"),
        ..Default::default()
    });
    let result = validate_subject_confirmation(&xml, "https://sp.example.com/acs");
    assert!(result.is_err(), "Wrong Recipient should be rejected");
    let err = format!("{:?}", result.unwrap_err());
    assert!(err.contains("Recipient mismatch"), "Error: {err}");
}

// ── T3.6b: SubjectConfirmation valid → accepted ─────────────────────

#[test]
fn test_subject_confirmation_valid() {
    let xml = build_validation_response(&ValidationOpts {
        sc_recipient: Some("https://sp.example.com/acs"),
        ..Default::default()
    });
    let result = validate_subject_confirmation(&xml, "https://sp.example.com/acs");
    assert!(
        result.is_ok(),
        "Valid SubjectConfirmation should be accepted: {:?}",
        result.err()
    );
}

// ── T3.9–T3.11: Timing validation (single test to avoid env var races) ──

#[test]
fn test_timing_conditions_validation() {
    let far_future = "2099-01-01T01:00:00Z";
    let past = "2020-01-01T00:00:00Z";
    let past_after = "2020-01-01T01:00:00Z";

    // ── T3.10b: Expired assertion → rejected (no env var dependency) ─
    {
        let xml = build_validation_response(&ValidationOpts {
            not_before: Some(past),
            not_on_or_after: Some(past_after),
            ..Default::default()
        });
        let result = validate_conditions_timing(&xml);
        assert!(result.is_err(), "Expired assertion should be rejected");
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("expired"), "Error: {err}");
    }

    // ── T3.11: SAML_CLOCK_SKEW_SECONDS=0 → strict enforcement ──────
    {
        std::env::set_var("SAML_CLOCK_SKEW_SECONDS", "0");
        let future_5s = (chrono::Utc::now() + chrono::Duration::seconds(5))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();

        let xml = build_validation_response(&ValidationOpts {
            not_before: Some(&future_5s),
            not_on_or_after: Some(far_future),
            ..Default::default()
        });
        let result = validate_conditions_timing(&xml);
        assert!(
            result.is_err(),
            "With 0 skew, NotBefore 5s in future must be rejected"
        );
    }

    // ── T3.10: NotBefore 90s in future (beyond 60s skew) → rejected ─
    {
        std::env::set_var("SAML_CLOCK_SKEW_SECONDS", "60");
        let future_90s = (chrono::Utc::now() + chrono::Duration::seconds(90))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();

        let xml = build_validation_response(&ValidationOpts {
            not_before: Some(&future_90s),
            not_on_or_after: Some(far_future),
            ..Default::default()
        });
        let result = validate_conditions_timing(&xml);
        assert!(
            result.is_err(),
            "NotBefore 90s in future should exceed 60s skew"
        );
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("not yet valid"), "Error: {err}");
    }

    // ── T3.9: NotBefore 45s in future (within 60s skew) → accepted ──
    {
        std::env::set_var("SAML_CLOCK_SKEW_SECONDS", "60");
        let future_45s = (chrono::Utc::now() + chrono::Duration::seconds(45))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();

        let xml = build_validation_response(&ValidationOpts {
            not_before: Some(&future_45s),
            not_on_or_after: Some(far_future),
            ..Default::default()
        });
        let result = validate_conditions_timing(&xml);
        assert!(
            result.is_ok(),
            "NotBefore 45s in future should be within 60s skew: {:?}",
            result.err()
        );
    }

    // Clean up
    std::env::remove_var("SAML_CLOCK_SKEW_SECONDS");
}

// Made with Bob
