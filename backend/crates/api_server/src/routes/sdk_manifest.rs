use axum::{
    extract::{Query, State},
    http::header,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

use crate::state::AppState;
use shared_types::{AppError, Result};

use crate::routes::org_config::{AuthConfig, BrandingConfig, OAuthConfig};
use capsule_compiler::policy_compiler::LoginMethodsConfig;

// ─── Public Response Types ────────────────────────────────────────────────────
// These types are SAFE to serialise to the client.
// They NEVER include oauth client_id or client_secret.

#[derive(Debug, Serialize)]
pub struct SdkManifest {
    pub org_id: String,
    pub org_name: String,
    pub slug: String,
    /// Hash of branding + auth_config JSON — used as ETag value.
    pub version: u64,
    pub branding: BrandingSafeFields,
    pub flows: FlowsManifest,
}

#[derive(Debug, Serialize)]
pub struct BrandingSafeFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    pub primary_color: String,
    pub background_color: String,
    pub text_color: String,
    pub font_family: String,
}

#[derive(Debug, Serialize)]
pub struct FlowsManifest {
    pub sign_in: SignInManifest,
    pub sign_up: SignUpManifest,
}

#[derive(Debug, Serialize)]
pub struct SignInManifest {
    pub oauth_providers: Vec<OAuthDescriptor>,
    pub passkey_enabled: bool,
    pub email_password_enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct SignUpManifest {
    pub fields: Vec<FieldDescriptor>,
}

/// An OAuth provider descriptor with NO credentials — safe to expose to the client.
#[derive(Debug, Serialize)]
pub struct OAuthDescriptor {
    pub provider: String,
    pub label: String,
    pub enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct FieldDescriptor {
    pub name: String,
    pub field_type: String,
    pub label: String,
    pub required: bool,
    pub order: u32,
}

// ─── Query Params ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ManifestQuery {
    /// org_id can be a UUID or slug. Optional when X-Publishable-Key header is provided.
    pub org_id: Option<String>,
}

// ─── Core Builder (shared with auth_flow.rs) ─────────────────────────────────

/// Build a `SdkManifest` for the given organisation ID or slug.
///
/// Accepts either a UUID or a plain slug in `org_id`.
/// Returns `AppError::NotFound` when no matching org exists.
///
/// This function is `pub` so that `auth_flow::init_flow` can inject the manifest
/// into the EIAA init response without duplicating the DB query logic.
pub async fn build_org_manifest(pool: &sqlx::PgPool, org_id: &str) -> Result<SdkManifest> {
    let row = sqlx::query(
        r#"
        SELECT id, name, slug, branding, auth_config, login_methods
        FROM   organizations
        WHERE  (id = $1 OR slug = $1)
          AND  deleted_at IS NULL
        LIMIT  1
        "#,
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound(format!("Organisation not found: {org_id}")))?;

    let id: String = row.try_get("id").unwrap_or_default();
    let name: String = row.try_get("name").unwrap_or_default();
    let slug: String = row.try_get("slug").unwrap_or_default();

    let branding_json: Option<serde_json::Value> = row.try_get("branding").ok().flatten();
    let auth_config_json: Option<serde_json::Value> = row.try_get("auth_config").ok().flatten();
    let login_methods_json: Option<serde_json::Value> = row.try_get("login_methods").ok().flatten();

    // Compute version as a hash over the raw JSON bytes so clients can cache by ETag.
    let version = {
        let mut hasher = DefaultHasher::new();
        branding_json
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_default()
            .hash(&mut hasher);
        auth_config_json
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_default()
            .hash(&mut hasher);
        hasher.finish()
    };

    // Deserialise with safe defaults so a NULL column never causes a 500.
    let branding: BrandingConfig = branding_json
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_else(default_branding);

    let auth_config: AuthConfig = auth_config_json
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_else(default_auth_config);

    let login_methods: LoginMethodsConfig = login_methods_json
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();

    Ok(SdkManifest {
        org_id: id,
        org_name: name,
        slug,
        version,
        branding: BrandingSafeFields {
            logo_url: branding.logo_url,
            primary_color: branding.primary_color,
            background_color: branding.background_color,
            text_color: branding.text_color,
            font_family: branding.font_family,
        },
        flows: FlowsManifest {
            sign_in: build_sign_in_manifest(&auth_config.oauth, &login_methods),
            sign_up: build_sign_up_manifest(&auth_config),
        },
    })
}

// ─── Manifest Sub-builders ────────────────────────────────────────────────────

fn build_sign_in_manifest(oauth: &OAuthConfig, lm: &LoginMethodsConfig) -> SignInManifest {
    SignInManifest {
        email_password_enabled: lm.email_password,
        passkey_enabled: lm.passkey,
        oauth_providers: vec![
            oauth_descriptor("google", "Continue with Google", oauth.google.enabled),
            oauth_descriptor("github", "Continue with GitHub", oauth.github.enabled),
            oauth_descriptor(
                "microsoft",
                "Continue with Microsoft",
                oauth.microsoft.enabled,
            ),
        ],
    }
}

fn build_sign_up_manifest(auth_config: &AuthConfig) -> SignUpManifest {
    let fields_cfg = &auth_config.fields;
    let mut fields: Vec<FieldDescriptor> = Vec::new();
    let mut order: u32 = 0;

    if fields_cfg.email {
        fields.push(FieldDescriptor {
            name: "email".into(),
            field_type: "Email".into(),
            label: "Email address".into(),
            required: true,
            order,
        });
        order += 1;
    }

    if fields_cfg.password {
        fields.push(FieldDescriptor {
            name: "password".into(),
            field_type: "Password".into(),
            label: "Password".into(),
            required: true,
            order,
        });
        order += 1;
    }

    if fields_cfg.phone {
        fields.push(FieldDescriptor {
            name: "phone".into(),
            field_type: "Phone".into(),
            label: "Phone number".into(),
            required: false,
            order,
        });
        order += 1;
    }

    for custom in &fields_cfg.custom_fields {
        fields.push(FieldDescriptor {
            name: custom.name.clone(),
            field_type: custom.field_type.clone(),
            label: to_title_case(&custom.name),
            required: custom.required,
            order,
        });
        order += 1;
    }

    SignUpManifest { fields }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

#[inline]
fn oauth_descriptor(provider: &str, label: &str, enabled: bool) -> OAuthDescriptor {
    OAuthDescriptor {
        provider: provider.to_string(),
        label: label.to_string(),
        enabled,
    }
}

/// Convert `snake_case` field name to a human-readable "Title Case" label.
fn to_title_case(s: &str) -> String {
    s.split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn default_branding() -> BrandingConfig {
    BrandingConfig {
        logo_url: None,
        primary_color: "#3B82F6".to_string(),
        background_color: "#FFFFFF".to_string(),
        text_color: "#1F2937".to_string(),
        font_family: "Inter".to_string(),
    }
}

fn default_auth_config() -> AuthConfig {
    use crate::routes::org_config::{FieldsConfig, OAuthProvider};
    AuthConfig {
        fields: FieldsConfig {
            email: true,
            password: true,
            phone: false,
            custom_fields: vec![],
        },
        oauth: OAuthConfig {
            google: OAuthProvider {
                enabled: false,
                client_id: None,
                client_secret: None,
            },
            github: OAuthProvider {
                enabled: false,
                client_id: None,
                client_secret: None,
            },
            microsoft: OAuthProvider {
                enabled: false,
                client_id: None,
                client_secret: None,
            },
        },
        custom_css: String::new(),
        redirect_urls: vec![],
    }
}

// ─── HTTP Handler ─────────────────────────────────────────────────────────────

/// GET /api/v1/sdk/manifest?org_id=<id_or_slug>
///
/// Public endpoint — no authentication required.
/// Returns the tenant manifest used by all SDK surfaces to configure rendering.
/// Response is cacheable for 60 s (stale-while-revalidate 300 s).
///
/// The org can be resolved from:
/// 1. `?org_id=<uuid_or_slug>` query parameter
/// 2. `X-Publishable-Key: pk_test_acme` header (validated against publishable_keys table)
/// 3. `X-API-Key: pk_test_acme` header (SDKs send publishable key as API key)
pub async fn get_sdk_manifest(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<ManifestQuery>,
) -> Result<Response> {
    // Resolve org_id: prefer query param, fall back to publishable key header
    let org_id = if let Some(ref id) = params.org_id {
        id.clone()
    } else {
        // Try X-Publishable-Key or X-API-Key headers for publishable key resolution
        let pk_header = headers
            .get("x-publishable-key")
            .or_else(|| headers.get("x-api-key"))
            .and_then(|v| v.to_str().ok())
            .filter(|v| v.starts_with("pk_"));

        match pk_header {
            Some(pk) => {
                let resolved = state
                    .publishable_key_service
                    .validate(pk)
                    .await?
                    .ok_or_else(|| {
                        AppError::BadRequest("Invalid or revoked publishable key".into())
                    })?;
                resolved.tenant_id
            }
            None => {
                return Err(AppError::BadRequest(
                    "org_id query parameter or X-Publishable-Key header is required".into(),
                ));
            }
        }
    };

    let manifest = build_org_manifest(&state.db, &org_id).await?;

    let response = (
        [
            (
                header::CACHE_CONTROL,
                "public, max-age=60, stale-while-revalidate=300",
            ),
            (header::CONTENT_TYPE, "application/json"),
        ],
        Json(manifest),
    )
        .into_response();

    Ok(response)
}
