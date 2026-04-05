#![allow(dead_code)]
//! Shared DB seed helpers for integration tests.
//!
//! All helpers use `ON CONFLICT DO NOTHING` so they're safe to call
//! from multiple tests against the same database.

use sqlx::PgPool;

/// Insert a minimal organization.
pub async fn seed_org(pool: &PgPool, id: &str, slug: &str) {
    sqlx::query(
        "INSERT INTO organizations (id, name, slug, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(format!("{slug} Corp"))
    .bind(slug)
    .execute(pool)
    .await
    .expect("seed_org");
}

/// Insert an organization with explicit branding and auth_config JSON.
pub async fn seed_org_with_config(
    pool: &PgPool,
    id: &str,
    slug: &str,
    branding: serde_json::Value,
    auth_config: serde_json::Value,
) {
    sqlx::query(
        "INSERT INTO organizations (id, name, slug, branding, auth_config, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(format!("{slug} Corp"))
    .bind(slug)
    .bind(branding)
    .bind(auth_config)
    .execute(pool)
    .await
    .expect("seed_org_with_config");
}

/// Insert a user (core record) in the given organization.
/// The `users` table has NO `email` column — use [`seed_identity`] for that.
pub async fn seed_user(pool: &PgPool, user_id: &str, org_id: &str) {
    sqlx::query(
        "INSERT INTO users (id, first_name, last_name, organization_id)
         VALUES ($1, 'Test', 'User', $2)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(user_id)
    .bind(org_id)
    .execute(pool)
    .await
    .expect("seed_user");
}

/// Insert an email identity row in the `identities` table.
pub async fn seed_identity(
    pool: &PgPool,
    identity_id: &str,
    user_id: &str,
    email: &str,
    org_id: &str,
) {
    sqlx::query(
        "INSERT INTO identities (id, user_id, type, identifier, verified, organization_id)
         VALUES ($1, $2, 'email', $3, true, $4)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(identity_id)
    .bind(user_id)
    .bind(email)
    .bind(org_id)
    .execute(pool)
    .await
    .expect("seed_identity");
}

/// Insert a password hash for a user.
pub async fn seed_password(pool: &PgPool, user_id: &str, password: &str) {
    let hash = auth_core::hash_password(password).expect("hash_password");
    sqlx::query(
        "INSERT INTO passwords (user_id, password_hash)
         VALUES ($1, $2)
         ON CONFLICT (user_id) DO NOTHING",
    )
    .bind(user_id)
    .bind(&hash)
    .execute(pool)
    .await
    .expect("seed_password");
}

/// Insert an organization membership row.
pub async fn seed_membership(
    pool: &PgPool,
    membership_id: &str,
    user_id: &str,
    org_id: &str,
    role: &str,
) {
    sqlx::query(
        "INSERT INTO memberships (id, user_id, organization_id, role)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(membership_id)
    .bind(user_id)
    .bind(org_id)
    .bind(role)
    .execute(pool)
    .await
    .expect("seed_membership");
}
