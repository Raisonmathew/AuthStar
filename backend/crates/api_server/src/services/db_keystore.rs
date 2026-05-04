//! Database-backed keystore extension.
//!
//! Wraps the in-memory `keystore::InMemoryKeystore` with PostgreSQL persistence
//! so that signing keys survive server restarts (migration 061 — `signing_keys` table).

use ed25519_dalek::SigningKey;
use keystore::{compute_kid, InMemoryKeystore, KeyId, Keystore as _};
use rand::rngs::OsRng;
use sqlx::PgPool;
use tracing::{info, warn};

/// Load an existing signing key from the database for `purpose`, or generate
/// a fresh one, persist it, and import it into the in-memory keystore.
///
/// # Conflict safety
/// Uses `ON CONFLICT DO NOTHING` — if two racing startup processes both
/// attempt to insert, only one wins; the other re-reads the winning row.
pub async fn load_or_generate(
    ks: &InMemoryKeystore,
    pool: &PgPool,
    purpose: &str,
) -> anyhow::Result<KeyId> {
    #[derive(sqlx::FromRow)]
    struct KeyRow {
        kid: String,
        sk_hex: String,
    }

    // 1. Try to load an existing key from DB
    if let Some(row) = sqlx::query_as::<_, KeyRow>(
        "SELECT kid, sk_hex FROM signing_keys WHERE purpose = $1",
    )
    .bind(purpose)
    .fetch_optional(pool)
    .await?
    {
        let sk_bytes = hex::decode(&row.sk_hex)
            .map_err(|e| anyhow::anyhow!("corrupt sk_hex for purpose={purpose}: {e}"))?;
        let kid = ks.import_ed25519(&sk_bytes)?;
        if kid.0 != row.kid {
            warn!(
                purpose,
                stored_kid = %row.kid,
                computed_kid = %kid.0,
                "signing_keys kid mismatch — using computed kid"
            );
        }
        info!(purpose, kid = %kid.0, "Loaded persistent signing key from DB");
        return Ok(kid);
    }

    // 2. Generate a new Ed25519 key
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key();
    let sk_bytes = sk.to_bytes();
    let pk_bytes = pk.to_bytes();
    let kid = compute_kid(&pk);

    // 3. Import into the in-memory keystore
    ks.import_ed25519(&sk_bytes)?;

    // 4. Persist to DB (ON CONFLICT DO NOTHING handles rare concurrent startups)
    let rows = sqlx::query(
        "INSERT INTO signing_keys (kid, purpose, sk_hex, pk_hex) \
         VALUES ($1, $2, $3, $4) ON CONFLICT (purpose) DO NOTHING",
    )
    .bind(&kid.0)
    .bind(purpose)
    .bind(hex::encode(sk_bytes))
    .bind(hex::encode(pk_bytes))
    .execute(pool)
    .await?;

    if rows.rows_affected() == 0 {
        // Race: another process inserted first — load their key
        let row = sqlx::query_as::<_, KeyRow>(
            "SELECT kid, sk_hex FROM signing_keys WHERE purpose = $1",
        )
        .bind(purpose)
        .fetch_one(pool)
        .await?;
        let sk_bytes = hex::decode(&row.sk_hex)
            .map_err(|e| anyhow::anyhow!("corrupt sk_hex for purpose={purpose}: {e}"))?;
        let kid = ks.import_ed25519(&sk_bytes)?;
        info!(purpose, kid = %kid.0, "Loaded signing key (after concurrent insert)");
        return Ok(kid);
    }

    warn!(purpose, kid = %kid.0, "Generated new signing key and persisted to DB");
    Ok(kid)
}
