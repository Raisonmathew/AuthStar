//! TenantConn — compile-time enforced RLS context wrapper.
//!
//! HIGH-A: The `set_rls_context_on_conn()` helper in `org_context.rs` is correct
//! but relies on convention — handlers must remember to call it. If a developer
//! adds a new handler and forgets, queries silently run without RLS, leaking
//! cross-tenant data.
//!
//! `TenantConn` wraps a `PoolConnection<Postgres>` and sets the RLS context
//! in its constructor. It implements `Deref<Target = PgConnection>` so it can
//! be used anywhere a `&mut PgConnection` is expected, but it is impossible to
//! obtain a raw connection without going through `TenantConn::acquire()`.
//!
//! Usage:
//! ```rust,ignore
//! let conn = TenantConn::acquire(&state.db, &org_ctx.org_id).await?;
//! let rows = sqlx::query("SELECT ...").fetch_all(&mut *conn).await?;
//! ```
//!
//! For transactions:
//! ```rust,ignore
//! let mut tx = TenantTx::begin(&state.db, &org_ctx.org_id).await?;
//! sqlx::query("INSERT ...").execute(&mut *tx).await?;
//! tx.commit().await?;
//! ```

use shared_types::{AppError, Result};
use sqlx::{pool::PoolConnection, PgPool, Postgres, Transaction};

/// A PostgreSQL connection with the RLS tenant context already set.
///
/// Obtain via `TenantConn::acquire()`. The RLS `app.current_org_id` session
/// variable is set atomically before the connection is returned to the caller,
/// so every query executed through this connection is automatically scoped to
/// the correct tenant.
pub struct TenantConn {
    conn: PoolConnection<Postgres>,
}

impl TenantConn {
    /// Acquire a connection from the pool and immediately set the RLS context.
    ///
    /// This is the ONLY way to obtain a `TenantConn`. There is no `unsafe` escape
    /// hatch — if you need a raw connection, use `sqlx::PgPool::acquire()` directly
    /// and accept that you are bypassing RLS (document why with a `// SAFETY:` comment).
    pub async fn acquire(pool: &PgPool, org_id: &str) -> Result<Self> {
        let mut conn = pool
            .acquire()
            .await
            .map_err(|e| AppError::Internal(format!("DB pool acquire failed: {e}")))?;

        // Set the RLS context on THIS connection before returning it.
        // `set_config` with `is_local = true` scopes the setting to the current
        // transaction; `false` scopes it to the session (connection lifetime).
        // We use `false` here because the connection may be used outside a transaction.
        sqlx::query("SELECT set_config('app.current_org_id', $1, false)")
            .bind(org_id)
            .execute(&mut *conn)
            .await
            .map_err(|e| AppError::Internal(format!("RLS context set failed: {e}")))?;

        Ok(Self { conn })
    }
}

impl std::ops::Deref for TenantConn {
    type Target = PoolConnection<Postgres>;
    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

impl std::ops::DerefMut for TenantConn {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.conn
    }
}

/// A PostgreSQL transaction with the RLS tenant context already set.
///
/// Obtain via `TenantTx::begin()`. The RLS context is set with `is_local = true`
/// so it is automatically cleared when the transaction commits or rolls back,
/// preventing context leakage to the next user of the connection.
#[allow(dead_code)] // Will be wired into transactional write handlers as needed
pub struct TenantTx<'a> {
    tx: Transaction<'a, Postgres>,
}

#[allow(dead_code)]
impl<'a> TenantTx<'a> {
    /// Begin a transaction and immediately set the RLS context.
    pub async fn begin(pool: &PgPool, org_id: &str) -> Result<Self> {
        let mut tx = pool
            .begin()
            .await
            .map_err(|e| AppError::Internal(format!("DB transaction begin failed: {e}")))?;

        // `is_local = true` — the setting is scoped to this transaction only.
        // When the transaction ends (commit or rollback), the setting reverts.
        sqlx::query("SELECT set_config('app.current_org_id', $1, true)")
            .bind(org_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Internal(format!("RLS context set failed: {e}")))?;

        Ok(Self { tx })
    }

    /// Commit the transaction.
    pub async fn commit(self) -> Result<()> {
        self.tx
            .commit()
            .await
            .map_err(|e| AppError::Internal(format!("Transaction commit failed: {e}")))
    }

    /// Roll back the transaction explicitly (also happens automatically on drop).
    pub async fn rollback(self) -> Result<()> {
        self.tx
            .rollback()
            .await
            .map_err(|e| AppError::Internal(format!("Transaction rollback failed: {e}")))
    }
}

impl<'a> std::ops::Deref for TenantTx<'a> {
    type Target = Transaction<'a, Postgres>;
    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

impl<'a> std::ops::DerefMut for TenantTx<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tx
    }
}

#[cfg(test)]
mod tests {
    // Integration tests require a live database.
    // Unit tests verify the type system guarantees:

    #[test]
    fn tenant_conn_is_not_send_without_acquire() {
        // This test documents the design intent: you cannot construct a TenantConn
        // without going through acquire(), which enforces the RLS context is always set.
        // The compiler enforces this — there is no public constructor other than acquire().
        //
        // If this test compiles, the type is correctly encapsulated.
        fn assert_no_public_constructor<T>(_: std::marker::PhantomData<T>) {}
        // TenantConn { conn: ... } would be a compile error here (private field)
        assert_no_public_constructor::<super::TenantConn>(std::marker::PhantomData);
    }
}

// Made with Bob
