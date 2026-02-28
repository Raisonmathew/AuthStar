# Database Migration Rollback Strategy

## F-3 FIX: Down Migrations

All forward migrations (001–031) now have corresponding `down.sql` rollback scripts in this directory.

## Rollback Procedure

### Emergency Rollback (single migration)
```bash
# Roll back the most recent migration
psql $DATABASE_URL -f migrations/rollback/031_down.sql

# Roll back multiple migrations (in reverse order)
psql $DATABASE_URL -f migrations/rollback/031_down.sql
psql $DATABASE_URL -f migrations/rollback/030_down.sql
psql $DATABASE_URL -f migrations/rollback/029_down.sql
```

### Blue-Green Deployment Rollback
1. Keep the old deployment running alongside the new one
2. New deployment applies forward migrations
3. If rollback is needed, run down migrations BEFORE switching traffic back
4. Schema must be backward-compatible between versions (additive changes only)

## Schema Compatibility Rules

To enable safe rollback:
1. **Never DROP columns in forward migrations** — mark as deprecated, drop in a later migration
2. **Never RENAME columns** — add new column, backfill, drop old in separate migration
3. **New NOT NULL columns must have DEFAULT** — so old code can still INSERT without the column
4. **Index changes are safe** — indexes can be added/dropped without data loss

## Migration Tool

The project uses `sqlx migrate` (via `db_migrations` crate). To add rollback support
to sqlx, use the `--reversible` flag when creating new migrations:

```bash
sqlx migrate add --reversible <migration_name>
# Creates: <timestamp>_<name>.up.sql and <timestamp>_<name>.down.sql
```

For existing migrations, the down.sql files in this directory serve as the
authoritative rollback scripts.