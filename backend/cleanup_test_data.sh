#!/bin/bash
# Removes test tenant data so the signup page can be used fresh with mike@google.com
# Usage: ./cleanup_test_data.sh

DATABASE_URL="${DATABASE_URL:-postgres://idaas_user:dev_password_change_me@localhost:5432/idaas}"

cat <<'SQL' | DATABASE_URL="$DATABASE_URL" cargo run --quiet --manifest-path Cargo.toml --bin cleanup_test 2>/dev/null || \
node -e "
const { Client } = require('pg');
const client = new Client({ connectionString: process.env.DATABASE_URL || '$DATABASE_URL' });
async function run() {
  await client.connect();
  // Find all test orgs (not system/default)
  const orgs = await client.query(
    \`SELECT o.id FROM organizations o
     JOIN users u ON u.organization_id = o.id
     JOIN identities i ON i.user_id = u.id AND i.type = 'email'
     WHERE i.identifier = 'mike@google.com' OR o.slug = 'mike-goo'
       OR o.slug LIKE 'test-%' OR o.slug LIKE 'browser-test-%' OR o.slug LIKE 'csrf-test-%'\`
  );
  for (const row of orgs.rows) {
    await client.query('DELETE FROM organizations WHERE id = \$1', [row.id]);
    console.log('Deleted org:', row.id);
  }
  await client.end();
}
run().catch(e => { console.error(e.message); process.exit(1); });
"
SQL
