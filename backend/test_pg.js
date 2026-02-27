const { Client } = require('pg');

async function test() {
    const client = new Client({ connectionString: 'postgres://idaas_user:dev_password_change_me@127.0.0.1:5432/idaas' });
    await client.connect();

    try {
        console.log("1. CREATE TABLE");
        await client.query(`
        CREATE TABLE IF NOT EXISTS user_factors (
            id VARCHAR(64) PRIMARY KEY,
            user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            tenant_id VARCHAR(64) NOT NULL,
            factor_type VARCHAR(32) NOT NULL,
            factor_data JSONB DEFAULT '{}'::jsonb,
            status VARCHAR(16) DEFAULT 'pending' NOT NULL,
            enrolled_at TIMESTAMPTZ,
            last_used_at TIMESTAMPTZ,
            disabled_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
            updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
            UNIQUE (user_id, factor_type, tenant_id)
        );
    `);

        console.log("2. INDEX 1");
        await client.query(`CREATE INDEX IF NOT EXISTS idx_user_factors_user_id ON user_factors(user_id);`);

        console.log("3. INDEX 2");
        await client.query(`CREATE INDEX IF NOT EXISTS idx_user_factors_tenant_id ON user_factors(tenant_id);`);

        console.log("4. INDEX 3");
        await client.query(`CREATE INDEX IF NOT EXISTS idx_user_factors_type_status ON user_factors(factor_type, status);`);

        console.log("Success!");
    } catch (err) {
        console.error("FAIL:", err.message);
    } finally {
        await client.end();
    }
}

test();
