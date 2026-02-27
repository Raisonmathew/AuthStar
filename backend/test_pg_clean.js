const { Client } = require('pg');

async function clean() {
    const client = new Client({ connectionString: 'postgres://idaas_user:dev_password_change_me@127.0.0.1:5432/postgres' });
    await client.connect();
    try {
        const res = await client.query("SELECT datname FROM pg_database WHERE datname LIKE '_sqlx_test_%'");
        for (let row of res.rows) {
            console.log(`Dropping ${row.datname}`);
            await client.query(`DROP DATABASE "${row.datname}"`);
        }
        console.log("Cleanup complete");
    } catch (e) {
        console.error(e);
    } finally {
        await client.end();
    }
}
clean();
