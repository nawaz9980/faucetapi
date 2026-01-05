const db = require('./config/db');

async function checkDB() {
    try {
        const [rows] = await db.execute('SELECT id, username, last_ip, fingerprint FROM users');
        console.log('--- USERS TABLE ---');
        console.table(rows);
    } catch (err) {
        console.error('Error:', err.message);
    } finally {
        process.exit();
    }
}

checkDB();
