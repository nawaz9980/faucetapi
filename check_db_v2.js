const db = require('./config/db');

async function checkDB() {
    try {
        const [rows] = await db.execute('SELECT id, username, last_ip, fingerprint FROM users');
        console.log('--- USERS TABLE ---');
        rows.forEach(row => {
            console.log(`ID: ${row.id}, User: ${row.username}, IP: ${row.last_ip}, FP: ${row.fingerprint}`);
        });
    } catch (err) {
        console.error('Error:', err.message);
    } finally {
        process.exit();
    }
}

checkDB();
