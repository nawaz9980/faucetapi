const pool = require('./config/db');
require('dotenv').config();

async function testAuth() {
    const testIdentifier = 'test_user_' + Date.now();
    const testRefCode = 'REF_' + Math.random().toString(36).substring(2, 6).toUpperCase();

    console.log('Testing Database Connection...');
    try {
        const [rows] = await pool.execute('SELECT 1');
        console.log('Database Connected Successfully!');
    } catch (err) {
        console.error('Database Connection Failed:', err.message);
        return;
    }

    console.log(`Attempting to simulate registration for: ${testIdentifier}`);
    try {
        const [result] = await pool.execute(
            'INSERT INTO users (username, referral_code, last_ip) VALUES (?, ?, ?)',
            [testIdentifier, testRefCode, '127.0.0.1']
        );
        console.log('User registered with ID:', result.insertId);

        const [userRows] = await pool.execute('SELECT * FROM users WHERE id = ?', [result.insertId]);
        console.log('Retrieved user from DB:', userRows[0] ? 'YES' : 'NO');

        if (userRows[0]) {
            console.log('Deleting test user...');
            await pool.execute('DELETE FROM users WHERE id = ?', [result.insertId]);
            console.log('Test user cleaned up.');
        }
    } catch (err) {
        console.error('Auth Simulation Failed:', err.message);
    } finally {
        process.exit();
    }
}

testAuth();
