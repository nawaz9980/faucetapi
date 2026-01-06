const express = require('express');
const router = express.Router();
const db = require('../config/db');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { normalizeIp } = require('../utils/helpers');

// Simple crypto for referral code generation
const generateReferralCode = () => Math.random().toString(36).substring(2, 10).toUpperCase();

router.post('/login', async (req, res) => {
    const { identifier, referredBy, fingerprint, botMetadata } = req.body;
    const ip = normalizeIp(req.ip);

    if (!identifier) {
        return res.status(400).json({ error: 'Username or Email is required' });
    }

    try {
        // 1. Anti-Bot: Basic JavaScript Trap Check
        if (botMetadata && botMetadata.webdriver) {
            // Logically we could track this in DB silently if needed
        }

        // FaucetPay Address Verification
        const FAUCETPAY_API_KEY = process.env.FAUCETPAY_API_KEY;
        if (!FAUCETPAY_API_KEY) {
            return res.status(500).json({ error: 'FaucetPay API Key is missing.' });
        }

        // Check if user exists
        let [rows] = await db.execute('SELECT * FROM users WHERE username = ?', [identifier]);
        let user;

        if (rows.length === 0) {
            // 2. Strict Multi-Account Detection (Registration Block)
            // Check if ANY user already exists with this device (fingerprint) or IP
            const [existing] = await db.execute(
                'SELECT id FROM users WHERE (fingerprint IS NOT NULL AND fingerprint = ?) OR last_ip = ? LIMIT 1',
                [fingerprint || 'NONE', ip]
            );

            if (existing.length > 0) {
                return res.status(403).json({ error: 'Multiple accounts are not allowed on the same device or IP.' });
            }

            // Verify with FaucetPay
            try {
                const params = new URLSearchParams();
                params.append('api_key', FAUCETPAY_API_KEY);
                params.append('address', identifier);
                const response = await axios.post('https://faucetpay.io/api/v1/checkaddress', params, {
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
                });
                if (response.data.status !== 200) {
                    return res.status(400).json({ error: response.data.message || 'Verification failed.' });
                }
            } catch (fpError) {
                return res.status(502).json({ error: 'Error connecting to FaucetPay.' });
            }

            const referralCode = generateReferralCode();
            let referrerId = null;
            if (referredBy) {
                const [refRows] = await db.execute('SELECT id FROM users WHERE referral_code = ? OR username = ?', [referredBy, referredBy]);
                if (refRows.length > 0) referrerId = refRows[0].id;
            }

            const [result] = await db.execute(
                'INSERT INTO users (username, referral_code, referred_by, last_ip, fingerprint) VALUES (?, ?, ?, ?, ?)',
                [identifier, referralCode, referrerId, ip, fingerprint]
            );
            const [newUserRows] = await db.execute('SELECT * FROM users WHERE id = ?', [result.insertId]);
            user = newUserRows[0];

            // Broadcast Updated Global Stats for new user registration
            const io = req.app.get('io');
            if (io) {
                const [[globalStats]] = await db.execute(`
                    SELECT 
                        (SELECT COUNT(*) FROM users) as totalUsers,
                        (SELECT COALESCE(SUM(amount), 0) FROM claims) as totalClaimed,
                        (SELECT COALESCE(SUM(referral_amount), 0) FROM claims) as totalReferralPaid
                `);
                // console.log('📣 Emitting global_stats_update for new user join');
                io.emit('global_stats_update', globalStats);
                // console.log('✅ global_stats_update emitted');
            } else {
                // console.warn('⚠️ Registration: Socket.io instance not found');
            }
        } else {
            user = rows[0];
            if (user.is_banned) {
                return res.status(403).json({ error: `You are banned. Reason: ${user.ban_reason}` });
            }
            // Update IP and fingerprint on login for existing users
            await db.execute('UPDATE users SET last_ip = ?, fingerprint = ? WHERE id = ?', [ip, fingerprint, user.id]);
        }

        const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.json({
            success: true,
            user: { id: user.id, username: user.username, balance: user.balance, referral_code: user.referral_code }
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error: ' + (error.message || 'Unknown error') });
    }
});

router.get('/me', async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Not authenticated' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const [rows] = await db.execute('SELECT id, username, balance, referral_code FROM users WHERE id = ?', [decoded.id]);

        if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

        res.json({ user: rows[0] });
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

router.post('/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ success: true });
});

module.exports = router;
