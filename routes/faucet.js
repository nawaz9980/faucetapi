const express = require('express');
const router = express.Router();
const db = require('../config/db');
const auth = require('../middleware/auth');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { normalizeIp } = require('../utils/helpers');

const captchaLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 10, // Limit each IP to 10 requests per windowMs
    message: { error: 'Too many captcha requests. Please wait a minute.' },
    standardHeaders: true,
    legacyHeaders: false,
    validate: { trustProxy: false },
});

// Helper to get settings
const getSetting = async (key, defaultValue) => {
    try {
        const [rows] = await db.execute('SELECT setting_value FROM settings WHERE setting_key = ?', [key]);
        return rows.length > 0 ? rows[0].setting_value : defaultValue;
    } catch (err) {
        return defaultValue;
    }
};

const CLAIM_COOLDOWN_MS = 10 * 1000; // 10 seconds
const DAILY_LIMIT = 500;
const REFERRAL_PERCENT = 10;

const CAPTCHA_EMOJIS = [
    { name: 'Apple', icon: '🍎' },
    { name: 'Banana', icon: '🍌' },
    { name: 'Pizza', icon: '🍕' },
    { name: 'Burger', icon: '🍔' },
    { name: 'Rocket', icon: '🚀' },
    { name: 'Car', icon: '🚗' },
    { name: 'Dog', icon: '🐶' },
    { name: 'Cat', icon: '🐱' },
    { name: 'Heart', icon: '❤️' },
    { name: 'Fire', icon: '🔥' },
    { name: 'Star', icon: '⭐' },
    { name: 'Moon', icon: '🌙' }
];

// Helper to convert emoji to a simple SVG Data URL to prevent plain-text scraping
const emojiToDataUrl = (emoji) => {
    // We use a base64 encoded SVG to hide the emoji character from simple text-based scrapers
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="60" height="60"><text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" font-size="40">${emoji}</text></svg>`;
    return `data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}`;
};

router.get('/captcha', auth, captchaLimiter, async (req, res) => {
    try {
        const shuffled = [...CAPTCHA_EMOJIS].sort(() => 0.5 - Math.random());
        const options = shuffled.slice(0, 6);
        const target = options[Math.floor(Math.random() * options.length)];

        // Map icons to randomized IDs for the current request
        const secureOptions = options.map(o => ({
            id: crypto.randomBytes(8).toString('hex'),
            name: o.name,
            icon: o.icon
        }));

        const challengeId = crypto.randomUUID();
        const claimToken = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

        // One-time Use: Delete any existing pending claims for this user
        await db.execute('DELETE FROM pending_claims WHERE user_id = ?', [req.user.id]);

        // Securely store the challenge state server-side
        await db.execute(
            'INSERT INTO pending_claims (user_id, challenge_id, target_name, options_json, claim_token, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
            [req.user.id, challengeId, target.name, JSON.stringify(secureOptions), claimToken, expiresAt]
        );

        res.json({
            challenge: `Select the ${target.name}`,
            // Sending Data URLs instead of plain-text emoji icons
            options: secureOptions.map(o => ({
                id: o.id,
                data: emojiToDataUrl(o.icon)
            })),
            challengeId,
            claimToken
        });
    } catch (error) {
        // console.error('Captcha Generation Error:', error);
        res.status(500).json({ error: 'Failed to generate challenge' });
    }
});

router.get('/status', auth, async (req, res) => {
    try {
        const [rows] = await db.execute(
            'SELECT last_claim, claims_today, last_reset_date, is_banned, ban_reason FROM users WHERE id = ?',
            [req.user.id]
        );

        const user = rows[0];
        if (user.is_banned) {
            return res.status(403).json({ error: `Banned: ${user.ban_reason}` });
        }

        const now = new Date();
        const lastReset = new Date(user.last_reset_date);

        let claimsToday = user.claims_today;
        if (now.toDateString() !== lastReset.toDateString()) {
            await db.execute(
                'UPDATE users SET claims_today = 0, last_reset_date = ? WHERE id = ?',
                [now.toISOString().split('T')[0], req.user.id]
            );
            claimsToday = 0;
        }

        const lastClaimTime = user.last_claim ? new Date(user.last_claim).getTime() : 0;
        const cooldownRemaining = Math.max(0, CLAIM_COOLDOWN_MS - (now.getTime() - lastClaimTime));

        // Fetch dynamic rewards
        const minReward = parseFloat(await getSetting('faucet_claim_min', '0.0001'));
        const maxReward = parseFloat(await getSetting('faucet_claim_max', '0.0002'));

        // console.log(`DEBUG: Status Reward Range: min=${minReward}, max=${maxReward}`);

        // Generate a session CSRF token and save it to the user
        const csrfToken = crypto.randomBytes(32).toString('hex');
        await db.execute('UPDATE users SET session_token = ? WHERE id = ?', [csrfToken, req.user.id]);

        res.json({
            claimsLeft: Math.max(0, DAILY_LIMIT - claimsToday),
            cooldownRemaining,
            rewardRange: { min: minReward, max: maxReward },
            sessionToken: csrfToken
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

router.post('/claim', auth, async (req, res) => {
    const { captcha_answer, challenge_id, claim_token, session_token, fingerprint, botMetadata, claim_speed } = req.body;
    const ip = normalizeIp(req.ip);

    if (!captcha_answer || !challenge_id || !claim_token || !session_token) {
        return res.status(400).json({ error: 'Invalid request parameters' });
    }

    try {
        const [userCheck] = await db.execute('SELECT id, username, referred_by, last_claim, claims_today, last_reset_date, fingerprint, session_token, is_banned, ban_reason FROM users WHERE id = ?', [req.user.id]);
        const user = userCheck[0];

        if (user?.is_banned) {
            return res.status(403).json({ error: `Account locked. Reason: ${user.ban_reason}` });
        }

        // 1. Session Token Validation (MAJOR FIX)
        if (!user.session_token || user.session_token !== session_token) {
            return res.status(401).json({ error: 'Session expired or CSRF detected. Please refresh the page.' });
        }

        // 2. Fingerprint Trust Policy (MAJOR FIX)
        if (user.fingerprint && user.fingerprint !== fingerprint) {
            // Log security event for analysis
            await db.execute(
                'INSERT INTO security_logs (user_id, event_type, ip, fingerprint, details) VALUES (?, ?, ?, ?, ?)',
                [user.id, 'fingerprint_mismatch', ip, fingerprint, `Stored: ${user.fingerprint}, Received: ${fingerprint}`]
            );
            return res.status(403).json({ error: 'Device mismatch. For security, please use your primary device.' });
        }

        // Verify Challenge Server-side
        const [challengeRows] = await db.execute(
            'SELECT * FROM pending_claims WHERE user_id = ? AND challenge_id = ? AND claim_token = ? AND expires_at > NOW()',
            [req.user.id, challenge_id, claim_token]
        );

        if (challengeRows.length === 0) {
            return res.status(400).json({ error: 'Challenge expired or invalid. Please refresh.' });
        }

        const challenge = challengeRows[0];
        const storedOptions = JSON.parse(challenge.options_json || '[]');

        // One-time use: Delete immediately
        await db.execute('DELETE FROM pending_claims WHERE id = ?', [challenge.id]);

        // Validate Captcha Answer using ID mapping (MAJOR FIX)
        const selectedOption = storedOptions.find(o => o.id === captcha_answer);
        if (!selectedOption || selectedOption.name !== challenge.target_name) {
            return res.status(400).json({ error: 'Incorrect Captcha. Please try again.' });
        }

        const now = new Date();
        const lastReset = new Date(user.last_reset_date);
        let claimsToday = user.claims_today;
        if (now.toDateString() !== lastReset.toDateString()) claimsToday = 0;

        if (claimsToday >= DAILY_LIMIT) return res.status(400).json({ error: 'Daily claim limit reached' });
        const lastClaimTime = user.last_claim ? new Date(user.last_claim).getTime() : 0;
        if (now.getTime() - lastClaimTime < CLAIM_COOLDOWN_MS) return res.status(400).json({ error: 'Cooldown in progress' });

        // Secure Backend Reward Calculation from DB
        const minReward = parseFloat(await getSetting('faucet_claim_min', '0.0001'));
        const maxReward = parseFloat(await getSetting('faucet_claim_max', '0.0002'));
        const amount = parseFloat((Math.random() * (maxReward - minReward) + minReward).toFixed(8));

        const connection = await db.getConnection();
        await connection.beginTransaction();

        try {
            const FAUCETPAY_API_KEY = process.env.FAUCETPAY_API_KEY;
            const CURRENCY = process.env.FAUCETPAY_CURRENCY || 'TRX';

            const sendPayout = async (toAddress, payoutAmount, isReferral = false) => {
                const params = new URLSearchParams();
                const multiplier = 100000000;
                params.append('api_key', FAUCETPAY_API_KEY);
                params.append('to', toAddress);
                params.append('amount', Math.round(payoutAmount * multiplier));
                params.append('currency', CURRENCY);
                if (isReferral) params.append('referral', 'true');

                const response = await axios.post('https://faucetpay.io/api/v1/send', params, {
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
                });

                if (response.data.status !== 200) {
                    // console.error(`FaucetPay Error (${isReferral ? 'Referral' : 'User'}):`, response.data.message);
                    throw new Error(response.data.message || 'FaucetPay Payout Failed');
                }
                return response.data;
            };

            const payoutResult = await sendPayout(user.username, amount);
            const payoutId = payoutResult.payout_id || null;

            let commission = 0;
            let referrerUsername = null;
            if (user.referred_by) {
                const [referrerRows] = await db.execute('SELECT username FROM users WHERE id = ?', [user.referred_by]);
                if (referrerRows.length > 0) {
                    commission = amount * (REFERRAL_PERCENT / 100);
                    referrerUsername = referrerRows[0].username;
                    try {
                        await sendPayout(referrerUsername, commission, true);
                    } catch (err) {
                        // console.error('Referral Payout Failed for:', referrerUsername, err.message);
                    }
                }
            }

            await connection.execute(
                'UPDATE users SET last_claim = ?, claims_today = ?, last_reset_date = ?, last_ip = ?, fingerprint = ?, session_token = NULL WHERE id = ?',
                [now, claimsToday + 1, now.toISOString().split('T')[0], ip, user.fingerprint || fingerprint, req.user.id]
            );

            await connection.execute(
                'INSERT INTO claims (user_id, amount, referral_amount, referrer_id, payout_id, ip, fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [req.user.id, amount, commission, user.referred_by || null, payoutId, ip, user.fingerprint || fingerprint]
            );

            await connection.commit();

            const io = req.app.get('io');
            // console.log('📣 Emitting new_payment event for:', user.username);
            io.emit('new_payment', {
                id: Date.now(), // Unique ID for frontend keys
                username: user.username,
                amount: amount,
                referral_amount: commission,
                referrer_username: referrerUsername,
                claimed_at: now
            });
            // console.log('✅ new_payment emitted');

            // Broadcast Updated Global Stats
            const [[globalStats]] = await db.execute(`
                SELECT 
                    (SELECT COUNT(*) FROM users) as totalUsers,
                    (SELECT COALESCE(SUM(amount), 0) FROM claims) as totalClaimed,
                    (SELECT COALESCE(SUM(referral_amount), 0) FROM claims) as totalReferralPaid
            `);
            io.emit('global_stats_update', globalStats);
            // console.log('✅ global_stats_update emitted:', globalStats);

            res.json({
                success: true,
                amount,
                referral_amount: commission,
                referrer_username: referrerUsername,
                claimsLeft: DAILY_LIMIT - (claimsToday + 1)
            });
        } catch (err) {
            await connection.rollback();
            return res.status(502).json({ error: err.message || 'FaucetPay service error' });
        } finally {
            connection.release();
        }
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

router.get('/stats', async (req, res) => {
    try {
        const [[stats]] = await db.execute(`
            SELECT 
                (SELECT COUNT(*) FROM users) as totalUsers,
                (SELECT COALESCE(SUM(amount), 0) FROM claims) as totalClaimed,
                (SELECT COALESCE(SUM(referral_amount), 0) FROM claims) as totalReferralPaid
        `);
        res.json(stats);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

router.get('/recent-payments', async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT 
                c.id, 
                u.username, 
                c.amount, 
                c.referral_amount, 
                c.claimed_at,
                r.username as referrer_username
            FROM claims c 
            JOIN users u ON c.user_id = u.id 
            LEFT JOIN users r ON c.referrer_id = r.id
            ORDER BY c.claimed_at DESC 
            LIMIT 20
        `);
        res.json(rows);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

module.exports = router;
