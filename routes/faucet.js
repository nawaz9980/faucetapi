const express = require('express');
const router = express.Router();
const db = require('../config/db');
const auth = require('../middleware/auth');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { normalizeIp } = require('../utils/helpers');

// Faucet Settings
const CLAIM_REWARD_MIN = 0.0001;
const CLAIM_REWARD_MAX = 0.0002;
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

router.get('/captcha', auth, (req, res) => {
    const shuffled = [...CAPTCHA_EMOJIS].sort(() => 0.5 - Math.random());
    const options = shuffled.slice(0, 6);
    const target = options[Math.floor(Math.random() * options.length)];

    const captchaToken = jwt.sign(
        { target: target.name, id: req.user.id },
        process.env.JWT_SECRET,
        { expiresIn: '5m' }
    );

    res.json({
        challenge: `Select the ${target.name}`,
        options: options.map(o => o.icon),
        captchaToken
    });
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

        res.json({
            claimsLeft: Math.max(0, DAILY_LIMIT - claimsToday),
            cooldownRemaining,
            rewardRange: { min: CLAIM_REWARD_MIN, max: CLAIM_REWARD_MAX }
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

router.post('/claim', auth, async (req, res) => {
    const { captcha_answer, captcha_token, fingerprint, botMetadata, claim_speed } = req.body;
    const ip = normalizeIp(req.ip);

    if (!captcha_answer || !captcha_token) {
        return res.status(400).json({ error: 'Captcha is required' });
    }

    try {
        const [userCheck] = await db.execute('SELECT id, username, referred_by, last_claim, claims_today, last_reset_date, fingerprint, is_banned, ban_reason FROM users WHERE id = ?', [req.user.id]);
        const user = userCheck[0];

        if (user?.is_banned) {
            return res.status(403).json({ error: `Account locked. Reason: ${user.ban_reason}` });
        }

        // Verify Captcha
        const decoded = jwt.verify(captcha_token, process.env.JWT_SECRET);
        if (decoded.id !== req.user.id) throw new Error('Invalid token owner');

        const selectedEmoji = CAPTCHA_EMOJIS.find(e => e.icon === captcha_answer);
        if (!selectedEmoji || selectedEmoji.name !== decoded.target) {
            return res.status(400).json({ error: 'Incorrect Captcha. Please try again.' });
        }

        const now = new Date();
        const lastReset = new Date(user.last_reset_date);
        let claimsToday = user.claims_today;
        if (now.toDateString() !== lastReset.toDateString()) claimsToday = 0;

        if (claimsToday >= DAILY_LIMIT) return res.status(400).json({ error: 'Daily claim limit reached' });
        const lastClaimTime = user.last_claim ? new Date(user.last_claim).getTime() : 0;
        if (now.getTime() - lastClaimTime < CLAIM_COOLDOWN_MS) return res.status(400).json({ error: 'Cooldown in progress' });

        // Secure Backend Reward Calculation
        const amount = parseFloat((Math.random() * (CLAIM_REWARD_MAX - CLAIM_REWARD_MIN) + CLAIM_REWARD_MIN).toFixed(8));

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
                'UPDATE users SET last_claim = ?, claims_today = ?, last_reset_date = ?, last_ip = ?, fingerprint = ? WHERE id = ?',
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
