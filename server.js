const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const http = require('http');
const { Server } = require('socket.io');
require('dotenv').config();

const authRoutes = require('./routes/auth');
const faucetRoutes = require('./routes/faucet');
const db = require('./config/db');
const { normalizeIp } = require('./utils/helpers');

const app = express();
app.set('trust proxy', true);
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: [process.env.FRONTEND_URL, 'http://localhost:5173', 'http://127.0.0.1:5173'],
        credentials: true
    }
});

app.use(cors({
    origin: process.env.FRONTEND_URL,
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());

// Request Logger
app.use((req, res, next) => {
    next();
});

// Store io instance for routes
app.set('io', io);

// Tracking online users for notifications
const userSockets = new Map();
app.set('userSockets', userSockets);

io.on('connection', (socket) => {
    // console.log(`🔌 New socket connection: ${socket.id} (Total: ${io.engine.clientsCount})`);

    socket.on('register', (userId) => {
        if (userId) {
            // console.log(`👤 User register: ${userId} -> Socket: ${socket.id}`);
            userSockets.set(userId.toString(), socket.id);
        }
    });

    socket.on('disconnect', (reason) => {
        // console.log(`🔌 Socket disconnected: ${socket.id} Reason: ${reason}`);
        for (const [userId, socketId] of userSockets.entries()) {
            if (socketId === socket.id) {
                userSockets.delete(userId);
                break;
            }
        }
    });
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/faucet', faucetRoutes);

// Diagnostic Route
app.get('/api/test', (req, res) => res.json({ message: 'Backend is reachable', timestamp: new Date() }));

// Catch-all 404
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Database Initialization
const initDB = async () => {
    try {

        const columns = [
            { name: 'last_ip', type: 'VARCHAR(45)' },
            { name: 'fingerprint', type: 'VARCHAR(255)' },
            { name: 'is_banned', type: 'BOOLEAN DEFAULT FALSE' },
            { name: 'ban_reason', type: 'VARCHAR(255)' }
        ];

        for (const col of columns) {
            try {
                await db.execute(`ALTER TABLE users ADD COLUMN ${col.name} ${col.type}`);
            } catch (err) {
            }
        }

        // Claims Table Migration
        const claimColumns = [
            { name: 'payout_id', type: 'VARCHAR(255)' },
            { name: 'ip', type: 'VARCHAR(45)' },
            { name: 'fingerprint', type: 'VARCHAR(255)' }
        ];

        for (const col of claimColumns) {
            try {
                await db.execute(`ALTER TABLE claims ADD COLUMN ${col.name} ${col.type}`);
            } catch (err) {
            }
        }

        // Create Settings Table if not exists (redundant with schema.sql but good for auto-migration)
        await db.execute(`
            CREATE TABLE IF NOT EXISTS settings (
                setting_key VARCHAR(50) PRIMARY KEY,
                setting_value VARCHAR(255) NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        `);

        // Initialize default settings if they don't exist
        const defaultSettings = [
            { key: 'faucet_claim_min', value: '0.0001' },
            { key: 'faucet_claim_max', value: '0.0002' }
        ];

        for (const setting of defaultSettings) {
            try {
                await db.execute(
                    'INSERT IGNORE INTO settings (setting_key, setting_value) VALUES (?, ?)',
                    [setting.key, setting.value]
                );
            } catch (err) {
                // Already exists or other error
            }
        }

        // Unban everyone to clear false positives
        await db.execute('UPDATE users SET is_banned = 0, ban_reason = NULL');
    } catch (err) {
        // console.error('Database initialization error:', err);
    }
};

const PORT = process.env.PORT || 5001;
server.listen(PORT, async () => {
    await initDB();
    console.log(`Server running on port ${PORT}`);

    // Settings Watcher for Real-time Updates
    let lastSettings = {};
    setInterval(async () => {
        try {
            const [rows] = await db.execute('SELECT setting_key, setting_value FROM settings WHERE setting_key IN ("faucet_claim_min", "faucet_claim_max")');
            const currentSettings = rows.reduce((acc, row) => ({ ...acc, [row.setting_key]: row.setting_value }), {});

            if (JSON.stringify(currentSettings) !== JSON.stringify(lastSettings)) {
                lastSettings = currentSettings;
                io.emit('reward_settings_update', {
                    min: parseFloat(currentSettings.faucet_claim_min || '0.0001'),
                    max: parseFloat(currentSettings.faucet_claim_max || '0.0002')
                });
            }
        } catch (err) {
            // Silently fail to avoid spamming logs
        }
    }, 5000); // Check every 5 seconds
});
