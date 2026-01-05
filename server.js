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
        origin: process.env.FRONTEND_URL,
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

    socket.on('register', (userId) => {
        if (userId) {
            userSockets.set(userId.toString(), socket.id);
        }
    });

    socket.on('disconnect', () => {
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

        // Unban everyone to clear false positives
        await db.execute('UPDATE users SET is_banned = 0, ban_reason = NULL');
    } catch (err) {
    }
};

const PORT = process.env.PORT || 5000;
server.listen(PORT, async () => {
    await initDB();
    console.log(`Server running on port ${PORT}`);
});
