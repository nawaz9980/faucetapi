-- Database Schema for Faucet application
-- Use the database name from your .env file
-- CREATE DATABASE IF NOT EXISTS u985593197_nodejsfaucet;
-- USE u985593197_nodejsfaucet;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL, -- Stores the FaucetPay address/email
    payout_user_hash VARCHAR(255),          -- Optional: can store FaucetPay user hash
    balance DECIMAL(20, 8) DEFAULT 0,
    referral_code VARCHAR(50) UNIQUE NOT NULL,
    referred_by INT,
    last_claim TIMESTAMP NULL DEFAULT NULL,
    claims_today INT DEFAULT 0,
    last_reset_date DATE DEFAULT (CURRENT_DATE),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_ip VARCHAR(45),
    fingerprint VARCHAR(255),
    session_token VARCHAR(255),
    is_banned BOOLEAN DEFAULT FALSE,
    ban_reason VARCHAR(255),
    FOREIGN KEY (referred_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS security_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    event_type VARCHAR(50) NOT NULL, -- 'multi_account', 'bot_detected', 'speed_claim', 'ip_mismatch'
    ip VARCHAR(45),
    fingerprint VARCHAR(255),
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS claims (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    amount DECIMAL(20, 8) NOT NULL,
    referral_amount DECIMAL(20, 8) DEFAULT 0,
    referrer_id INT,
    payout_id VARCHAR(255),
    ip VARCHAR(45),
    fingerprint VARCHAR(255),
    claimed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (referrer_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS settings (
    setting_key VARCHAR(50) PRIMARY KEY,
    setting_value VARCHAR(255) NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS pending_claims (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    challenge_id VARCHAR(255) UNIQUE NOT NULL,
    target_name VARCHAR(50) NOT NULL,
    options_json TEXT,
    claim_token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
