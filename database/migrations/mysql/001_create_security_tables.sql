-- Security Shield Database Schema for MySQL/MariaDB
-- Version: 1.0.0

-- Security Events Log
CREATE TABLE IF NOT EXISTS security_shield_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    type VARCHAR(50) NOT NULL,
    ip VARCHAR(45) NOT NULL,
    data JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_type (type),
    INDEX idx_ip (ip),
    INDEX idx_created (created_at DESC),
    INDEX idx_type_created (type, created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- IP Bans Table
CREATE TABLE IF NOT EXISTS security_shield_bans (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(45) NOT NULL,
    reason TEXT,
    banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    banned_by INT UNSIGNED DEFAULT NULL,

    UNIQUE KEY uk_ip (ip),
    INDEX idx_expires (expires_at),
    INDEX idx_ip (ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- IP Whitelist Table
CREATE TABLE IF NOT EXISTS security_shield_whitelist (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(45) NOT NULL,
    note TEXT,
    created_by INT UNSIGNED DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uk_ip (ip),
    INDEX idx_ip (ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Configuration Table
CREATE TABLE IF NOT EXISTS security_shield_config (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `key` VARCHAR(100) NOT NULL,
    `value` JSON NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY uk_key (`key`),
    INDEX idx_key (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- IP Scores Table (for persistence when Redis unavailable)
CREATE TABLE IF NOT EXISTS security_shield_scores (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(45) NOT NULL,
    score INT UNSIGNED NOT NULL DEFAULT 0,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,

    UNIQUE KEY uk_ip (ip),
    INDEX idx_ip (ip),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Request Counts Table (for rate limiting when Redis unavailable)
CREATE TABLE IF NOT EXISTS security_shield_request_counts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(45) NOT NULL,
    action VARCHAR(50) NOT NULL DEFAULT 'general',
    count INT UNSIGNED NOT NULL DEFAULT 1,
    window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,

    UNIQUE KEY uk_ip_action_window (ip, action, window_start),
    INDEX idx_ip_action (ip, action),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Bot Verification Cache
CREATE TABLE IF NOT EXISTS security_shield_bot_cache (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(45) NOT NULL,
    is_legitimate TINYINT(1) NOT NULL DEFAULT 0,
    metadata JSON,
    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,

    UNIQUE KEY uk_ip (ip),
    INDEX idx_ip (ip),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert default configuration
INSERT IGNORE INTO security_shield_config (`key`, `value`) VALUES
    ('score_threshold', '50'),
    ('ban_duration', '86400'),
    ('rate_limit_max', '100'),
    ('rate_limit_window', '60'),
    ('honeypot_enabled', '"true"'),
    ('bot_verification_enabled', '"true"'),
    ('fail_closed', '"false"');

-- Cleanup event for expired records (requires EVENT scheduler enabled)
DELIMITER //

CREATE EVENT IF NOT EXISTS security_shield_cleanup_event
ON SCHEDULE EVERY 1 HOUR
DO
BEGIN
    DELETE FROM security_shield_bans WHERE expires_at < NOW();
    DELETE FROM security_shield_scores WHERE expires_at < NOW();
    DELETE FROM security_shield_request_counts WHERE expires_at < NOW();
    DELETE FROM security_shield_bot_cache WHERE expires_at < NOW();
    DELETE FROM security_shield_events WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY);
END//

DELIMITER ;
