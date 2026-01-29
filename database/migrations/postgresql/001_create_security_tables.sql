-- Security Shield Database Schema for PostgreSQL
-- Version: 1.0.0

-- Security Events Log
CREATE TABLE IF NOT EXISTS security_shield_events (
    id BIGSERIAL PRIMARY KEY,
    type VARCHAR(50) NOT NULL,
    ip VARCHAR(45) NOT NULL,
    data JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    -- Indexes for common queries
    CONSTRAINT security_shield_events_type_check CHECK (type <> '')
);

CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_shield_events(type);
CREATE INDEX IF NOT EXISTS idx_security_events_ip ON security_shield_events(ip);
CREATE INDEX IF NOT EXISTS idx_security_events_created ON security_shield_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_type_created ON security_shield_events(type, created_at DESC);

-- IP Bans Table
CREATE TABLE IF NOT EXISTS security_shield_bans (
    id BIGSERIAL PRIMARY KEY,
    ip VARCHAR(45) NOT NULL UNIQUE,
    reason TEXT,
    banned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    banned_by INTEGER DEFAULT NULL,

    CONSTRAINT security_shield_bans_ip_check CHECK (ip <> '')
);

CREATE INDEX IF NOT EXISTS idx_security_bans_expires ON security_shield_bans(expires_at);
CREATE INDEX IF NOT EXISTS idx_security_bans_ip ON security_shield_bans(ip);

-- IP Whitelist Table
CREATE TABLE IF NOT EXISTS security_shield_whitelist (
    id BIGSERIAL PRIMARY KEY,
    ip VARCHAR(45) NOT NULL UNIQUE,
    note TEXT,
    created_by INTEGER DEFAULT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT security_shield_whitelist_ip_check CHECK (ip <> '')
);

CREATE INDEX IF NOT EXISTS idx_security_whitelist_ip ON security_shield_whitelist(ip);

-- Configuration Table
CREATE TABLE IF NOT EXISTS security_shield_config (
    id BIGSERIAL PRIMARY KEY,
    key VARCHAR(100) NOT NULL UNIQUE,
    value JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT security_shield_config_key_check CHECK (key <> '')
);

CREATE INDEX IF NOT EXISTS idx_security_config_key ON security_shield_config(key);

-- IP Scores Table (for persistence when Redis unavailable)
CREATE TABLE IF NOT EXISTS security_shield_scores (
    id BIGSERIAL PRIMARY KEY,
    ip VARCHAR(45) NOT NULL UNIQUE,
    score INTEGER NOT NULL DEFAULT 0,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT security_shield_scores_ip_check CHECK (ip <> ''),
    CONSTRAINT security_shield_scores_score_check CHECK (score >= 0)
);

CREATE INDEX IF NOT EXISTS idx_security_scores_ip ON security_shield_scores(ip);
CREATE INDEX IF NOT EXISTS idx_security_scores_expires ON security_shield_scores(expires_at);

-- Request Counts Table (for rate limiting when Redis unavailable)
CREATE TABLE IF NOT EXISTS security_shield_request_counts (
    id BIGSERIAL PRIMARY KEY,
    ip VARCHAR(45) NOT NULL,
    action VARCHAR(50) NOT NULL DEFAULT 'general',
    count INTEGER NOT NULL DEFAULT 1,
    window_start TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT security_shield_request_counts_unique UNIQUE (ip, action, window_start)
);

CREATE INDEX IF NOT EXISTS idx_security_request_counts_ip ON security_shield_request_counts(ip, action);
CREATE INDEX IF NOT EXISTS idx_security_request_counts_expires ON security_shield_request_counts(expires_at);

-- Bot Verification Cache
CREATE TABLE IF NOT EXISTS security_shield_bot_cache (
    id BIGSERIAL PRIMARY KEY,
    ip VARCHAR(45) NOT NULL UNIQUE,
    is_legitimate BOOLEAN NOT NULL DEFAULT FALSE,
    metadata JSONB DEFAULT '{}',
    cached_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_security_bot_cache_ip ON security_shield_bot_cache(ip);
CREATE INDEX IF NOT EXISTS idx_security_bot_cache_expires ON security_shield_bot_cache(expires_at);

-- Insert default configuration
INSERT INTO security_shield_config (key, value) VALUES
    ('score_threshold', '50'),
    ('ban_duration', '86400'),
    ('rate_limit_max', '100'),
    ('rate_limit_window', '60'),
    ('honeypot_enabled', 'true'),
    ('bot_verification_enabled', 'true'),
    ('fail_closed', 'false')
ON CONFLICT (key) DO NOTHING;

-- Cleanup function for expired records
CREATE OR REPLACE FUNCTION security_shield_cleanup() RETURNS void AS $$
BEGIN
    DELETE FROM security_shield_bans WHERE expires_at < NOW();
    DELETE FROM security_shield_scores WHERE expires_at < NOW();
    DELETE FROM security_shield_request_counts WHERE expires_at < NOW();
    DELETE FROM security_shield_bot_cache WHERE expires_at < NOW();
    DELETE FROM security_shield_events WHERE created_at < NOW() - INTERVAL '90 days';
END;
$$ LANGUAGE plpgsql;

-- Optional: Create scheduled job for cleanup (requires pg_cron extension)
-- SELECT cron.schedule('security_shield_cleanup', '0 3 * * *', 'SELECT security_shield_cleanup()');
