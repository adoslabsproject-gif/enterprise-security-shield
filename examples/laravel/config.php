<?php

/**
 * Laravel Configuration Example
 *
 * Save this as: config/security-shield.php
 */

return [
    /*
    |--------------------------------------------------------------------------
    | Threat Score Threshold
    |--------------------------------------------------------------------------
    |
    | IP addresses exceeding this score will be automatically banned.
    | Recommended: 50 (default)
    |
    */
    'score_threshold' => env('SECURITY_SCORE_THRESHOLD', 50),

    /*
    |--------------------------------------------------------------------------
    | Ban Duration
    |--------------------------------------------------------------------------
    |
    | How long to ban IPs that exceed the threshold (in seconds).
    | Default: 86400 (24 hours)
    |
    */
    'ban_duration' => env('SECURITY_BAN_DURATION', 86400),

    /*
    |--------------------------------------------------------------------------
    | Tracking Window
    |--------------------------------------------------------------------------
    |
    | Time window for accumulating threat scores (in seconds).
    | Default: 3600 (1 hour)
    |
    */
    'tracking_window' => env('SECURITY_TRACKING_WINDOW', 3600),

    /*
    |--------------------------------------------------------------------------
    | Honeypot Ban Duration
    |--------------------------------------------------------------------------
    |
    | How long to ban IPs that access honeypot endpoints (in seconds).
    | Default: 604800 (7 days)
    |
    */
    'honeypot_ban_duration' => env('SECURITY_HONEYPOT_BAN', 604800),

    /*
    |--------------------------------------------------------------------------
    | Honeypot Endpoints
    |--------------------------------------------------------------------------
    |
    | List of trap endpoints that will trigger instant bans.
    |
    */
    'honeypot_paths' => [
        '/.env',
        '/.git/config',
        '/phpinfo.php',
        '/wp-admin',
        '/admin.php',
        '/backup.sql',
        '/config.php',
        '/api/debug',
        '/swagger.json',
    ],

    /*
    |--------------------------------------------------------------------------
    | IP Whitelist
    |--------------------------------------------------------------------------
    |
    | IPs that should never be banned (supports CIDR notation).
    |
    */
    'ip_whitelist' => [
        '127.0.0.1',
        // env('OFFICE_IP'), // Your office IP
    ],

    /*
    |--------------------------------------------------------------------------
    | IP Blacklist
    |--------------------------------------------------------------------------
    |
    | IPs that should always be blocked.
    |
    */
    'ip_blacklist' => [
        // '1.2.3.4',
    ],

    /*
    |--------------------------------------------------------------------------
    | Bot Verification
    |--------------------------------------------------------------------------
    |
    | Enable DNS-based verification for legitimate bots (Google, Bing, etc.).
    |
    */
    'bot_verification_enabled' => env('SECURITY_BOT_VERIFICATION', true),

    /*
    |--------------------------------------------------------------------------
    | Bot Verification Cache TTL
    |--------------------------------------------------------------------------
    |
    | How long to cache bot verification results (in seconds).
    | Default: 604800 (7 days)
    |
    */
    'bot_cache_ttl' => env('SECURITY_BOT_CACHE_TTL', 604800),

    /*
    |--------------------------------------------------------------------------
    | Honeypot Enabled
    |--------------------------------------------------------------------------
    |
    | Enable or disable honeypot trap endpoints.
    |
    */
    'honeypot_enabled' => env('SECURITY_HONEYPOT_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Intelligence Gathering
    |--------------------------------------------------------------------------
    |
    | Collect attack intelligence (fingerprinting, scanner identification).
    |
    */
    'intelligence_enabled' => env('SECURITY_INTELLIGENCE', true),

    /*
    |--------------------------------------------------------------------------
    | Critical Alerts
    |--------------------------------------------------------------------------
    |
    | Send alerts for critical security events (honeypot access, etc.).
    |
    */
    'alerts_enabled' => env('SECURITY_ALERTS_ENABLED', false),

    /*
    |--------------------------------------------------------------------------
    | Alert Webhook
    |--------------------------------------------------------------------------
    |
    | Webhook URL for critical security alerts (Slack, Discord, etc.).
    |
    */
    'alert_webhook' => env('SECURITY_ALERT_WEBHOOK'),

    /*
    |--------------------------------------------------------------------------
    | Environment
    |--------------------------------------------------------------------------
    |
    | Current environment (production, staging, development).
    |
    */
    'environment' => env('APP_ENV', 'production'),

    /*
    |--------------------------------------------------------------------------
    | Storage Backend
    |--------------------------------------------------------------------------
    |
    | Configure the storage backend for security data.
    | Options: 'redis', 'database', 'memory'
    |
    */
    'storage' => env('SECURITY_STORAGE', 'redis'),

    /*
    |--------------------------------------------------------------------------
    | Redis Connection
    |--------------------------------------------------------------------------
    |
    | Redis connection name from config/database.php.
    | Only used if storage is 'redis'.
    |
    */
    'redis_connection' => env('SECURITY_REDIS_CONNECTION', 'default'),

    /*
    |--------------------------------------------------------------------------
    | Redis Key Prefix
    |--------------------------------------------------------------------------
    |
    | Prefix for all Redis keys used by SecurityShield.
    |
    */
    'redis_key_prefix' => env('SECURITY_REDIS_PREFIX', 'security_shield:'),
];
