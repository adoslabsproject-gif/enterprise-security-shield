<?php

require_once __DIR__ . '/../../vendor/autoload.php';

use Senza1dio\SecurityShield\Config\SecurityConfig;
use Senza1dio\SecurityShield\Middleware\WafMiddleware;
use Senza1dio\SecurityShield\Middleware\HoneypotMiddleware;
use Senza1dio\SecurityShield\Storage\RedisStorage;
use Senza1dio\SecurityShield\Storage\NullLogger;

/**
 * Advanced Pure PHP Example - Redis Storage (Production-Ready)
 *
 * This example shows a production-ready setup with Redis for persistence.
 * Includes custom configuration, IP whitelisting, and honeypot integration.
 */

// 1. Connect to Redis
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
// $redis->auth('your-redis-password'); // Uncomment if Redis requires auth

// 2. Create Redis storage
$storage = new RedisStorage($redis, 'myapp:security:');

// 3. Create logger (use Monolog in production)
$logger = new NullLogger(); // Replace with Monolog logger in production

// 4. Configure security with custom settings
$config = (new SecurityConfig())
    ->setStorage($storage)
    ->setLogger($logger)
    ->setScoreThreshold(50)            // Ban after 50 points
    ->setBanDuration(86400)            // 24 hours
    ->setTrackingWindow(3600)          // 1 hour tracking window
    ->setHoneypotBanDuration(604800)   // 7 days for honeypot access
    ->addIPWhitelist([
        '127.0.0.1',                   // Localhost
        '192.168.1.0/24',              // Private network
    ])
    ->addIPBlacklist([
        '1.2.3.4',                     // Known attacker
    ])
    ->enableBotVerification(true)      // DNS verification for bots
    ->enableIntelligence(true)         // Gather attack intelligence
    ->enableAlerts(false)              // Disable alerts (or set webhook)
    ->setEnvironment('production');

// 5. Create WAF middleware
$waf = new WafMiddleware($config);

// 6. Create Honeypot middleware with custom paths
$honeypotPaths = [
    '/.env',
    '/.git/config',
    '/phpinfo.php',
    '/wp-admin',
    '/admin.php',
    '/backup.sql',
    '/config.php',
    '/api/debug',
    '/swagger.json',
];
$honeypot = new HoneypotMiddleware($config, $honeypotPaths);

// 7. Check honeypot FIRST (before WAF)
$requestPath = $_SERVER['REQUEST_URI'] ?? '/';

if ($honeypot->isHoneypotPath($requestPath)) {
    // This will:
    // 1. Ban IP for 7 days
    // 2. Gather intelligence
    // 3. Log security event
    // 4. Send realistic fake response
    // 5. Exit
    $honeypot->handle($_SERVER, $_GET, $_POST);
    exit; // Never reached - middleware exits
}

// 8. Check WAF security rules
if (!$waf->handle($_SERVER, $_GET, $_POST)) {
    // Request blocked by WAF
    http_response_code(403);
    header('Content-Type: application/json');

    $response = [
        'error' => 'Access Denied',
        'reason' => $waf->getBlockReason(),
        'threat_score' => $waf->getThreatScore(),
        'timestamp' => time(),
    ];

    echo json_encode($response, JSON_PRETTY_PRINT);
    exit;
}

// 9. Request allowed - your application code here
header('Content-Type: application/json');

echo json_encode([
    'status' => 'success',
    'message' => 'Request passed all security checks',
    'timestamp' => time(),
], JSON_PRETTY_PRINT);

// 10. (Optional) Display statistics
if (isset($_GET['stats'])) {
    $botVerifier = $waf->getBotVerifier();
    $stats = $botVerifier->getStatistics();

    echo "\n\nBot Verification Statistics:\n";
    echo json_encode($stats, JSON_PRETTY_PRINT);
}
