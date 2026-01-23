<?php

require_once __DIR__ . '/../../vendor/autoload.php';

use Senza1dio\SecurityShield\Config\SecurityConfig;
use Senza1dio\SecurityShield\Middleware\WafMiddleware;
use Senza1dio\SecurityShield\Middleware\HoneypotMiddleware;
use Senza1dio\SecurityShield\Storage\NullStorage;
use Senza1dio\SecurityShield\Storage\NullLogger;

/**
 * Basic Pure PHP Example - Zero Dependencies
 *
 * This example shows the absolute minimum code needed to protect your application.
 * Uses NullStorage (in-memory) - suitable for development/testing only.
 * For production, use RedisStorage (see advanced-redis.php).
 */

// 1. Create configuration (zero-config defaults)
$config = new SecurityConfig();
$config->setStorage(new NullStorage());
$config->setLogger(new NullLogger());

// 2. Create WAF middleware
$waf = new WafMiddleware($config);

// 3. Check request BEFORE any application logic
if (!$waf->handle($_SERVER, $_GET, $_POST)) {
    // Request blocked - send 403 response
    http_response_code(403);
    header('Content-Type: text/plain');

    $reason = $waf->getBlockReason();
    $score = $waf->getThreatScore();

    echo "Access Denied\n";
    echo "Reason: {$reason}\n";
    echo "Threat Score: {$score}\n";
    exit;
}

// 4. (Optional) Check honeypot paths
$honeypot = new HoneypotMiddleware($config);

if ($honeypot->isHoneypotPath($_SERVER['REQUEST_URI'] ?? '/')) {
    // This will ban the IP and exit with fake response
    $honeypot->handle($_SERVER, $_GET, $_POST);
    exit; // Never reached
}

// 5. Your application code starts here
echo "Welcome! Your request passed security checks.\n";
echo "You are using a legitimate browser and not a vulnerability scanner.\n";
