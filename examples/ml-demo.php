<?php
/**
 * ML Threat Detection Demo
 *
 * Demonstrates the ML-based threat detection trained on real need2talk.it attack data.
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use AdosLabs\EnterpriseSecurityShield\ML\ThreatClassifier;
use AdosLabs\EnterpriseSecurityShield\ML\AnomalyDetector;
use AdosLabs\EnterpriseSecurityShield\ML\RequestAnalyzer;

echo "\n🛡️  Enterprise Security Shield - ML Demo\n";
echo "========================================\n\n";

// Initialize components
$classifier = new ThreatClassifier();
$anomalyDetector = new AnomalyDetector();
$analyzer = new RequestAnalyzer($classifier, $anomalyDetector);

// Show model stats
echo "📊 Model Statistics:\n";
$stats = $classifier->getModelStats();
foreach ($stats as $key => $value) {
    echo "  • {$key}: {$value}\n";
}
echo "\n";

// Test cases based on REAL attacks from need2talk.it logs
$testCases = [
    // REAL ATTACK: From 185.177.72.51 on 2026-01-22
    [
        'name' => 'Real Scanner (185.177.72.51 pattern)',
        'ip' => '185.177.72.51',
        'user_agent' => 'curl/8.7.1',
        'path' => '/admin/phpinfo.php',
    ],

    // REAL ATTACK: GPON exploit (seen multiple days)
    [
        'name' => 'GPON Router Exploit',
        'ip' => '122.97.212.147',
        'user_agent' => 'Hello, World',
        'path' => '/GponForm/diag_Form?images/',
    ],

    // REAL ATTACK: Fake Googlebot from 2026-01-24
    [
        'name' => 'Bot Spoofing (fake Googlebot)',
        'ip' => '34.126.179.187',
        'user_agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'path' => '/wordpress/',
    ],

    // REAL ATTACK: WordPress scanning
    [
        'name' => 'CMS Probe (WordPress)',
        'ip' => '45.94.31.58',
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'path' => '/wp-includes/wlwmanifest.xml',
    ],

    // REAL ATTACK: Credential hunting from 2026-01-22
    [
        'name' => 'Credential Theft (AWS)',
        'ip' => '185.177.72.51',
        'user_agent' => 'curl/8.7.1',
        'path' => '/admin/config?cmd=cat%20/root/.aws/credentials',
    ],

    // REAL ATTACK: Censys scanner
    [
        'name' => 'Known Scanner (Censys)',
        'ip' => '167.94.138.165',
        'user_agent' => 'Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)',
        'path' => '/',
    ],

    // LEGITIMATE: Normal Safari user
    [
        'name' => 'Legitimate User (Safari)',
        'ip' => '93.71.164.36',
        'user_agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.1 Safari/605.1.15',
        'path' => '/auth/login',
    ],

    // LEGITIMATE: Mobile user
    [
        'name' => 'Legitimate User (Mobile)',
        'ip' => '79.37.99.128',
        'user_agent' => 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36',
        'path' => '/',
    ],
];

echo "🧪 Running Tests:\n";
echo str_repeat("-", 80) . "\n\n";

foreach ($testCases as $test) {
    echo "▶ {$test['name']}\n";
    echo "  IP: {$test['ip']}\n";
    echo "  UA: " . substr($test['user_agent'], 0, 50) . "...\n";
    echo "  Path: {$test['path']}\n\n";

    // Quick classification
    $classification = $classifier->classify(
        $test['ip'],
        $test['user_agent'],
        $test['path']
    );

    echo "  📋 Classification: {$classification['classification']}\n";
    echo "  📊 Confidence: " . number_format($classification['confidence'] * 100, 1) . "%\n";
    echo "  ⚠️  Is Threat: " . ($classification['is_threat'] ? '✗ YES' : '✓ NO') . "\n";

    if (!empty($classification['features_detected'])) {
        echo "  🔍 Features: " . implode(', ', array_slice($classification['features_detected'], 0, 5)) . "\n";
    }

    echo "  💭 Reasoning: " . $classification['reasoning'] . "\n";

    // Full analysis
    $analysis = $analyzer->analyze([
        'ip' => $test['ip'],
        'user_agent' => $test['user_agent'],
        'path' => $test['path'],
        'request_count' => 1,
        'error_count' => 0,
    ]);

    echo "\n  🔒 Full Analysis:\n";
    echo "     Decision: {$analysis['decision']}\n";
    echo "     Score: {$analysis['score']}/100\n";
    echo "     Recommendation: " . substr($analysis['recommendation'], 0, 60) . "...\n";

    echo "\n" . str_repeat("-", 80) . "\n\n";
}

// Summary
echo "\n📈 Summary:\n";
echo "  • The ML model is trained on REAL attack data from need2talk.it\n";
echo "  • 662 security events analyzed (Dec 2025 - Jan 2026)\n";
echo "  • 407 confirmed attacks used for training\n";
echo "  • Detects: Scanners, Bot Spoofing, CMS Probes, Config Hunting, IoT Exploits\n\n";

echo "✅ Demo complete!\n\n";
