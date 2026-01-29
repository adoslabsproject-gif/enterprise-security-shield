<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Core;

use AdosLabs\EnterpriseSecurityShield\Bot\BotVerificationService;
use AdosLabs\EnterpriseSecurityShield\Config\SecurityConfig;
use AdosLabs\EnterpriseSecurityShield\Contracts\StorageInterface;
use AdosLabs\EnterpriseSecurityShield\Detection\SQLiDetector;
use AdosLabs\EnterpriseSecurityShield\Detection\XSSDetector;
use AdosLabs\EnterpriseSecurityShield\GeoIP\GeoIPService;
use AdosLabs\EnterpriseSecurityShield\ML\AnomalyDetector;
use AdosLabs\EnterpriseSecurityShield\ML\OnlineLearningClassifier;
use AdosLabs\EnterpriseSecurityShield\ML\RequestAnalyzer;
use AdosLabs\EnterpriseSecurityShield\ML\ThreatClassifier;
use AdosLabs\EnterpriseSecurityShield\RateLimiting\RateLimiter;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Security Shield - Enterprise WAF Core.
 *
 * Unified entry point for all security functionality.
 * Coordinates all security components for comprehensive request protection.
 *
 * SECURITY LAYERS:
 * 1. IP Reputation (whitelist/blacklist/ban check)
 * 2. Bot Verification (legitimate bots vs spoofed)
 * 3. Rate Limiting (per IP, per route, global)
 * 4. GeoIP Blocking (country/ASN restrictions)
 * 5. ML Threat Classification (trained on real attacks)
 * 6. Payload Analysis (SQLi, XSS detection)
 * 7. Honeypot Detection (scanner traps)
 * 8. Anomaly Detection (behavioral analysis)
 *
 * @version 1.0.0
 */
final class SecurityShield
{
    private StorageInterface $storage;

    private SecurityConfig $config;

    private LoggerInterface $logger;

    // Components (lazy loaded)
    private ?ThreatClassifier $threatClassifier = null;

    private ?OnlineLearningClassifier $onlineLearner = null;

    private ?AnomalyDetector $anomalyDetector = null;

    private ?RequestAnalyzer $requestAnalyzer = null;

    private ?BotVerificationService $botVerifier = null;

    private ?GeoIPService $geoIP = null;

    private ?SQLiDetector $sqliDetector = null;

    private ?XSSDetector $xssDetector = null;

    private ?RateLimiter $rateLimiter = null;

    // ML configuration
    private bool $onlineLearningEnabled = true;

    // Statistics
    private array $stats = [
        'requests_analyzed' => 0,
        'threats_blocked' => 0,
        'bots_verified' => 0,
        'bots_spoofed' => 0,
        'rate_limited' => 0,
    ];

    public function __construct(
        StorageInterface $storage,
        ?SecurityConfig $config = null,
        ?LoggerInterface $logger = null,
    ) {
        $this->storage = $storage;
        $this->config = $config ?? new SecurityConfig();
        $this->logger = $logger ?? new NullLogger();
    }

    /**
     * Analyze a request and return security decision.
     *
     * @return array{
     *     allowed: bool,
     *     action: string,
     *     score: int,
     *     reasons: array<string>,
     *     bot: array|null,
     *     geo: array|null,
     *     threats: array,
     *     rate_limit: array|null,
     *     recommendation: string
     * }
     */
    public function analyze(
        string $ip,
        string $userAgent,
        string $path,
        string $method = 'GET',
        array $headers = [],
        ?string $queryString = null,
        ?string $body = null,
    ): array {
        $this->stats['requests_analyzed']++;

        $reasons = [];
        $threats = [];
        $totalScore = 0;
        $action = 'ALLOW';

        // === LAYER 1: IP Reputation ===
        $ipCheck = $this->checkIPReputation($ip);
        if ($ipCheck['blocked']) {
            $this->stats['threats_blocked']++;

            return $this->buildResponse(
                false,
                'BLOCK',
                100,
                [$ipCheck['reason']],
                null,
                null,
                [],
                null,
                'Request blocked: ' . $ipCheck['reason'],
            );
        }
        if ($ipCheck['whitelisted']) {
            return $this->buildResponse(
                true,
                'ALLOW',
                0,
                ['IP whitelisted'],
                null,
                null,
                [],
                null,
                'IP is whitelisted - bypassing all checks',
            );
        }

        // === LAYER 2: Bot Verification ===
        $botResult = null;
        if ($this->config->get('bot_verification_enabled', true)) {
            $botResult = $this->getBotVerifier()->verify($ip, $userAgent);

            if ($botResult['is_bot']) {
                if ($botResult['is_verified']) {
                    $this->stats['bots_verified']++;
                    // Verified bot - apply bot-specific rules
                    $reasons[] = sprintf('Verified %s bot', $botResult['bot_name']);
                } else {
                    // Spoofed bot!
                    $this->stats['bots_spoofed']++;
                    $totalScore += 80;
                    $reasons[] = sprintf('SPOOFED %s bot detected', $botResult['bot_name']);
                    $threats[] = [
                        'type' => 'bot_spoofing',
                        'severity' => 'HIGH',
                        'details' => $botResult['details'],
                    ];
                }
            }
        }

        // === LAYER 3: Rate Limiting ===
        $rateLimitResult = null;
        if ($this->config->get('rate_limiting_enabled', true)) {
            $rateLimitResult = $this->checkRateLimit($ip, $path);
            if (!$rateLimitResult['allowed']) {
                $this->stats['rate_limited']++;
                $totalScore += 40;
                $reasons[] = 'Rate limit exceeded';
                if ($rateLimitResult['remaining'] <= 0) {
                    return $this->buildResponse(
                        false,
                        'RATE_LIMIT',
                        $totalScore,
                        $reasons,
                        $botResult,
                        null,
                        $threats,
                        $rateLimitResult,
                        'Rate limit exceeded. Retry after ' . $rateLimitResult['retry_after'] . ' seconds',
                    );
                }
            }
        }

        // === LAYER 4: GeoIP Blocking ===
        $geoResult = null;
        if ($this->config->get('geoip_enabled', true)) {
            $geoResult = $this->getGeoIP()->lookup($ip);
            if ($geoResult['is_blocked']) {
                $this->stats['threats_blocked']++;
                $reasons[] = $geoResult['block_reason'];

                return $this->buildResponse(
                    false,
                    'BLOCK',
                    100,
                    $reasons,
                    $botResult,
                    $geoResult,
                    $threats,
                    $rateLimitResult,
                    'Request blocked: ' . $geoResult['block_reason'],
                );
            }
            // Add geo risk to score
            $totalScore += $geoResult['risk_score'];
        }

        // === LAYER 5: Payload Analysis (SQLi, XSS) - BEFORE ML for feature extraction ===
        $payloadsToCheck = array_filter([$queryString, $body], fn ($v) => !empty($v));
        $sqliDetected = false;
        $xssDetected = false;

        foreach ($payloadsToCheck as $payload) {
            // SQLi Detection
            if ($this->config->get('sqli_detection_enabled', true)) {
                $sqliResult = $this->getSQLiDetector()->detect($payload);
                if ($sqliResult['detected']) {
                    $sqliDetected = true;
                    $totalScore += min(50, $sqliResult['confidence']);
                    $reasons[] = sprintf('SQL injection detected (%.0f%% confidence)', $sqliResult['confidence']);
                    $threats[] = [
                        'type' => 'sqli',
                        'confidence' => $sqliResult['confidence'],
                        'fingerprint' => $sqliResult['fingerprint'] ?? null,
                        'severity' => $sqliResult['confidence'] >= 80 ? 'CRITICAL' : 'HIGH',
                    ];
                }
            }

            // XSS Detection
            if ($this->config->get('xss_detection_enabled', true)) {
                $xssResult = $this->getXSSDetector()->detect($payload);
                if ($xssResult['detected']) {
                    $xssDetected = true;
                    $totalScore += min(40, $xssResult['confidence']);
                    $reasons[] = sprintf('XSS detected (%.0f%% confidence)', $xssResult['confidence']);
                    $threats[] = [
                        'type' => 'xss',
                        'confidence' => $xssResult['confidence'],
                        'vectors' => $xssResult['vectors'],
                        'severity' => $xssResult['confidence'] >= 80 ? 'HIGH' : 'MEDIUM',
                    ];
                }
            }
        }

        // === LAYER 6: Honeypot Check ===
        $honeypotHit = false;
        if ($this->config->get('honeypot_enabled', true)) {
            $honeypotPaths = $this->config->get('honeypot_paths', [
                '/.env', '/.git/config', '/wp-config.php', '/phpinfo.php',
                '/admin/config.php', '/.aws/credentials', '/server-status',
            ]);

            foreach ($honeypotPaths as $honeypot) {
                if (str_contains(strtolower($path), strtolower($honeypot))) {
                    $honeypotHit = true;
                    $totalScore += 60;
                    $reasons[] = 'Honeypot path accessed: ' . $path;
                    $threats[] = [
                        'type' => 'honeypot',
                        'path' => $path,
                        'severity' => 'HIGH',
                    ];
                    break;
                }
            }
        }

        // === LAYER 7: ML Threat Classification (DUAL-ENGINE) ===
        // Now with REAL detection results from Layers 5-6
        $mlResult = null;
        $onlineResult = null;
        if ($this->config->get('ml_enabled', true)) {
            // 7A: Static ML Analyzer (trained on 662 events)
            $mlResult = $this->getRequestAnalyzer()->analyze([
                'ip' => $ip,
                'user_agent' => $userAgent,
                'path' => $path,
                'method' => $method,
                'headers' => $headers,
                'query_string' => $queryString ?? '',
                'body' => $body ?? '',
            ]);

            $totalScore += (int) ($mlResult['score'] * 0.35); // Static ML weight: 35%

            if ($mlResult['classification']['is_threat']) {
                $reasons[] = $mlResult['classification']['reasoning'];
                $threats[] = [
                    'type' => 'ml_classification',
                    'classification' => $mlResult['classification']['classification'],
                    'confidence' => $mlResult['classification']['confidence'],
                    'severity' => $mlResult['score'] >= 70 ? 'HIGH' : 'MEDIUM',
                ];
            }

            // 7B: Online Learning ML Classifier (TRUE ML with REAL features)
            $onlineLearner = $this->getOnlineLearner();
            $onlineResult = $onlineLearner->classify([
                'ip' => $ip,
                'user_agent' => $userAgent,
                'path' => $path,
                'request_count' => $this->getRequestCount($ip),
                'error_404_count' => $this->getIPMetrics($ip)['error_count'] ?? 0,
                'rate_limited' => $rateLimitResult !== null && !$rateLimitResult['allowed'],
                'honeypot_hit' => $honeypotHit,
                'sqli_detected' => $sqliDetected,
                'xss_detected' => $xssDetected,
            ]);

            // Online Learning ML weight: 25% (increases model maturity)
            if ($onlineResult['is_threat']) {
                $onlineScore = (int) ($onlineResult['confidence'] * 25);
                $totalScore += $onlineScore;
                $reasons[] = 'Online ML: ' . $onlineResult['classification'] . ' (confidence: ' . round($onlineResult['confidence'] * 100) . '%)';
                $threats[] = [
                    'type' => 'online_ml_classification',
                    'classification' => $onlineResult['classification'],
                    'confidence' => $onlineResult['confidence'],
                    'learning_status' => $onlineResult['learning_status'],
                    'total_samples' => $onlineResult['total_samples_learned'],
                    'severity' => $onlineResult['confidence'] >= 0.8 ? 'HIGH' : 'MEDIUM',
                ];
            }
        }

        // === LAYER 8: Anomaly Detection ===
        if ($this->config->get('anomaly_detection_enabled', true)) {
            $ipMetrics = $this->getIPMetrics($ip);
            $anomalyResult = $this->getAnomalyDetector()->analyze(
                $ip,
                $path,
                $ipMetrics['request_count'],
                $ipMetrics['error_count'],
            );

            if ($anomalyResult['is_anomaly']) {
                $totalScore += (int) ($anomalyResult['anomaly_score'] * 0.4);
                $reasons = array_merge($reasons, $anomalyResult['risk_factors']);
                foreach ($anomalyResult['anomalies'] as $anomaly) {
                    $threats[] = [
                        'type' => 'anomaly',
                        'metric' => $anomaly['metric'],
                        'severity' => $anomaly['severity'],
                    ];
                }
            }
        }

        // === Final Decision ===
        $totalScore = min(100, $totalScore);
        $action = $this->determineAction($totalScore);

        // Update IP score in storage
        if ($totalScore > 0) {
            $this->updateIPScore($ip, $totalScore, $reasons);
        }

        // Track metrics
        $this->trackRequest($ip, $path, $totalScore, $action);

        if ($action === 'BLOCK' || $action === 'BAN') {
            $this->stats['threats_blocked']++;
        }

        $recommendation = $this->buildRecommendation($action, $totalScore, $reasons);

        return $this->buildResponse(
            $action === 'ALLOW' || $action === 'MONITOR',
            $action,
            $totalScore,
            $reasons,
            $botResult,
            $geoResult,
            $threats,
            $rateLimitResult,
            $recommendation,
        );
    }

    /**
     * Quick check if IP should be blocked (for early blocking).
     */
    public function shouldBlock(string $ip): bool
    {
        $ipCheck = $this->checkIPReputation($ip);

        return $ipCheck['blocked'];
    }

    /**
     * Ban an IP.
     */
    public function banIP(string $ip, int $duration = 86400, string $reason = 'Manual ban'): bool
    {
        $this->storage->set("security:banned:{$ip}", [
            'reason' => $reason,
            'banned_at' => time(),
            'expires_at' => time() + $duration,
        ], $duration);

        $this->logger->warning('IP banned', [
            'ip' => $ip,
            'duration' => $duration,
            'reason' => $reason,
        ]);

        return true;
    }

    /**
     * Unban an IP.
     */
    public function unbanIP(string $ip): bool
    {
        $this->storage->delete("security:banned:{$ip}");

        $this->logger->info('IP unbanned', ['ip' => $ip]);

        return true;
    }

    /**
     * Whitelist an IP.
     */
    public function whitelistIP(string $ip): bool
    {
        $this->storage->set("security:whitelist:{$ip}", [
            'added_at' => time(),
        ], 0); // No expiration

        return true;
    }

    /**
     * Remove from whitelist.
     */
    public function removeFromWhitelist(string $ip): bool
    {
        $this->storage->delete("security:whitelist:{$ip}");

        return true;
    }

    /**
     * Get IP score.
     */
    public function getIPScore(string $ip): int
    {
        $data = $this->storage->get("security:score:{$ip}");

        return $data['score'] ?? 0;
    }

    /**
     * Get banned IPs.
     */
    public function getBannedIPs(int $limit = 100): array
    {
        // Implementation depends on storage backend capabilities
        // This is a simplified version
        return [];
    }

    /**
     * Get statistics.
     */
    public function getStats(): array
    {
        return $this->stats;
    }

    /**
     * Get component instances (for testing/advanced use).
     */
    public function getThreatClassifier(): ThreatClassifier
    {
        return $this->threatClassifier ??= new ThreatClassifier();
    }

    public function getBotVerifier(): BotVerificationService
    {
        return $this->botVerifier ??= new BotVerificationService();
    }

    public function getGeoIP(): GeoIPService
    {
        return $this->geoIP ??= new GeoIPService();
    }

    public function getSQLiDetector(): SQLiDetector
    {
        return $this->sqliDetector ??= new SQLiDetector();
    }

    public function getXSSDetector(): XSSDetector
    {
        return $this->xssDetector ??= new XSSDetector();
    }

    public function getAnomalyDetector(): AnomalyDetector
    {
        return $this->anomalyDetector ??= new AnomalyDetector();
    }

    public function getRequestAnalyzer(): RequestAnalyzer
    {
        if ($this->requestAnalyzer === null) {
            $this->requestAnalyzer = new RequestAnalyzer(
                $this->getThreatClassifier(),
                $this->getAnomalyDetector(),
            );
        }

        return $this->requestAnalyzer;
    }

    /**
     * Get Online Learning Classifier (TRUE ML with continuous learning).
     */
    public function getOnlineLearner(): OnlineLearningClassifier
    {
        return $this->onlineLearner ??= new OnlineLearningClassifier($this->storage, $this->logger);
    }

    /**
     * Enable or disable online learning.
     */
    public function setOnlineLearningEnabled(bool $enabled): self
    {
        $this->onlineLearningEnabled = $enabled;

        return $this;
    }

    /**
     * Train the online learning model from historical security events.
     *
     * @param int $limit Maximum events to learn from
     *
     * @return int Number of events learned from
     */
    public function trainFromHistoricalEvents(int $limit = 1000): int
    {
        $learned = $this->getOnlineLearner()->autoLearnFromEvents($limit);

        $this->logger->info('SecurityShield: ML model trained from historical events', [
            'events_learned' => $learned,
            'stats' => $this->getOnlineLearner()->getStats(),
        ]);

        return $learned;
    }

    /**
     * Get ML model statistics.
     */
    public function getMLStats(): array
    {
        return [
            'static_classifier' => $this->getThreatClassifier()->getModelStats(),
            'online_learner' => $this->getOnlineLearner()->getStats(),
        ];
    }

    // === Private Methods ===

    private function checkIPReputation(string $ip): array
    {
        // Check whitelist
        if ($this->storage->get("security:whitelist:{$ip}") !== null) {
            return ['blocked' => false, 'whitelisted' => true, 'reason' => null];
        }

        // Check ban list
        $banData = $this->storage->get("security:banned:{$ip}");
        if ($banData !== null) {
            if (isset($banData['expires_at']) && $banData['expires_at'] < time()) {
                // Ban expired
                $this->storage->delete("security:banned:{$ip}");
            } else {
                return [
                    'blocked' => true,
                    'whitelisted' => false,
                    'reason' => $banData['reason'] ?? 'IP is banned',
                ];
            }
        }

        // Check IP score threshold
        $scoreData = $this->storage->get("security:score:{$ip}");
        $threshold = $this->config->get('score_threshold', 100);
        if ($scoreData !== null && ($scoreData['score'] ?? 0) >= $threshold) {
            return [
                'blocked' => true,
                'whitelisted' => false,
                'reason' => 'IP score exceeded threshold',
            ];
        }

        return ['blocked' => false, 'whitelisted' => false, 'reason' => null];
    }

    private function checkRateLimit(string $ip, string $path): array
    {
        if ($this->rateLimiter === null) {
            $maxRequests = $this->config->get('rate_limit_max', 100);
            $windowSeconds = $this->config->get('rate_limit_window', 60);
            $this->rateLimiter = RateLimiter::slidingWindow(
                $this->storage,
                $maxRequests,
                $windowSeconds,
            );
        }

        $result = $this->rateLimiter->attempt("ip:{$ip}");

        return [
            'allowed' => $result->allowed,
            'remaining' => $result->remaining,
            'retry_after' => $result->retryAfter,
        ];
    }

    private function getIPMetrics(string $ip): array
    {
        $data = $this->storage->get("security:metrics:{$ip}");

        return [
            'request_count' => $data['requests'] ?? 1,
            'error_count' => $data['errors'] ?? 0,
        ];
    }

    private function updateIPScore(string $ip, int $score, array $reasons): void
    {
        $key = "security:score:{$ip}";
        $current = $this->storage->get($key) ?? ['score' => 0, 'reasons' => []];

        $newScore = min(1000, ($current['score'] ?? 0) + $score);

        $this->storage->set($key, [
            'score' => $newScore,
            'reasons' => array_merge($current['reasons'] ?? [], $reasons),
            'updated_at' => time(),
        ], 86400 * 7); // Keep for 7 days

        // Auto-ban if threshold exceeded
        $threshold = $this->config->get('score_threshold', 100);
        if ($newScore >= $threshold) {
            $this->banIP($ip, $this->config->get('ban_duration', 86400), 'Auto-ban: Score threshold exceeded');

            // Feed online ML classifier with this confirmed threat
            $this->learnFromSecurityEvent('auto_ban', $ip, [
                'reasons' => $reasons,
            ]);
        }
    }

    private function trackRequest(string $ip, string $path, int $score, string $action): void
    {
        $key = "security:metrics:{$ip}";
        $data = $this->storage->get($key) ?? ['requests' => 0, 'errors' => 0];

        $data['requests'] = ($data['requests'] ?? 0) + 1;
        $data['last_seen'] = time();
        $data['last_path'] = $path;

        if ($action !== 'ALLOW') {
            $data['errors'] = ($data['errors'] ?? 0) + 1;
        }

        $this->storage->set($key, $data, 3600);
    }

    private function getRequestCount(string $ip): int
    {
        $data = $this->storage->get("security:metrics:{$ip}");

        return $data['requests'] ?? 1;
    }

    /**
     * Learn from a security event (feeds online ML classifier).
     */
    private function learnFromSecurityEvent(string $eventType, string $ip, array $data): void
    {
        if (!$this->onlineLearningEnabled) {
            return;
        }

        $classMapping = [
            'auto_ban' => OnlineLearningClassifier::CLASS_SCANNER,
            'bot_spoofing' => OnlineLearningClassifier::CLASS_BOT_SPOOF,
            'sqli_detected' => OnlineLearningClassifier::CLASS_SQLI_ATTEMPT,
            'xss_detected' => OnlineLearningClassifier::CLASS_XSS_ATTEMPT,
            'honeypot_access' => OnlineLearningClassifier::CLASS_SCANNER,
            'brute_force' => OnlineLearningClassifier::CLASS_BRUTE_FORCE,
            'path_traversal' => OnlineLearningClassifier::CLASS_PATH_TRAVERSAL,
            'config_hunt' => OnlineLearningClassifier::CLASS_CONFIG_HUNT,
        ];

        $class = $classMapping[$eventType] ?? null;
        if ($class === null) {
            return;
        }

        $features = [
            'user_agent' => $data['user_agent'] ?? '',
            'path' => $data['path'] ?? '',
            'request_count' => $data['request_count'] ?? 0,
            'sqli_detected' => str_contains($eventType, 'sqli'),
            'xss_detected' => str_contains($eventType, 'xss'),
            'honeypot_hit' => str_contains($eventType, 'honeypot'),
        ];

        $weight = in_array($eventType, ['auto_ban', 'sqli_detected', 'xss_detected']) ? 1.0 : 0.8;

        $this->getOnlineLearner()->learn($features, $class, $weight);

        $this->logger->debug('SecurityShield: Online ML learned from event', [
            'event_type' => $eventType,
            'class' => $class,
            'ip' => $ip,
        ]);
    }

    private function determineAction(int $score): string
    {
        if ($score >= $this->config->get('ban_threshold', 90)) {
            return 'BAN';
        }
        if ($score >= $this->config->get('block_threshold', 70)) {
            return 'BLOCK';
        }
        if ($score >= $this->config->get('rate_limit_threshold', 55)) {
            return 'RATE_LIMIT';
        }
        if ($score >= $this->config->get('challenge_threshold', 40)) {
            return 'CHALLENGE';
        }
        if ($score >= $this->config->get('monitor_threshold', 20)) {
            return 'MONITOR';
        }

        return 'ALLOW';
    }

    private function buildRecommendation(string $action, int $score, array $reasons): string
    {
        $messages = [
            'ALLOW' => 'Request allowed.',
            'MONITOR' => 'Request allowed but logged for analysis.',
            'CHALLENGE' => 'Consider presenting CAPTCHA verification.',
            'RATE_LIMIT' => 'Apply rate limiting to this IP.',
            'BLOCK' => 'Block this request.',
            'BAN' => 'Ban this IP immediately.',
        ];

        $base = $messages[$action] ?? 'Unknown action.';

        if (!empty($reasons)) {
            $base .= ' Reasons: ' . implode('; ', array_slice($reasons, 0, 3));
        }

        return $base;
    }

    private function buildResponse(
        bool $allowed,
        string $action,
        int $score,
        array $reasons,
        ?array $bot,
        ?array $geo,
        array $threats,
        ?array $rateLimit,
        string $recommendation,
    ): array {
        return [
            'allowed' => $allowed,
            'action' => $action,
            'score' => $score,
            'reasons' => $reasons,
            'bot' => $bot,
            'geo' => $geo,
            'threats' => $threats,
            'rate_limit' => $rateLimit,
            'recommendation' => $recommendation,
        ];
    }
}
