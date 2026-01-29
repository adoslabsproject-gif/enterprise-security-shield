<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\ML;

use AdosLabs\EnterpriseSecurityShield\Detection\SQLiDetector;
use AdosLabs\EnterpriseSecurityShield\Detection\XSSDetector;

/**
 * Unified Request Analyzer.
 *
 * Combines all ML and detection components for comprehensive request analysis.
 * This is the main entry point for the ML-based threat detection system.
 *
 * ANALYSIS PIPELINE:
 * 1. Feature extraction
 * 2. Threat classification (ThreatClassifier)
 * 3. Anomaly detection (AnomalyDetector)
 * 4. SQLi detection (SQLiDetector)
 * 5. XSS detection (XSSDetector)
 * 6. Score aggregation & decision
 *
 * DECISION OUTCOMES:
 * - ALLOW: Request is safe
 * - MONITOR: Log and watch
 * - CHALLENGE: Require CAPTCHA/verification
 * - RATE_LIMIT: Apply rate limiting
 * - BLOCK: Block the request
 * - BAN: Ban the IP
 *
 * @version 1.0.0
 */
final class RequestAnalyzer
{
    private ThreatClassifier $threatClassifier;

    private AnomalyDetector $anomalyDetector;

    private ?SQLiDetector $sqliDetector = null;

    private ?XSSDetector $xssDetector = null;

    /**
     * Score thresholds for decisions.
     */
    private int $monitorThreshold = 20;

    private int $challengeThreshold = 40;

    private int $rateLimitThreshold = 55;

    private int $blockThreshold = 70;

    private int $banThreshold = 85;

    /**
     * Weight factors for different analyzers.
     */
    private const ANALYZER_WEIGHTS = [
        'threat_classifier' => 0.35,
        'anomaly_detector' => 0.25,
        'sqli_detector' => 0.20,
        'xss_detector' => 0.20,
    ];

    public function __construct(
        ?ThreatClassifier $threatClassifier = null,
        ?AnomalyDetector $anomalyDetector = null,
    ) {
        $this->threatClassifier = $threatClassifier ?? new ThreatClassifier();
        $this->anomalyDetector = $anomalyDetector ?? new AnomalyDetector();
    }

    /**
     * Enable SQL injection detection.
     */
    public function enableSQLiDetection(): self
    {
        if (!class_exists(SQLiDetector::class)) {
            throw new \RuntimeException('SQLiDetector class not available');
        }
        $this->sqliDetector = new SQLiDetector();

        return $this;
    }

    /**
     * Enable XSS detection.
     */
    public function enableXSSDetection(): self
    {
        if (!class_exists(XSSDetector::class)) {
            throw new \RuntimeException('XSSDetector class not available');
        }
        $this->xssDetector = new XSSDetector();

        return $this;
    }

    /**
     * Set decision thresholds.
     */
    public function setThresholds(
        int $monitor = 20,
        int $challenge = 40,
        int $rateLimit = 55,
        int $block = 70,
        int $ban = 85,
    ): self {
        $this->monitorThreshold = $monitor;
        $this->challengeThreshold = $challenge;
        $this->rateLimitThreshold = $rateLimit;
        $this->blockThreshold = $block;
        $this->banThreshold = $ban;

        return $this;
    }

    /**
     * Analyze a request.
     *
     * @param array{
     *     ip: string,
     *     user_agent: string,
     *     path: string,
     *     method?: string,
     *     headers?: array,
     *     query_string?: string,
     *     body?: string,
     *     request_count?: int,
     *     error_count?: int,
     *     session_duration?: int
     * } $request
     *
     * @return array{
     *     decision: string,
     *     score: int,
     *     classification: array,
     *     anomalies: array,
     *     sqli: array|null,
     *     xss: array|null,
     *     reasons: array<string>,
     *     recommendation: string,
     *     should_log: bool,
     *     details: array
     * }
     */
    public function analyze(array $request): array
    {
        $ip = $request['ip'] ?? '';
        $userAgent = $request['user_agent'] ?? '';
        $path = $request['path'] ?? '/';
        $method = $request['method'] ?? 'GET';
        $headers = $request['headers'] ?? [];
        $queryString = $request['query_string'] ?? '';
        $body = $request['body'] ?? '';
        $requestCount = $request['request_count'] ?? 1;
        $errorCount = $request['error_count'] ?? 0;
        $sessionDuration = $request['session_duration'] ?? null;

        $reasons = [];
        $componentScores = [];

        // 1. Threat Classification
        $classification = $this->threatClassifier->classify(
            $ip,
            $userAgent,
            $path,
            $method,
            $headers,
            [
                '404_count' => $errorCount,
                'has_session' => $sessionDuration !== null,
            ],
        );

        $classificationScore = $classification['is_threat']
            ? (int) ($classification['confidence'] * 100)
            : 0;
        $componentScores['threat_classifier'] = $classificationScore;

        if ($classification['is_threat']) {
            $reasons[] = sprintf(
                'Classified as %s (%.0f%% confidence)',
                $classification['classification'],
                $classification['confidence'] * 100,
            );
        }

        // 2. Anomaly Detection
        $anomalies = $this->anomalyDetector->analyze(
            $ip,
            $path,
            $requestCount,
            $errorCount,
            $sessionDuration,
        );

        $componentScores['anomaly_detector'] = (int) $anomalies['anomaly_score'];

        if ($anomalies['is_anomaly']) {
            $reasons = array_merge($reasons, $anomalies['risk_factors']);
        }

        // 3. SQLi Detection (if enabled)
        $sqliResult = null;
        if ($this->sqliDetector !== null) {
            // Check query string and body
            $sqliInputs = array_filter([$queryString, $body], fn ($v) => !empty($v));
            $maxSqliScore = 0;

            foreach ($sqliInputs as $input) {
                $sqliCheck = $this->sqliDetector->detect($input);
                if ($sqliCheck['detected'] && $sqliCheck['confidence'] > $maxSqliScore) {
                    $sqliResult = $sqliCheck;
                    $maxSqliScore = $sqliCheck['confidence'];
                }
            }

            $componentScores['sqli_detector'] = $maxSqliScore;

            if ($sqliResult !== null && $sqliResult['detected']) {
                $reasons[] = sprintf(
                    'SQL injection detected (%.0f%% confidence, fingerprint: %s)',
                    $sqliResult['confidence'],
                    $sqliResult['fingerprint'] ?? 'unknown',
                );
            }
        } else {
            $componentScores['sqli_detector'] = 0;
        }

        // 4. XSS Detection (if enabled)
        $xssResult = null;
        if ($this->xssDetector !== null) {
            $xssInputs = array_filter([$queryString, $body], fn ($v) => !empty($v));
            $maxXssScore = 0;

            foreach ($xssInputs as $input) {
                $xssCheck = $this->xssDetector->detect($input);
                if ($xssCheck['detected'] && $xssCheck['confidence'] > $maxXssScore) {
                    $xssResult = $xssCheck;
                    $maxXssScore = $xssCheck['confidence'];
                }
            }

            $componentScores['xss_detector'] = $maxXssScore;

            if ($xssResult !== null && $xssResult['detected']) {
                $reasons[] = sprintf(
                    'XSS detected (%.0f%% confidence)',
                    $xssResult['confidence'],
                );
            }
        } else {
            $componentScores['xss_detector'] = 0;
        }

        // 5. Calculate weighted aggregate score
        $totalScore = 0.0;
        $totalWeight = 0.0;

        foreach ($componentScores as $component => $score) {
            $weight = self::ANALYZER_WEIGHTS[$component] ?? 0.25;
            $totalScore += $score * $weight;
            $totalWeight += $weight;
        }

        $aggregateScore = (int) round($totalScore / $totalWeight);

        // Boost score for critical detections
        if (($sqliResult['detected'] ?? false) && $sqliResult['confidence'] >= 80) {
            $aggregateScore = max($aggregateScore, 80);
        }
        if (($xssResult['detected'] ?? false) && $xssResult['confidence'] >= 80) {
            $aggregateScore = max($aggregateScore, 75);
        }
        if ($classification['classification'] === 'BOT_SPOOF' && $classification['confidence'] >= 0.9) {
            $aggregateScore = max($aggregateScore, 90);
        }

        // Cap at 100
        $aggregateScore = min(100, $aggregateScore);

        // 6. Determine decision
        $decision = $this->determineDecision($aggregateScore);

        // 7. Build recommendation
        $recommendation = $this->buildRecommendation($decision, $aggregateScore, $reasons);

        return [
            'decision' => $decision,
            'score' => $aggregateScore,
            'classification' => $classification,
            'anomalies' => $anomalies,
            'sqli' => $sqliResult,
            'xss' => $xssResult,
            'reasons' => $reasons,
            'recommendation' => $recommendation,
            'should_log' => $aggregateScore >= $this->monitorThreshold,
            'details' => [
                'component_scores' => $componentScores,
                'ip' => $ip,
                'path' => $path,
                'method' => $method,
            ],
        ];
    }

    /**
     * Quick check if request should be blocked.
     */
    public function shouldBlock(array $request): bool
    {
        $result = $this->analyze($request);

        return in_array($result['decision'], ['BLOCK', 'BAN'], true);
    }

    /**
     * Get threat score only (faster than full analysis).
     */
    public function getQuickScore(string $ip, string $userAgent, string $path): int
    {
        $classification = $this->threatClassifier->classify($ip, $userAgent, $path);

        if (!$classification['is_threat']) {
            return 0;
        }

        return (int) ($classification['confidence'] * 100);
    }

    /**
     * Analyze batch of requests.
     *
     * @param array<array> $requests
     *
     * @return array<array>
     */
    public function analyzeBatch(array $requests): array
    {
        $results = [];
        foreach ($requests as $key => $request) {
            $results[$key] = $this->analyze($request);
        }

        return $results;
    }

    /**
     * Get analyzer statistics.
     */
    public function getStats(): array
    {
        return [
            'threat_classifier' => $this->threatClassifier->getModelStats(),
            'anomaly_detector' => [
                'baseline_metrics' => count($this->anomalyDetector->getBaselineStats()),
            ],
            'sqli_detector_enabled' => $this->sqliDetector !== null,
            'xss_detector_enabled' => $this->xssDetector !== null,
            'thresholds' => [
                'monitor' => $this->monitorThreshold,
                'challenge' => $this->challengeThreshold,
                'rate_limit' => $this->rateLimitThreshold,
                'block' => $this->blockThreshold,
                'ban' => $this->banThreshold,
            ],
        ];
    }

    /**
     * Determine decision based on score.
     */
    private function determineDecision(int $score): string
    {
        if ($score >= $this->banThreshold) {
            return 'BAN';
        }
        if ($score >= $this->blockThreshold) {
            return 'BLOCK';
        }
        if ($score >= $this->rateLimitThreshold) {
            return 'RATE_LIMIT';
        }
        if ($score >= $this->challengeThreshold) {
            return 'CHALLENGE';
        }
        if ($score >= $this->monitorThreshold) {
            return 'MONITOR';
        }

        return 'ALLOW';
    }

    /**
     * Build recommendation message.
     */
    private function buildRecommendation(string $decision, int $score, array $reasons): string
    {
        $messages = [
            'ALLOW' => 'Request appears legitimate. No action required.',
            'MONITOR' => 'Minor suspicion detected. Request logged for analysis.',
            'CHALLENGE' => 'Moderate risk. Consider presenting CAPTCHA or verification challenge.',
            'RATE_LIMIT' => 'Elevated risk. Apply rate limiting to this IP.',
            'BLOCK' => 'High risk request. Block this request immediately.',
            'BAN' => 'Critical threat detected. Ban IP and block all future requests.',
        ];

        $base = $messages[$decision] ?? 'Unknown decision.';

        if (!empty($reasons)) {
            $base .= ' Reasons: ' . implode('; ', array_slice($reasons, 0, 3));
        }

        return $base;
    }
}
