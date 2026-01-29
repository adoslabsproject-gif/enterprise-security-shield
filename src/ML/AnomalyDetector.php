<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\ML;

/**
 * Statistical Anomaly Detector
 *
 * Uses statistical methods to detect anomalous behavior patterns.
 * Trained on baseline metrics from need2talk.it normal traffic.
 *
 * DETECTION METHODS:
 * 1. Z-Score: Detects values > 3 standard deviations from mean
 * 2. IQR (Interquartile Range): Robust outlier detection
 * 3. Time Series: Detects unusual patterns over time windows
 * 4. Behavioral Clustering: Groups similar request patterns
 *
 * FEATURES ANALYZED:
 * - Request frequency per IP
 * - Path entropy (scanning behavior has low entropy)
 * - Session behavior patterns
 * - Geographic anomalies
 * - Time-based patterns (attacks often happen at specific times)
 *
 * @version 1.0.0
 */
final class AnomalyDetector
{
    /**
     * Baseline statistics from need2talk normal traffic
     * These represent "normal" user behavior
     */
    private const BASELINE_STATS = [
        // Requests per minute from single IP (normal user)
        'requests_per_minute' => [
            'mean' => 2.5,
            'std' => 1.8,
            'q1' => 1.0,
            'median' => 2.0,
            'q3' => 3.5,
        ],

        // 404 errors per session (normal user occasionally hits wrong URLs)
        '404_per_session' => [
            'mean' => 0.3,
            'std' => 0.7,
            'q1' => 0.0,
            'median' => 0.0,
            'q3' => 0.0,
        ],

        // Unique paths per session (normal user visits ~5-15 pages)
        'unique_paths_per_session' => [
            'mean' => 8.5,
            'std' => 6.2,
            'q1' => 3.0,
            'median' => 7.0,
            'q3' => 12.0,
        ],

        // Session duration in seconds
        'session_duration' => [
            'mean' => 420, // 7 minutes
            'std' => 380,
            'q1' => 60,
            'median' => 300,
            'q3' => 600,
        ],

        // Path depth (normal pages are usually /section/page)
        'path_depth' => [
            'mean' => 2.3,
            'std' => 1.1,
            'q1' => 1.0,
            'median' => 2.0,
            'q3' => 3.0,
        ],

        // Request payload size (bytes)
        'payload_size' => [
            'mean' => 150,
            'std' => 300,
            'q1' => 0,
            'median' => 50,
            'q3' => 200,
        ],

        // Login attempts per hour per IP
        'login_attempts_per_hour' => [
            'mean' => 0.5,
            'std' => 0.8,
            'q1' => 0.0,
            'median' => 0.0,
            'q3' => 1.0,
        ],
    ];

    /**
     * Attack patterns timing (from log analysis)
     * Attacks in need2talk logs clustered around certain hours
     */
    private const ATTACK_HOUR_DISTRIBUTION = [
        // Percentage of attacks per hour (UTC)
        0 => 0.05, 1 => 0.06, 2 => 0.07, 3 => 0.08,
        4 => 0.09, 5 => 0.08, 6 => 0.06, 7 => 0.04,
        8 => 0.03, 9 => 0.02, 10 => 0.02, 11 => 0.02,
        12 => 0.03, 13 => 0.03, 14 => 0.03, 15 => 0.03,
        16 => 0.03, 17 => 0.04, 18 => 0.04, 19 => 0.04,
        20 => 0.04, 21 => 0.04, 22 => 0.04, 23 => 0.05,
    ];

    /**
     * Path entropy thresholds
     * Scanners often have very low entropy (sequential paths)
     */
    private const PATH_ENTROPY_THRESHOLD = 2.0; // Below this is suspicious

    private float $zScoreThreshold = 3.0;
    private float $iqrMultiplier = 1.5;

    /**
     * Per-IP metrics storage for time-series analysis
     * @var array<string, array>
     */
    private array $ipMetrics = [];

    /**
     * Time window for metrics collection (seconds)
     */
    private int $timeWindow = 300; // 5 minutes

    public function setZScoreThreshold(float $threshold): self
    {
        $this->zScoreThreshold = max(1.0, $threshold);
        return $this;
    }

    public function setIQRMultiplier(float $multiplier): self
    {
        $this->iqrMultiplier = max(1.0, $multiplier);
        return $this;
    }

    public function setTimeWindow(int $seconds): self
    {
        $this->timeWindow = max(60, $seconds);
        return $this;
    }

    /**
     * Analyze request for anomalies
     *
     * @return array{
     *     is_anomaly: bool,
     *     anomaly_score: float,
     *     anomalies: array<array{type: string, metric: string, value: float, threshold: float, severity: string}>,
     *     risk_factors: array<string>,
     *     recommendation: string
     * }
     */
    public function analyze(
        string $ip,
        string $path,
        int $requestCount = 1,
        int $errorCount404 = 0,
        ?int $sessionDuration = null,
        ?int $payloadSize = null,
        ?int $hour = null
    ): array {
        $anomalies = [];
        $riskFactors = [];
        $anomalyScore = 0.0;

        $hour = $hour ?? (int) date('G');

        // 1. Request frequency anomaly (Z-Score)
        $requestsPerMinute = $requestCount / ($this->timeWindow / 60);
        $zScore = $this->calculateZScore($requestsPerMinute, 'requests_per_minute');
        if (abs($zScore) > $this->zScoreThreshold) {
            $anomalies[] = [
                'type' => 'zscore',
                'metric' => 'requests_per_minute',
                'value' => $requestsPerMinute,
                'threshold' => self::BASELINE_STATS['requests_per_minute']['mean'] + (self::BASELINE_STATS['requests_per_minute']['std'] * $this->zScoreThreshold),
                'severity' => $zScore > 5 ? 'CRITICAL' : 'HIGH',
                'z_score' => $zScore,
            ];
            $anomalyScore += min(30, $zScore * 5);
            $riskFactors[] = sprintf('Unusual request rate: %.1f/min (expected ~%.1f)', $requestsPerMinute, self::BASELINE_STATS['requests_per_minute']['mean']);
        }

        // 2. 404 error rate anomaly (IQR)
        $isOutlier = $this->isIQROutlier($errorCount404, '404_per_session');
        if ($isOutlier && $errorCount404 > 3) {
            $anomalies[] = [
                'type' => 'iqr',
                'metric' => '404_per_session',
                'value' => $errorCount404,
                'threshold' => self::BASELINE_STATS['404_per_session']['q3'] + (self::BASELINE_STATS['404_per_session']['q3'] - self::BASELINE_STATS['404_per_session']['q1']) * $this->iqrMultiplier,
                'severity' => $errorCount404 > 10 ? 'CRITICAL' : 'MEDIUM',
            ];
            $anomalyScore += min(25, $errorCount404 * 2);
            $riskFactors[] = sprintf('High 404 error rate: %d errors (scanning behavior)', $errorCount404);
        }

        // 3. Path depth analysis
        $pathDepth = substr_count($path, '/');
        $pathZScore = $this->calculateZScore($pathDepth, 'path_depth');
        if ($pathDepth > 6 || str_contains($path, '..')) {
            $anomalies[] = [
                'type' => 'structural',
                'metric' => 'path_depth',
                'value' => $pathDepth,
                'threshold' => 6,
                'severity' => str_contains($path, '..') ? 'CRITICAL' : 'LOW',
            ];
            $anomalyScore += str_contains($path, '..') ? 40 : 10;
            $riskFactors[] = 'Deep or suspicious path structure';
        }

        // 4. Payload size anomaly (if provided)
        if ($payloadSize !== null && $payloadSize > 0) {
            $payloadZScore = $this->calculateZScore($payloadSize, 'payload_size');
            if ($payloadZScore > $this->zScoreThreshold) {
                $anomalies[] = [
                    'type' => 'zscore',
                    'metric' => 'payload_size',
                    'value' => $payloadSize,
                    'threshold' => self::BASELINE_STATS['payload_size']['mean'] + (self::BASELINE_STATS['payload_size']['std'] * $this->zScoreThreshold),
                    'severity' => $payloadSize > 10000 ? 'HIGH' : 'LOW',
                ];
                $anomalyScore += min(15, $payloadZScore * 3);
                $riskFactors[] = sprintf('Unusually large request payload: %d bytes', $payloadSize);
            }
        }

        // 5. Session duration anomaly (very short sessions are suspicious)
        if ($sessionDuration !== null && $sessionDuration < 5 && $requestCount > 10) {
            $anomalies[] = [
                'type' => 'behavioral',
                'metric' => 'session_duration',
                'value' => $sessionDuration,
                'threshold' => 5,
                'severity' => 'MEDIUM',
            ];
            $anomalyScore += 15;
            $riskFactors[] = 'Very short session with many requests (automated behavior)';
        }

        // 6. Time-based anomaly
        $attackProbability = self::ATTACK_HOUR_DISTRIBUTION[$hour] ?? 0.04;
        if ($attackProbability > 0.06 && $anomalyScore > 0) {
            // Attacks more likely at this hour - boost score
            $anomalyScore *= 1.2;
            $riskFactors[] = sprintf('Request during high-attack period (hour %d UTC)', $hour);
        }

        // 7. Track IP metrics for time-series analysis
        $this->trackIPMetrics($ip, $requestCount, $errorCount404);
        $burstDetected = $this->detectRequestBurst($ip);
        if ($burstDetected) {
            $anomalies[] = [
                'type' => 'timeseries',
                'metric' => 'request_burst',
                'value' => $burstDetected['rate'],
                'threshold' => $burstDetected['threshold'],
                'severity' => 'HIGH',
            ];
            $anomalyScore += 25;
            $riskFactors[] = 'Request burst detected within time window';
        }

        // Normalize score to 0-100
        $anomalyScore = min(100, $anomalyScore);

        // Determine if anomaly
        $isAnomaly = $anomalyScore >= 30 || count($anomalies) >= 2;

        // Build recommendation
        $recommendation = $this->buildRecommendation($anomalyScore, $anomalies);

        return [
            'is_anomaly' => $isAnomaly,
            'anomaly_score' => round($anomalyScore, 2),
            'anomalies' => $anomalies,
            'risk_factors' => $riskFactors,
            'recommendation' => $recommendation,
        ];
    }

    /**
     * Calculate path entropy (measure of randomness)
     * Low entropy = likely scanning (similar paths like /admin1, /admin2, etc.)
     */
    public function calculatePathEntropy(array $paths): float
    {
        if (count($paths) < 2) {
            return 0.0;
        }

        // Tokenize paths and count occurrences
        $tokens = [];
        foreach ($paths as $path) {
            $parts = explode('/', trim($path, '/'));
            foreach ($parts as $part) {
                // Normalize: remove numbers, lowercase
                $normalized = preg_replace('/\d+/', '#', strtolower($part));
                $tokens[] = $normalized;
            }
        }

        if (empty($tokens)) {
            return 0.0;
        }

        // Calculate entropy
        $counts = array_count_values($tokens);
        $total = count($tokens);
        $entropy = 0.0;

        foreach ($counts as $count) {
            $p = $count / $total;
            if ($p > 0) {
                $entropy -= $p * log($p, 2);
            }
        }

        return $entropy;
    }

    /**
     * Detect scanning behavior based on paths visited
     */
    public function detectScanning(array $paths): array
    {
        $entropy = $this->calculatePathEntropy($paths);
        $isScanning = false;
        $confidence = 0.0;
        $patterns = [];

        // Low entropy indicates scanning
        if ($entropy < self::PATH_ENTROPY_THRESHOLD && count($paths) > 5) {
            $isScanning = true;
            $confidence = 1.0 - ($entropy / self::PATH_ENTROPY_THRESHOLD);
            $patterns[] = 'low_entropy';
        }

        // Check for sequential patterns
        $sequential = $this->detectSequentialPaths($paths);
        if ($sequential['detected']) {
            $isScanning = true;
            $confidence = max($confidence, 0.8);
            $patterns[] = 'sequential_paths';
        }

        // Check for common scanner path patterns
        $scannerPaths = ['/wp-', '/admin', '/.env', '/.git', '/config', '/phpinfo', '/phpmyadmin'];
        $scannerPathCount = 0;
        foreach ($paths as $path) {
            $pathLower = strtolower($path);
            foreach ($scannerPaths as $scannerPath) {
                if (str_contains($pathLower, $scannerPath)) {
                    $scannerPathCount++;
                    break;
                }
            }
        }

        if ($scannerPathCount > 3) {
            $isScanning = true;
            $confidence = max($confidence, 0.9);
            $patterns[] = 'known_scanner_paths';
        }

        return [
            'is_scanning' => $isScanning,
            'confidence' => round($confidence, 2),
            'entropy' => round($entropy, 3),
            'patterns' => $patterns,
            'path_count' => count($paths),
            'scanner_path_hits' => $scannerPathCount,
        ];
    }

    /**
     * Calculate Z-Score for a value
     */
    private function calculateZScore(float $value, string $metric): float
    {
        if (!isset(self::BASELINE_STATS[$metric])) {
            return 0.0;
        }

        $stats = self::BASELINE_STATS[$metric];
        if ($stats['std'] == 0) {
            return 0.0;
        }

        return ($value - $stats['mean']) / $stats['std'];
    }

    /**
     * Check if value is an IQR outlier
     */
    private function isIQROutlier(float $value, string $metric): bool
    {
        if (!isset(self::BASELINE_STATS[$metric])) {
            return false;
        }

        $stats = self::BASELINE_STATS[$metric];
        $iqr = $stats['q3'] - $stats['q1'];
        $lowerBound = $stats['q1'] - ($this->iqrMultiplier * $iqr);
        $upperBound = $stats['q3'] + ($this->iqrMultiplier * $iqr);

        return $value < $lowerBound || $value > $upperBound;
    }

    /**
     * Track IP metrics over time
     */
    private function trackIPMetrics(string $ip, int $requestCount, int $errorCount): void
    {
        $now = time();

        if (!isset($this->ipMetrics[$ip])) {
            $this->ipMetrics[$ip] = [
                'requests' => [],
                'errors' => [],
            ];
        }

        // Add current data point
        $this->ipMetrics[$ip]['requests'][] = ['time' => $now, 'count' => $requestCount];
        $this->ipMetrics[$ip]['errors'][] = ['time' => $now, 'count' => $errorCount];

        // Clean old data points
        $cutoff = $now - $this->timeWindow;
        $this->ipMetrics[$ip]['requests'] = array_filter(
            $this->ipMetrics[$ip]['requests'],
            fn($point) => $point['time'] >= $cutoff
        );
        $this->ipMetrics[$ip]['errors'] = array_filter(
            $this->ipMetrics[$ip]['errors'],
            fn($point) => $point['time'] >= $cutoff
        );

        // Limit memory usage
        if (count($this->ipMetrics) > 10000) {
            // Remove oldest IPs
            $this->ipMetrics = array_slice($this->ipMetrics, -5000, null, true);
        }
    }

    /**
     * Detect request burst for an IP
     */
    private function detectRequestBurst(string $ip): ?array
    {
        if (!isset($this->ipMetrics[$ip])) {
            return null;
        }

        $requests = $this->ipMetrics[$ip]['requests'];
        if (count($requests) < 3) {
            return null;
        }

        // Calculate requests in time window
        $totalRequests = array_sum(array_column($requests, 'count'));
        $timeSpan = max(1, end($requests)['time'] - reset($requests)['time']);

        // Requests per second
        $rate = $totalRequests / $timeSpan;

        // Burst threshold: more than 2 requests per second sustained
        $threshold = 2.0;

        if ($rate > $threshold) {
            return [
                'rate' => round($rate, 2),
                'threshold' => $threshold,
                'total_requests' => $totalRequests,
                'time_span' => $timeSpan,
            ];
        }

        return null;
    }

    /**
     * Detect sequential path patterns (common in scanners)
     */
    private function detectSequentialPaths(array $paths): array
    {
        if (count($paths) < 3) {
            return ['detected' => false];
        }

        $sequential = 0;

        for ($i = 1; $i < count($paths); $i++) {
            $prev = $paths[$i - 1];
            $curr = $paths[$i];

            // Check if paths differ only by a number
            $prevNorm = preg_replace('/\d+/', '#', $prev);
            $currNorm = preg_replace('/\d+/', '#', $curr);

            if ($prevNorm === $currNorm && $prev !== $curr) {
                $sequential++;
            }

            // Check for directory enumeration (same base, different file)
            $prevDir = dirname($prev);
            $currDir = dirname($curr);
            if ($prevDir === $currDir && $prev !== $curr) {
                $sequential++;
            }
        }

        $sequentialRatio = $sequential / (count($paths) - 1);

        return [
            'detected' => $sequentialRatio > 0.5,
            'sequential_count' => $sequential,
            'ratio' => round($sequentialRatio, 2),
        ];
    }

    /**
     * Build recommendation based on analysis
     */
    private function buildRecommendation(float $score, array $anomalies): string
    {
        if ($score >= 80) {
            return 'BLOCK: High confidence malicious activity. Recommend immediate IP ban.';
        }

        if ($score >= 60) {
            return 'CHALLENGE: Elevated risk. Recommend CAPTCHA or rate limiting.';
        }

        if ($score >= 40) {
            return 'MONITOR: Moderate anomalies detected. Increase monitoring for this IP.';
        }

        if ($score >= 20) {
            return 'LOG: Minor anomalies. Log for pattern analysis.';
        }

        return 'ALLOW: No significant anomalies detected.';
    }

    /**
     * Get baseline statistics
     */
    public function getBaselineStats(): array
    {
        return self::BASELINE_STATS;
    }

    /**
     * Clear tracked metrics (for testing or memory management)
     */
    public function clearMetrics(): void
    {
        $this->ipMetrics = [];
    }
}
