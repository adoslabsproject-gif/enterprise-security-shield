<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Detection;

use AdosLabs\EnterpriseSecurityShield\Contracts\StorageInterface;

/**
 * Layer 7 DDoS Protection.
 *
 * Detects and mitigates application-layer DDoS attacks:
 * - Slowloris (slow HTTP headers)
 * - RUDY (R-U-Dead-Yet, slow POST body)
 * - HTTP Flood (high request rate)
 * - SSL/TLS Abuse (renegotiation attacks)
 * - Resource Exhaustion (expensive endpoints)
 *
 * IMPORTANT: Full DDoS protection requires:
 * 1. Network-level filtering (iptables, nftables)
 * 2. CDN/Proxy (Cloudflare, AWS Shield)
 * 3. This application-layer detection
 *
 * This class handles #3 - application-layer detection and signaling.
 */
final class DDoSProtector
{
    /**
     * Storage backend for tracking state.
     */
    private ?StorageInterface $storage;

    /**
     * Maximum requests per IP per window.
     */
    private int $maxRequestsPerWindow = 1000;

    /**
     * Window size in seconds.
     */
    private int $windowSize = 60;

    /**
     * Maximum concurrent connections per IP.
     */
    private int $maxConcurrentConnections = 50;

    /**
     * Slowloris detection: minimum headers per second.
     */
    private float $minHeadersPerSecond = 2.0;

    /**
     * RUDY detection: minimum body bytes per second.
     */
    private int $minBodyBytesPerSecond = 100;

    /**
     * Maximum request duration (seconds).
     */
    private int $maxRequestDuration = 30;

    /**
     * Expensive endpoints (path => cost multiplier).
     *
     * @var array<string, int>
     */
    private array $expensiveEndpoints = [];

    /**
     * Whitelisted IPs.
     *
     * @var array<string>
     */
    private array $whitelist = [];

    /**
     * Constructor.
     *
     * @param array<string, mixed> $config Configuration options
     */
    public function __construct(?StorageInterface $storage = null, array $config = [])
    {
        $this->storage = $storage;
        $this->maxRequestsPerWindow = $config['max_requests_per_window'] ?? 1000;
        $this->windowSize = $config['window_size'] ?? 60;
        $this->maxConcurrentConnections = $config['max_concurrent_connections'] ?? 50;
        $this->minHeadersPerSecond = $config['min_headers_per_second'] ?? 2.0;
        $this->minBodyBytesPerSecond = $config['min_body_bytes_per_second'] ?? 100;
        $this->maxRequestDuration = $config['max_request_duration'] ?? 30;
        $this->expensiveEndpoints = $config['expensive_endpoints'] ?? [];
        $this->whitelist = $config['whitelist'] ?? [];
    }

    /**
     * Analyze request for DDoS indicators.
     *
     * @param string $clientIp Client IP address
     * @param string $path Request path
     * @param string $method HTTP method
     * @param array<string, mixed> $metrics Request metrics from web server
     *
     * @return array{
     *     allowed: bool,
     *     attack_type: string|null,
     *     confidence: float,
     *     reason: string,
     *     action: string,
     *     metrics: array<string, mixed>
     * }
     */
    public function analyze(
        string $clientIp,
        string $path,
        string $method,
        array $metrics = [],
    ): array {
        // Check whitelist
        if (in_array($clientIp, $this->whitelist, true)) {
            return $this->buildResult(true, null, 0.0, 'IP is whitelisted', 'ALLOW', []);
        }

        $attackType = null;
        $confidence = 0.0;
        $reasons = [];
        $collectedMetrics = [];

        // Check 1: HTTP Flood
        $floodResult = $this->detectHttpFlood($clientIp);
        $collectedMetrics['request_count'] = $floodResult['count'];
        $collectedMetrics['window_size'] = $this->windowSize;

        if ($floodResult['detected']) {
            $attackType = 'HTTP_FLOOD';
            $confidence = max($confidence, $floodResult['confidence']);
            $reasons[] = $floodResult['reason'];
        }

        // Check 2: Slowloris (requires timing metrics)
        if (isset($metrics['header_receive_time'], $metrics['header_count'])) {
            $slowlorisResult = $this->detectSlowloris(
                (float) $metrics['header_receive_time'],
                (int) $metrics['header_count'],
            );
            $collectedMetrics['headers_per_second'] = $slowlorisResult['rate'];

            if ($slowlorisResult['detected']) {
                $attackType ??= 'SLOWLORIS';
                $confidence = max($confidence, $slowlorisResult['confidence']);
                $reasons[] = $slowlorisResult['reason'];
            }
        }

        // Check 3: RUDY (requires body timing metrics)
        if (isset($metrics['body_receive_time'], $metrics['content_length'])) {
            $rudyResult = $this->detectRudy(
                (float) $metrics['body_receive_time'],
                (int) $metrics['content_length'],
            );
            $collectedMetrics['body_bytes_per_second'] = $rudyResult['rate'];

            if ($rudyResult['detected']) {
                $attackType ??= 'RUDY';
                $confidence = max($confidence, $rudyResult['confidence']);
                $reasons[] = $rudyResult['reason'];
            }
        }

        // Check 4: Request duration
        if (isset($metrics['request_duration'])) {
            $duration = (float) $metrics['request_duration'];
            $collectedMetrics['request_duration'] = $duration;

            if ($duration > $this->maxRequestDuration) {
                $attackType ??= 'SLOW_REQUEST';
                $confidence = max($confidence, 0.7);
                $reasons[] = "Request duration ({$duration}s) exceeds maximum ({$this->maxRequestDuration}s)";
            }
        }

        // Check 5: Concurrent connections
        if (isset($metrics['concurrent_connections'])) {
            $connections = (int) $metrics['concurrent_connections'];
            $collectedMetrics['concurrent_connections'] = $connections;

            if ($connections > $this->maxConcurrentConnections) {
                $attackType ??= 'CONNECTION_FLOOD';
                $confidence = max($confidence, 0.85);
                $reasons[] = "Concurrent connections ({$connections}) exceeds maximum ({$this->maxConcurrentConnections})";
            }
        }

        // Check 6: Expensive endpoint abuse
        $endpointCost = $this->getEndpointCost($path, $method);
        $collectedMetrics['endpoint_cost'] = $endpointCost;

        if ($endpointCost > 1) {
            $effectiveRequests = $floodResult['count'] * $endpointCost;
            if ($effectiveRequests > $this->maxRequestsPerWindow) {
                $attackType ??= 'RESOURCE_EXHAUSTION';
                $confidence = max($confidence, 0.75);
                $reasons[] = "Expensive endpoint abuse (cost: {$endpointCost}x, effective requests: {$effectiveRequests})";
            }
        }

        // Determine action
        $allowed = $attackType === null;
        $action = $this->determineAction($attackType, $confidence);
        $reason = empty($reasons) ? 'Request appears normal' : implode('; ', $reasons);

        return $this->buildResult($allowed, $attackType, $confidence, $reason, $action, $collectedMetrics);
    }

    /**
     * Detect HTTP flood attack.
     *
     * @return array{detected: bool, confidence: float, reason: string, count: int}
     */
    private function detectHttpFlood(string $clientIp): array
    {
        if ($this->storage === null) {
            return [
                'detected' => false,
                'confidence' => 0.0,
                'reason' => 'No storage configured for flood detection',
                'count' => 0,
            ];
        }

        $key = "ddos:flood:{$clientIp}";
        $count = $this->storage->incrementScore($key, 1, $this->windowSize);

        $detected = $count > $this->maxRequestsPerWindow;
        $confidence = 0.0;

        if ($detected) {
            // Higher confidence as we exceed the limit more
            $ratio = $count / $this->maxRequestsPerWindow;
            $confidence = min(0.95, 0.5 + ($ratio - 1) * 0.2);
        }

        return [
            'detected' => $detected,
            'confidence' => $confidence,
            'reason' => $detected
                ? "Request count ({$count}) exceeds maximum ({$this->maxRequestsPerWindow}) in {$this->windowSize}s window"
                : 'Within rate limit',
            'count' => $count,
        ];
    }

    /**
     * Detect Slowloris attack.
     *
     * Slowloris sends HTTP headers slowly to keep connections open.
     *
     * @return array{detected: bool, confidence: float, reason: string, rate: float}
     */
    private function detectSlowloris(float $headerReceiveTime, int $headerCount): array
    {
        if ($headerReceiveTime <= 0 || $headerCount <= 0) {
            return [
                'detected' => false,
                'confidence' => 0.0,
                'reason' => 'Insufficient data for Slowloris detection',
                'rate' => 0.0,
            ];
        }

        $headersPerSecond = $headerCount / $headerReceiveTime;
        $detected = $headersPerSecond < $this->minHeadersPerSecond && $headerReceiveTime > 5;

        $confidence = 0.0;
        if ($detected) {
            // Lower rate = higher confidence
            $confidence = min(0.9, 0.5 + (($this->minHeadersPerSecond - $headersPerSecond) / $this->minHeadersPerSecond) * 0.4);
        }

        return [
            'detected' => $detected,
            'confidence' => $confidence,
            'reason' => $detected
                ? sprintf('Slow headers detected (%.2f headers/sec, minimum: %d)', $headersPerSecond, $this->minHeadersPerSecond)
                : 'Header rate normal',
            'rate' => $headersPerSecond,
        ];
    }

    /**
     * Detect RUDY (R-U-Dead-Yet) attack.
     *
     * RUDY sends POST body slowly to exhaust server resources.
     *
     * @return array{detected: bool, confidence: float, reason: string, rate: float}
     */
    private function detectRudy(float $bodyReceiveTime, int $contentLength): array
    {
        if ($bodyReceiveTime <= 0 || $contentLength <= 0) {
            return [
                'detected' => false,
                'confidence' => 0.0,
                'reason' => 'Insufficient data for RUDY detection',
                'rate' => 0.0,
            ];
        }

        $bytesPerSecond = $contentLength / $bodyReceiveTime;
        $detected = $bytesPerSecond < $this->minBodyBytesPerSecond && $bodyReceiveTime > 10;

        $confidence = 0.0;
        if ($detected) {
            // Lower rate = higher confidence
            $confidence = min(0.9, 0.5 + (($this->minBodyBytesPerSecond - $bytesPerSecond) / $this->minBodyBytesPerSecond) * 0.4);
        }

        return [
            'detected' => $detected,
            'confidence' => $confidence,
            'reason' => $detected
                ? sprintf('Slow POST body detected (%.0f bytes/sec, minimum: %d)', $bytesPerSecond, $this->minBodyBytesPerSecond)
                : 'Body receive rate normal',
            'rate' => $bytesPerSecond,
        ];
    }

    /**
     * Get cost multiplier for an endpoint.
     */
    private function getEndpointCost(string $path, string $method): int
    {
        // Check exact match
        $key = "{$method}:{$path}";
        if (isset($this->expensiveEndpoints[$key])) {
            return $this->expensiveEndpoints[$key];
        }

        // Check path-only match
        if (isset($this->expensiveEndpoints[$path])) {
            return $this->expensiveEndpoints[$path];
        }

        // Check pattern matches
        foreach ($this->expensiveEndpoints as $pattern => $cost) {
            if (str_starts_with($pattern, 'regex:')) {
                $regex = substr($pattern, 6);
                if (preg_match($regex, $path)) {
                    return $cost;
                }
            } elseif (str_contains($pattern, '*')) {
                $regex = '/^' . str_replace(['*', '/'], ['.*', '\\/'], $pattern) . '$/';
                if (preg_match($regex, $path)) {
                    return $cost;
                }
            }
        }

        return 1;
    }

    /**
     * Determine action based on attack type and confidence.
     */
    private function determineAction(?string $attackType, float $confidence): string
    {
        if ($attackType === null) {
            return 'ALLOW';
        }

        if ($confidence >= 0.8) {
            return 'BLOCK';
        }

        if ($confidence >= 0.6) {
            return 'CHALLENGE';
        }

        if ($confidence >= 0.4) {
            return 'THROTTLE';
        }

        return 'MONITOR';
    }

    /**
     * Build result array.
     *
     * @param array<string, mixed> $metrics
     *
     * @return array{
     *     allowed: bool,
     *     attack_type: string|null,
     *     confidence: float,
     *     reason: string,
     *     action: string,
     *     metrics: array<string, mixed>
     * }
     */
    private function buildResult(
        bool $allowed,
        ?string $attackType,
        float $confidence,
        string $reason,
        string $action,
        array $metrics,
    ): array {
        return [
            'allowed' => $allowed,
            'attack_type' => $attackType,
            'confidence' => round($confidence, 3),
            'reason' => $reason,
            'action' => $action,
            'metrics' => $metrics,
        ];
    }

    /**
     * Record attack metrics for analysis.
     */
    public function recordAttack(string $clientIp, string $attackType): void
    {
        if ($this->storage === null) {
            return;
        }

        // Track attack frequency by type
        $key = "ddos:attacks:{$attackType}";
        $this->storage->incrementScore($key, 1, 3600);

        // Track attacking IPs
        $ipKey = "ddos:attackers:{$clientIp}";
        $this->storage->incrementScore($ipKey, 1, 86400);
    }

    /**
     * Get attack statistics.
     *
     * @return array<string, mixed>
     */
    public function getStatistics(): array
    {
        if ($this->storage === null) {
            return ['error' => 'No storage configured'];
        }

        // This would require additional storage methods to implement properly
        return [
            'window_size' => $this->windowSize,
            'max_requests' => $this->maxRequestsPerWindow,
            'max_connections' => $this->maxConcurrentConnections,
        ];
    }

    /**
     * Add IP to whitelist.
     */
    public function addToWhitelist(string $ip): self
    {
        $this->whitelist[] = $ip;

        return $this;
    }

    /**
     * Add expensive endpoint.
     */
    public function addExpensiveEndpoint(string $pattern, int $cost): self
    {
        $this->expensiveEndpoints[$pattern] = $cost;

        return $this;
    }

    /**
     * Set maximum requests per window.
     */
    public function setMaxRequestsPerWindow(int $max): self
    {
        $this->maxRequestsPerWindow = $max;

        return $this;
    }

    /**
     * Set window size in seconds.
     */
    public function setWindowSize(int $seconds): self
    {
        $this->windowSize = $seconds;

        return $this;
    }
}
