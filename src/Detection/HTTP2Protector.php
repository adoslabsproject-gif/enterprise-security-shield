<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Detection;

/**
 * HTTP/2 Specific Attack Protector.
 *
 * Detects attacks specific to HTTP/2 protocol:
 * - CONTINUATION Flood (CVE-2024-27983)
 * - HPACK Bomb (header compression abuse)
 * - Stream Multiplexing Abuse
 * - Priority Manipulation (DoS)
 * - Rapid Reset (CVE-2023-44487)
 * - Settings Flood
 *
 * IMPORTANT LIMITATIONS:
 * PHP does not have direct access to HTTP/2 framing. These checks work with:
 * 1. Metrics provided by the web server (nginx, Apache with mod_http2)
 * 2. Headers that indicate HTTP/2 behavior
 * 3. Patterns detectable at the application layer
 *
 * For full HTTP/2 protection, configure your reverse proxy (nginx, Cloudflare, etc.)
 */
final class HTTP2Protector
{
    /**
     * Maximum allowed pseudo-headers.
     */
    private int $maxPseudoHeaders = 4;

    /**
     * Maximum header list size (bytes).
     */
    private int $maxHeaderListSize = 16384;

    /**
     * Maximum individual header size.
     */
    private int $maxHeaderSize = 8192;

    /**
     * Maximum concurrent streams (for detection, not enforcement).
     */
    private int $maxConcurrentStreams = 100;

    /**
     * Maximum CONTINUATION frames allowed.
     */
    private int $maxContinuationFrames = 5;

    /**
     * Maximum resets per minute.
     */
    private int $maxResetsPerMinute = 100;

    /**
     * Maximum settings frames per minute.
     */
    private int $maxSettingsPerMinute = 10;

    /**
     * Constructor.
     *
     * @param array<string, mixed> $config Configuration options
     */
    public function __construct(array $config = [])
    {
        $this->maxPseudoHeaders = $config['max_pseudo_headers'] ?? 4;
        $this->maxHeaderListSize = $config['max_header_list_size'] ?? 16384;
        $this->maxHeaderSize = $config['max_header_size'] ?? 8192;
        $this->maxConcurrentStreams = $config['max_concurrent_streams'] ?? 100;
        $this->maxContinuationFrames = $config['max_continuation_frames'] ?? 5;
        $this->maxResetsPerMinute = $config['max_resets_per_minute'] ?? 100;
        $this->maxSettingsPerMinute = $config['max_settings_per_minute'] ?? 10;
    }

    /**
     * Analyze request for HTTP/2-specific attacks.
     *
     * @param array<string, string|array<string>> $headers Request headers
     * @param array<string, mixed> $serverMetrics Metrics from web server
     *
     * @return array{
     *     allowed: bool,
     *     attacks_detected: array<string>,
     *     risk_score: int,
     *     warnings: array<string>,
     *     recommendations: array<string>
     * }
     */
    public function analyze(array $headers, array $serverMetrics = []): array
    {
        $attacksDetected = [];
        $warnings = [];
        $recommendations = [];
        $riskScore = 0;

        // Determine if this is HTTP/2
        $isHttp2 = $this->isHttp2Request($headers, $serverMetrics);

        if (!$isHttp2) {
            return [
                'allowed' => true,
                'attacks_detected' => [],
                'risk_score' => 0,
                'warnings' => [],
                'recommendations' => [],
            ];
        }

        // Check 1: Header size analysis
        $headerSizeResult = $this->analyzeHeaderSize($headers);
        if ($headerSizeResult['suspicious']) {
            $attacksDetected[] = 'HPACK_BOMB';
            $riskScore += $headerSizeResult['risk'];
            $warnings[] = $headerSizeResult['warning'];
        }

        // Check 2: CONTINUATION flood (requires server metrics)
        if (isset($serverMetrics['continuation_frames'])) {
            $continuationFrames = (int) $serverMetrics['continuation_frames'];
            if ($continuationFrames > $this->maxContinuationFrames) {
                $attacksDetected[] = 'CONTINUATION_FLOOD';
                $riskScore += 50;
                $warnings[] = "Excessive CONTINUATION frames: {$continuationFrames}";
                $recommendations[] = 'CVE-2024-27983: Update your HTTP/2 server implementation';
            }
        }

        // Check 3: Rapid Reset (RST_STREAM flood)
        if (isset($serverMetrics['rst_stream_count'])) {
            $rstCount = (int) $serverMetrics['rst_stream_count'];
            if ($rstCount > $this->maxResetsPerMinute) {
                $attacksDetected[] = 'RAPID_RESET';
                $riskScore += 60;
                $warnings[] = "Excessive RST_STREAM frames: {$rstCount}/min";
                $recommendations[] = 'CVE-2023-44487: Implement RST_STREAM rate limiting';
            }
        }

        // Check 4: Settings flood
        if (isset($serverMetrics['settings_frames'])) {
            $settingsCount = (int) $serverMetrics['settings_frames'];
            if ($settingsCount > $this->maxSettingsPerMinute) {
                $attacksDetected[] = 'SETTINGS_FLOOD';
                $riskScore += 40;
                $warnings[] = "Excessive SETTINGS frames: {$settingsCount}/min";
            }
        }

        // Check 5: Stream count abuse
        if (isset($serverMetrics['concurrent_streams'])) {
            $streams = (int) $serverMetrics['concurrent_streams'];
            if ($streams > $this->maxConcurrentStreams) {
                $attacksDetected[] = 'STREAM_ABUSE';
                $riskScore += 30;
                $warnings[] = "Excessive concurrent streams: {$streams}";
            }
        }

        // Check 6: Pseudo-header anomalies
        $pseudoHeaderResult = $this->analyzePseudoHeaders($headers);
        if ($pseudoHeaderResult['suspicious']) {
            $attacksDetected[] = 'PSEUDO_HEADER_ABUSE';
            $riskScore += $pseudoHeaderResult['risk'];
            $warnings[] = $pseudoHeaderResult['warning'];
        }

        // Check 7: Priority manipulation
        if (isset($serverMetrics['priority_changes'])) {
            $priorityChanges = (int) $serverMetrics['priority_changes'];
            if ($priorityChanges > 50) {
                $attacksDetected[] = 'PRIORITY_MANIPULATION';
                $riskScore += 25;
                $warnings[] = "Excessive priority changes: {$priorityChanges}";
            }
        }

        // Check 8: Window update flood
        if (isset($serverMetrics['window_updates'])) {
            $windowUpdates = (int) $serverMetrics['window_updates'];
            if ($windowUpdates > 100) {
                $attacksDetected[] = 'WINDOW_UPDATE_FLOOD';
                $riskScore += 30;
                $warnings[] = "Excessive WINDOW_UPDATE frames: {$windowUpdates}";
            }
        }

        $allowed = empty($attacksDetected) || $riskScore < 50;

        return [
            'allowed' => $allowed,
            'attacks_detected' => $attacksDetected,
            'risk_score' => min(100, $riskScore),
            'warnings' => $warnings,
            'recommendations' => $recommendations,
        ];
    }

    /**
     * Detect if request is HTTP/2.
     *
     * @param array<string, string|array<string>> $headers
     * @param array<string, mixed> $serverMetrics
     */
    private function isHttp2Request(array $headers, array $serverMetrics): bool
    {
        // Check server-provided protocol info
        if (isset($serverMetrics['protocol'])) {
            return str_contains(strtolower($serverMetrics['protocol']), 'http/2')
                || $serverMetrics['protocol'] === 'h2';
        }

        // Check $_SERVER['SERVER_PROTOCOL'] equivalent
        if (isset($headers['x-forwarded-proto-version'])) {
            return str_contains($headers['x-forwarded-proto-version'], '2');
        }

        // Check for HTTP/2 pseudo-headers (these shouldn't appear in HTTP/1.x)
        $http2Indicators = [':method', ':path', ':scheme', ':authority'];
        foreach ($http2Indicators as $indicator) {
            if (isset($headers[$indicator])) {
                return true;
            }
        }

        return false;
    }

    /**
     * Analyze header sizes for HPACK bomb detection.
     *
     * @param array<string, string|array<string>> $headers
     *
     * @return array{suspicious: bool, risk: int, warning: string}
     */
    private function analyzeHeaderSize(array $headers): array
    {
        $totalSize = 0;
        $largeHeaders = [];

        foreach ($headers as $name => $value) {
            $valueStr = is_array($value) ? implode(', ', $value) : $value;
            $headerSize = strlen($name) + strlen($valueStr) + 32; // Overhead estimate

            if ($headerSize > $this->maxHeaderSize) {
                $largeHeaders[] = $name;
            }

            $totalSize += $headerSize;
        }

        $suspicious = false;
        $risk = 0;
        $warning = '';

        if ($totalSize > $this->maxHeaderListSize) {
            $suspicious = true;
            $risk = 40;
            $warning = "Total header size ({$totalSize} bytes) exceeds limit ({$this->maxHeaderListSize})";
        }

        if (!empty($largeHeaders)) {
            $suspicious = true;
            $risk = max($risk, 30);
            $warning .= ($warning ? '; ' : '') . 'Large headers: ' . implode(', ', $largeHeaders);
        }

        // Check for header count (many small headers can also be an attack)
        if (count($headers) > 100) {
            $suspicious = true;
            $risk = max($risk, 25);
            $warning .= ($warning ? '; ' : '') . 'Excessive header count: ' . count($headers);
        }

        return [
            'suspicious' => $suspicious,
            'risk' => $risk,
            'warning' => $warning ?: 'Headers within limits',
        ];
    }

    /**
     * Analyze HTTP/2 pseudo-headers.
     *
     * @param array<string, string|array<string>> $headers
     *
     * @return array{suspicious: bool, risk: int, warning: string}
     */
    private function analyzePseudoHeaders(array $headers): array
    {
        $pseudoHeaders = [];
        $suspicious = false;
        $risk = 0;
        $warnings = [];

        foreach ($headers as $name => $value) {
            if (str_starts_with($name, ':')) {
                $pseudoHeaders[$name] = $value;
            }
        }

        // Check for too many pseudo-headers
        if (count($pseudoHeaders) > $this->maxPseudoHeaders) {
            $suspicious = true;
            $risk += 20;
            $warnings[] = 'Too many pseudo-headers: ' . count($pseudoHeaders);
        }

        // Check for invalid pseudo-headers
        $validPseudoHeaders = [':method', ':path', ':scheme', ':authority', ':status'];
        foreach (array_keys($pseudoHeaders) as $name) {
            if (!in_array($name, $validPseudoHeaders, true)) {
                $suspicious = true;
                $risk += 30;
                $warnings[] = "Invalid pseudo-header: {$name}";
            }
        }

        // Check for duplicate pseudo-headers (not allowed in HTTP/2)
        foreach ($pseudoHeaders as $name => $value) {
            if (is_array($value) && count($value) > 1) {
                $suspicious = true;
                $risk += 40;
                $warnings[] = "Duplicate pseudo-header: {$name}";
            }
        }

        return [
            'suspicious' => $suspicious,
            'risk' => $risk,
            'warning' => empty($warnings) ? 'Pseudo-headers valid' : implode('; ', $warnings),
        ];
    }

    /**
     * Get recommended nginx configuration for HTTP/2 protection.
     *
     * @return string Nginx configuration snippet
     */
    public function getNginxConfig(): string
    {
        return <<<'NGINX'
            # HTTP/2 Security Configuration
            # Add this to your nginx.conf http{} block

            # Limit concurrent streams per connection
            http2_max_concurrent_streams 100;

            # Limit header size
            http2_max_header_size 16k;

            # Limit total size of request headers
            large_client_header_buffers 4 16k;

            # Connection timeout
            http2_idle_timeout 60s;

            # Limit receiving timeout
            http2_recv_timeout 30s;

            # For CVE-2023-44487 (Rapid Reset) mitigation:
            # Upgrade to nginx 1.25.3+ or apply the patch
            # limit_req_zone $binary_remote_addr zone=h2reset:10m rate=10r/s;

            # For CVE-2024-27983 (CONTINUATION Flood):
            # Upgrade your HTTP/2 implementation to latest version
            NGINX;
    }

    /**
     * Get recommended Apache configuration.
     *
     * @return string Apache configuration snippet
     */
    public function getApacheConfig(): string
    {
        return <<<'APACHE'
            # HTTP/2 Security Configuration for Apache
            # Requires mod_http2

            # Maximum concurrent streams per connection
            H2MaxSessionStreams 100

            # Maximum size for a request header
            LimitRequestFieldSize 8190

            # Maximum total size of request headers
            LimitRequestFields 100

            # Connection timeout
            H2SessionExtraFiles 5

            # For CVE-2023-44487 mitigation, upgrade to Apache 2.4.58+
            # For CVE-2024-27983 mitigation, upgrade to latest version
            APACHE;
    }

    /**
     * Set maximum header list size.
     */
    public function setMaxHeaderListSize(int $size): self
    {
        $this->maxHeaderListSize = $size;

        return $this;
    }

    /**
     * Set maximum concurrent streams.
     */
    public function setMaxConcurrentStreams(int $max): self
    {
        $this->maxConcurrentStreams = $max;

        return $this;
    }

    /**
     * Set maximum resets per minute.
     */
    public function setMaxResetsPerMinute(int $max): self
    {
        $this->maxResetsPerMinute = $max;

        return $this;
    }
}
