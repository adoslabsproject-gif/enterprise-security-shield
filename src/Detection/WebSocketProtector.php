<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Detection;

/**
 * WebSocket Security Protector.
 *
 * Validates WebSocket upgrade requests and detects abuse patterns:
 * - Invalid upgrade requests (protocol downgrade attacks)
 * - Cross-Site WebSocket Hijacking (CSWSH)
 * - Origin validation bypass attempts
 * - Connection flooding
 *
 * LIMITATIONS:
 * PHP cannot handle actual WebSocket frames - this protects the UPGRADE phase only.
 * For full WebSocket protection, use Swoole, ReactPHP, or dedicated WS servers.
 */
final class WebSocketProtector
{
    /**
     * Allowed WebSocket origins (domains).
     *
     * @var array<string>
     */
    private array $allowedOrigins = [];

    /**
     * Enable strict origin checking.
     */
    private bool $strictOrigin = true;

    /**
     * Required subprotocols (if any).
     *
     * @var array<string>
     */
    private array $allowedSubprotocols = [];

    /**
     * Maximum connections per IP.
     */
    private int $maxConnectionsPerIp = 10;

    /**
     * Constructor.
     *
     * @param array<string, mixed> $config Configuration options
     */
    public function __construct(array $config = [])
    {
        $this->allowedOrigins = $config['allowed_origins'] ?? [];
        $this->strictOrigin = $config['strict_origin'] ?? true;
        $this->allowedSubprotocols = $config['allowed_subprotocols'] ?? [];
        $this->maxConnectionsPerIp = $config['max_connections_per_ip'] ?? 10;
    }

    /**
     * Validate WebSocket upgrade request.
     *
     * @param array<string, string> $headers Request headers
     * @param string $origin Request origin
     * @param string $clientIp Client IP address
     * @param int $currentConnections Current connections from this IP
     *
     * @return array{
     *     valid: bool,
     *     errors: array<string>,
     *     warnings: array<string>,
     *     risk_score: int,
     *     recommended_action: string
     * }
     */
    public function validateUpgrade(
        array $headers,
        string $origin,
        string $clientIp,
        int $currentConnections = 0,
    ): array {
        $errors = [];
        $warnings = [];
        $riskScore = 0;

        // Normalize headers
        $headers = array_change_key_case($headers, CASE_LOWER);

        // Check 1: Verify this is actually an upgrade request
        $upgrade = $headers['upgrade'] ?? '';
        $connection = $headers['connection'] ?? '';

        if (strtolower($upgrade) !== 'websocket') {
            $errors[] = 'Invalid Upgrade header - must be "websocket"';
            $riskScore += 30;
        }

        if (!str_contains(strtolower($connection), 'upgrade')) {
            $errors[] = 'Connection header must contain "Upgrade"';
            $riskScore += 20;
        }

        // Check 2: WebSocket version
        $wsVersion = $headers['sec-websocket-version'] ?? '';
        if ($wsVersion !== '13') {
            $errors[] = "Unsupported WebSocket version: {$wsVersion} (expected 13)";
            $riskScore += 25;
        }

        // Check 3: WebSocket key (must be 16 bytes base64 encoded = 24 chars)
        $wsKey = $headers['sec-websocket-key'] ?? '';
        if ($wsKey === '') {
            $errors[] = 'Missing Sec-WebSocket-Key header';
            $riskScore += 40;
        } elseif (strlen(base64_decode($wsKey, true) ?: '') !== 16) {
            $errors[] = 'Invalid Sec-WebSocket-Key format';
            $riskScore += 35;
        }

        // Check 4: Origin validation (CSWSH protection)
        if ($this->strictOrigin && !empty($this->allowedOrigins)) {
            if (!$this->isOriginAllowed($origin)) {
                $errors[] = "Origin not allowed: {$origin}";
                $riskScore += 50;
            }
        } elseif ($origin === '') {
            $warnings[] = 'No Origin header - possible non-browser client';
            $riskScore += 10;
        }

        // Check 5: Subprotocol validation
        $requestedProtocols = $headers['sec-websocket-protocol'] ?? '';
        if ($requestedProtocols !== '' && !empty($this->allowedSubprotocols)) {
            $protocols = array_map('trim', explode(',', $requestedProtocols));
            $validProtocol = false;

            foreach ($protocols as $protocol) {
                if (in_array($protocol, $this->allowedSubprotocols, true)) {
                    $validProtocol = true;
                    break;
                }
            }

            if (!$validProtocol) {
                $errors[] = 'No allowed subprotocol requested. Allowed: ' . implode(', ', $this->allowedSubprotocols);
                $riskScore += 20;
            }
        }

        // Check 6: Connection limit per IP
        if ($currentConnections >= $this->maxConnectionsPerIp) {
            $errors[] = "Connection limit exceeded for IP {$clientIp} ({$currentConnections}/{$this->maxConnectionsPerIp})";
            $riskScore += 40;
        } elseif ($currentConnections >= $this->maxConnectionsPerIp * 0.8) {
            $warnings[] = "Approaching connection limit ({$currentConnections}/{$this->maxConnectionsPerIp})";
            $riskScore += 15;
        }

        // Check 7: Extensions validation
        $extensions = $headers['sec-websocket-extensions'] ?? '';
        if ($extensions !== '') {
            $dangerousExtensions = $this->checkDangerousExtensions($extensions);
            if (!empty($dangerousExtensions)) {
                $warnings[] = 'Potentially dangerous extensions: ' . implode(', ', $dangerousExtensions);
                $riskScore += 15;
            }
        }

        // Check 8: Host header validation
        $host = $headers['host'] ?? '';
        if ($host === '') {
            $errors[] = 'Missing Host header';
            $riskScore += 20;
        }

        // Calculate final result
        $valid = empty($errors);
        $recommendedAction = $this->getRecommendedAction($riskScore, $valid);

        return [
            'valid' => $valid,
            'errors' => $errors,
            'warnings' => $warnings,
            'risk_score' => min(100, $riskScore),
            'recommended_action' => $recommendedAction,
        ];
    }

    /**
     * Generate WebSocket accept key for handshake.
     *
     * @param string $clientKey Sec-WebSocket-Key from client
     *
     * @return string Accept key for Sec-WebSocket-Accept header
     */
    public function generateAcceptKey(string $clientKey): string
    {
        // RFC 6455 GUID
        $guid = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

        return base64_encode(sha1($clientKey . $guid, true));
    }

    /**
     * Check if origin is allowed.
     */
    private function isOriginAllowed(string $origin): bool
    {
        if (empty($this->allowedOrigins)) {
            return true;
        }

        $originHost = parse_url($origin, PHP_URL_HOST);
        if ($originHost === null || $originHost === false) {
            return false;
        }

        foreach ($this->allowedOrigins as $allowed) {
            // Exact match
            if ($originHost === $allowed) {
                return true;
            }

            // Wildcard subdomain match (*.example.com)
            if (str_starts_with($allowed, '*.')) {
                $domain = substr($allowed, 2);
                if ($originHost === $domain || str_ends_with($originHost, '.' . $domain)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check for potentially dangerous WebSocket extensions.
     *
     * @return array<string>
     */
    private function checkDangerousExtensions(string $extensions): array
    {
        $dangerous = [];
        $parts = array_map('trim', explode(',', strtolower($extensions)));

        // permessage-deflate is generally safe but can be used for CRIME-like attacks
        // if compression is used with sensitive data
        foreach ($parts as $ext) {
            $extName = explode(';', $ext)[0];

            // Unknown extensions could be malicious
            $knownExtensions = ['permessage-deflate', 'x-webkit-deflate-frame'];
            if (!in_array($extName, $knownExtensions, true)) {
                $dangerous[] = $extName;
            }
        }

        return $dangerous;
    }

    /**
     * Get recommended action based on risk score.
     */
    private function getRecommendedAction(int $riskScore, bool $valid): string
    {
        if (!$valid) {
            return 'REJECT: Invalid WebSocket upgrade request';
        }

        if ($riskScore >= 50) {
            return 'REJECT: High risk score - possible attack';
        }

        if ($riskScore >= 30) {
            return 'CHALLENGE: Request additional verification';
        }

        if ($riskScore >= 10) {
            return 'MONITOR: Log and monitor this connection';
        }

        return 'ALLOW: Request appears legitimate';
    }

    /**
     * Detect Cross-Site WebSocket Hijacking (CSWSH) attack.
     *
     * @param string $origin Request origin
     * @param string $referer Request referer
     * @param string $host Request host
     *
     * @return array{
     *     detected: bool,
     *     confidence: float,
     *     reason: string
     * }
     */
    public function detectCSWSH(string $origin, string $referer, string $host): array
    {
        $originHost = parse_url($origin, PHP_URL_HOST);
        $refererHost = parse_url($referer, PHP_URL_HOST);

        // No origin = possible attack from non-browser or privacy extension
        if ($originHost === null || $originHost === false) {
            return [
                'detected' => false,
                'confidence' => 0.3,
                'reason' => 'No origin header - may be non-browser client',
            ];
        }

        // Origin doesn't match host
        if ($originHost !== $host && !str_ends_with($originHost, '.' . $host)) {
            return [
                'detected' => true,
                'confidence' => 0.9,
                'reason' => "Origin ({$originHost}) does not match host ({$host})",
            ];
        }

        // Referer from different domain
        if ($refererHost !== null && $refererHost !== $host) {
            return [
                'detected' => true,
                'confidence' => 0.7,
                'reason' => "Referer ({$refererHost}) does not match host ({$host})",
            ];
        }

        return [
            'detected' => false,
            'confidence' => 0.0,
            'reason' => 'Origin matches host - request appears legitimate',
        ];
    }

    /**
     * Add allowed origin.
     */
    public function addAllowedOrigin(string $origin): self
    {
        $this->allowedOrigins[] = $origin;

        return $this;
    }

    /**
     * Add allowed subprotocol.
     */
    public function addAllowedSubprotocol(string $protocol): self
    {
        $this->allowedSubprotocols[] = $protocol;

        return $this;
    }

    /**
     * Set maximum connections per IP.
     */
    public function setMaxConnectionsPerIp(int $max): self
    {
        $this->maxConnectionsPerIp = $max;

        return $this;
    }
}
