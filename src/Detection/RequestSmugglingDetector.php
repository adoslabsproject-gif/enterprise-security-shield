<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Detection;

/**
 * HTTP Request Smuggling Detector.
 *
 * Detects CL.TE, TE.CL, and TE.TE request smuggling attacks.
 * These attacks exploit discrepancies in how front-end and back-end
 * servers parse HTTP requests with ambiguous Content-Length and
 * Transfer-Encoding headers.
 *
 * ATTACK TYPES:
 * - CL.TE: Front-end uses Content-Length, back-end uses Transfer-Encoding
 * - TE.CL: Front-end uses Transfer-Encoding, back-end uses Content-Length
 * - TE.TE: Both use Transfer-Encoding but parse obfuscation differently
 *
 * @see https://portswigger.net/web-security/request-smuggling
 */
final class RequestSmugglingDetector
{
    /**
     * Obfuscated Transfer-Encoding patterns.
     *
     * @var array<string>
     */
    private const TE_OBFUSCATION_PATTERNS = [
        '/transfer-encoding\s*:\s*chunked/i',
        '/transfer-encoding\s*:\s*\x00chunked/i',        // Null byte
        '/transfer-encoding\s*:\s*chunked\s*,/i',        // Trailing comma
        '/transfer-encoding\s*:\s*,\s*chunked/i',        // Leading comma
        '/transfer-encoding\s*:\s*chunked\s+/i',         // Trailing space
        '/transfer-encoding\s*:\s*\tchunked/i',          // Tab before
        '/transfer-encoding\s*:\s*chunked\t/i',          // Tab after
        '/transfer-encoding\s*:\s*x\s*,\s*chunked/i',    // Invalid value before
        '/transfer-encoding\s*:\s*chunked\s*;\s*x/i',    // Parameter after
        '/transfer[\s\-_]encoding/i',                     // Variations
        '/x-transfer-encoding/i',                         // X- prefix
    ];

    /**
     * Dangerous header combinations.
     *
     * @var array<array{headers: array<string>, severity: string, description: string}>
     */
    private const DANGEROUS_COMBINATIONS = [
        [
            'headers' => ['content-length', 'transfer-encoding'],
            'severity' => 'CRITICAL',
            'description' => 'Both CL and TE headers present - possible CL.TE or TE.CL attack',
        ],
        [
            'headers' => ['content-length', 'content-length'],
            'severity' => 'HIGH',
            'description' => 'Duplicate Content-Length headers - request smuggling attempt',
        ],
        [
            'headers' => ['transfer-encoding', 'transfer-encoding'],
            'severity' => 'HIGH',
            'description' => 'Duplicate Transfer-Encoding headers - TE.TE attack',
        ],
    ];

    /**
     * Detect request smuggling attempts.
     *
     * @param array<string, string|array<string>> $headers Request headers
     * @param string $rawRequest Raw HTTP request (optional, for deep analysis)
     *
     * @return array{
     *     detected: bool,
     *     confidence: float,
     *     attack_type: string|null,
     *     findings: array<array{type: string, severity: string, description: string}>,
     *     recommendation: string
     * }
     */
    public function detect(array $headers, string $rawRequest = ''): array
    {
        $findings = [];
        $confidence = 0.0;
        $attackType = null;

        // Normalize header names to lowercase
        $normalizedHeaders = [];
        $headerCounts = [];

        foreach ($headers as $name => $value) {
            $lowerName = strtolower($name);
            $normalizedHeaders[$lowerName] = $value;

            // Count header occurrences
            if (!isset($headerCounts[$lowerName])) {
                $headerCounts[$lowerName] = 0;
            }
            $headerCounts[$lowerName]++;
        }

        // Check 1: Both CL and TE present (CRITICAL)
        $hasCL = isset($normalizedHeaders['content-length']);
        $hasTE = isset($normalizedHeaders['transfer-encoding']);

        if ($hasCL && $hasTE) {
            $confidence = max($confidence, 0.95);
            $attackType = 'CL_TE_CONFLICT';
            $findings[] = [
                'type' => 'CL_TE_CONFLICT',
                'severity' => 'CRITICAL',
                'description' => 'Both Content-Length and Transfer-Encoding headers present',
            ];
        }

        // Check 2: Duplicate headers
        foreach ($headerCounts as $name => $count) {
            if ($count > 1) {
                if ($name === 'content-length') {
                    $confidence = max($confidence, 0.90);
                    $attackType ??= 'DUPLICATE_CL';
                    $findings[] = [
                        'type' => 'DUPLICATE_CL',
                        'severity' => 'HIGH',
                        'description' => "Duplicate Content-Length headers ({$count} occurrences)",
                    ];
                } elseif ($name === 'transfer-encoding') {
                    $confidence = max($confidence, 0.90);
                    $attackType ??= 'DUPLICATE_TE';
                    $findings[] = [
                        'type' => 'DUPLICATE_TE',
                        'severity' => 'HIGH',
                        'description' => "Duplicate Transfer-Encoding headers ({$count} occurrences)",
                    ];
                }
            }
        }

        // Check 3: TE obfuscation patterns
        if ($hasTE) {
            $teValue = $normalizedHeaders['transfer-encoding'];
            $teString = is_array($teValue) ? implode(', ', $teValue) : $teValue;

            // Check for obfuscation
            if ($this->isObfuscatedTE($teString)) {
                $confidence = max($confidence, 0.85);
                $attackType ??= 'TE_OBFUSCATION';
                $findings[] = [
                    'type' => 'TE_OBFUSCATION',
                    'severity' => 'HIGH',
                    'description' => 'Obfuscated Transfer-Encoding value detected',
                ];
            }

            // Check for invalid TE values
            if (!$this->isValidTE($teString)) {
                $confidence = max($confidence, 0.75);
                $findings[] = [
                    'type' => 'INVALID_TE',
                    'severity' => 'MEDIUM',
                    'description' => 'Invalid Transfer-Encoding value',
                ];
            }
        }

        // Check 4: CL value anomalies
        if ($hasCL) {
            $clValue = $normalizedHeaders['content-length'];
            $clString = is_array($clValue) ? $clValue[0] : $clValue;

            // Negative or non-numeric
            if (!ctype_digit($clString) || (int) $clString < 0) {
                $confidence = max($confidence, 0.80);
                $findings[] = [
                    'type' => 'INVALID_CL',
                    'severity' => 'HIGH',
                    'description' => 'Invalid Content-Length value: ' . substr($clString, 0, 20),
                ];
            }

            // Extremely large CL (potential DoS)
            if (ctype_digit($clString) && (int) $clString > 10 * 1024 * 1024) {
                $confidence = max($confidence, 0.60);
                $findings[] = [
                    'type' => 'LARGE_CL',
                    'severity' => 'MEDIUM',
                    'description' => 'Unusually large Content-Length: ' . $clString,
                ];
            }
        }

        // Check 5: Raw request analysis (if provided)
        if ($rawRequest !== '') {
            $rawFindings = $this->analyzeRawRequest($rawRequest);
            $findings = array_merge($findings, $rawFindings);

            if (!empty($rawFindings)) {
                $confidence = max($confidence, 0.85);
            }
        }

        // Check 6: Suspicious header variations
        foreach ($normalizedHeaders as $name => $value) {
            // Check for header name obfuscation
            if (preg_match('/^(content[\s\-_]?length|transfer[\s\-_]?encoding)$/i', $name) && $name !== strtolower($name)) {
                $confidence = max($confidence, 0.70);
                $findings[] = [
                    'type' => 'HEADER_OBFUSCATION',
                    'severity' => 'MEDIUM',
                    'description' => "Suspicious header name format: {$name}",
                ];
            }
        }

        $detected = $confidence >= 0.5;

        return [
            'detected' => $detected,
            'confidence' => round($confidence * 100, 1),
            'attack_type' => $attackType,
            'findings' => $findings,
            'recommendation' => $this->getRecommendation($attackType, $confidence),
        ];
    }

    /**
     * Check if Transfer-Encoding value is obfuscated.
     */
    private function isObfuscatedTE(string $value): bool
    {
        // Normal value is just "chunked" or "identity"
        $normalized = strtolower(trim($value));

        if ($normalized === 'chunked' || $normalized === 'identity') {
            return false;
        }

        // Check for known obfuscation patterns
        foreach (self::TE_OBFUSCATION_PATTERNS as $pattern) {
            if (preg_match($pattern, $value)) {
                return true;
            }
        }

        // Check for whitespace obfuscation
        if (preg_match('/\s{2,}/', $value)) {
            return true;
        }

        // Check for null bytes or control characters
        if (preg_match('/[\x00-\x08\x0b\x0c\x0e-\x1f]/', $value)) {
            return true;
        }

        return false;
    }

    /**
     * Check if Transfer-Encoding value is valid.
     */
    private function isValidTE(string $value): bool
    {
        $validValues = ['chunked', 'compress', 'deflate', 'gzip', 'identity'];
        $parts = array_map('trim', explode(',', strtolower($value)));

        foreach ($parts as $part) {
            // Remove parameters (e.g., "chunked;q=1.0")
            $part = preg_replace('/;.*$/', '', $part);

            if ($part !== '' && !in_array($part, $validValues, true)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Analyze raw HTTP request for smuggling indicators.
     *
     * @return array<array{type: string, severity: string, description: string}>
     */
    private function analyzeRawRequest(string $rawRequest): array
    {
        $findings = [];

        // Check for CRLF variations
        if (str_contains($rawRequest, "\r\n\r\n") && str_contains($rawRequest, "\n\n")) {
            $findings[] = [
                'type' => 'MIXED_LINE_ENDINGS',
                'severity' => 'HIGH',
                'description' => 'Mixed CRLF and LF line endings detected',
            ];
        }

        // Check for embedded requests
        if (preg_match('/(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\/[^\r\n]*HTTP\//', $rawRequest, $matches, PREG_OFFSET_CAPTURE)) {
            $firstMatch = $matches[0][1];
            if ($firstMatch > 0) {
                // Found HTTP method not at the start
                $findings[] = [
                    'type' => 'EMBEDDED_REQUEST',
                    'severity' => 'CRITICAL',
                    'description' => 'Possible embedded HTTP request detected',
                ];
            }
        }

        // Check for chunked encoding issues
        if (preg_match('/\r\n0\r\n\r\n/s', $rawRequest) && preg_match('/[^\r]\n0\n\n/s', $rawRequest)) {
            $findings[] = [
                'type' => 'CHUNKED_TERMINATOR_MISMATCH',
                'severity' => 'HIGH',
                'description' => 'Inconsistent chunked encoding terminators',
            ];
        }

        // Check for chunk size manipulation
        if (preg_match('/[\r\n][0-9a-fA-F]+[\s;][^\r\n]*\r\n/', $rawRequest)) {
            $findings[] = [
                'type' => 'CHUNK_EXTENSION',
                'severity' => 'MEDIUM',
                'description' => 'Chunk extension detected (potential obfuscation)',
            ];
        }

        return $findings;
    }

    /**
     * Get recommendation based on attack type.
     */
    private function getRecommendation(?string $attackType, float $confidence): string
    {
        if ($confidence < 0.5) {
            return 'No action required - request appears normal';
        }

        return match ($attackType) {
            'CL_TE_CONFLICT' => 'BLOCK: Reject requests with both Content-Length and Transfer-Encoding headers',
            'DUPLICATE_CL', 'DUPLICATE_TE' => 'BLOCK: Reject requests with duplicate length/encoding headers',
            'TE_OBFUSCATION' => 'BLOCK: Transfer-Encoding obfuscation is a strong smuggling indicator',
            'EMBEDDED_REQUEST' => 'BLOCK: Embedded HTTP request detected - confirmed smuggling attempt',
            default => 'INVESTIGATE: Review request for potential smuggling attempt',
        };
    }

    /**
     * Sanitize request by normalizing headers.
     *
     * Returns sanitized headers that are safe from smuggling attacks.
     *
     * @param array<string, string|array<string>> $headers
     *
     * @return array<string, string>
     */
    public function sanitize(array $headers): array
    {
        $sanitized = [];

        foreach ($headers as $name => $value) {
            $lowerName = strtolower(trim($name));

            // Skip if already processed (handles duplicates)
            if (isset($sanitized[$lowerName])) {
                continue;
            }

            // Use first value if array
            $stringValue = is_array($value) ? $value[0] : $value;

            // Remove null bytes and control characters
            $stringValue = preg_replace('/[\x00-\x08\x0b\x0c\x0e-\x1f]/', '', $stringValue);

            // Normalize whitespace
            $stringValue = preg_replace('/\s+/', ' ', trim($stringValue));

            $sanitized[$lowerName] = $stringValue;
        }

        // If both CL and TE exist, prefer TE (RFC 7230 compliance)
        if (isset($sanitized['content-length']) && isset($sanitized['transfer-encoding'])) {
            unset($sanitized['content-length']);
        }

        return $sanitized;
    }
}
