<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Detection;

use AdosLabs\EnterpriseSecurityShield\Detection\Parser\SQLInjectionAnalyzer;
use AdosLabs\EnterpriseSecurityShield\Detection\Parser\SQLTokenizer;

/**
 * Advanced SQL Injection Detector
 *
 * Enterprise-grade SQLi detection using real lexical analysis.
 * This replaces regex-based detection with actual SQL parsing.
 *
 * CAPABILITIES:
 * - Tokenizes SQL to understand structure
 * - Detects UNION, boolean, time-based, error-based attacks
 * - Handles encoding bypasses (URL, hex, unicode)
 * - Recognizes stacked queries
 * - Identifies dangerous functions
 *
 * @version 2.0.0
 */
final class AdvancedSQLiDetector
{
    private SQLInjectionAnalyzer $analyzer;
    private float $threshold;

    public function __construct(float $threshold = 0.5)
    {
        $this->analyzer = new SQLInjectionAnalyzer(new SQLTokenizer());
        $this->threshold = $threshold;
    }

    /**
     * Detect SQL injection in input
     *
     * @param string $input User input to analyze
     * @return array{
     *     detected: bool,
     *     confidence: float,
     *     risk_level: string,
     *     attack_type: string|null,
     *     evidence: array<string>,
     *     fingerprint: string|null
     * }
     */
    public function detect(string $input): array
    {
        $result = $this->analyzer->analyze($input);

        // Add fingerprint for tracking
        $fingerprint = null;
        if ($result['detected']) {
            $fingerprint = $this->generateFingerprint($input, $result);
        }

        return [
            'detected' => $result['detected'] && $result['confidence'] >= $this->threshold,
            'confidence' => $result['confidence'] * 100, // Convert to percentage
            'risk_level' => $result['risk_level'],
            'attack_type' => $result['attack_type'],
            'evidence' => $result['evidence'],
            'fingerprint' => $fingerprint,
        ];
    }

    /**
     * Detect SQLi in multiple inputs (batch)
     *
     * @param array<string, string> $inputs Key => value pairs to check
     * @return array{
     *     detected: bool,
     *     total_checked: int,
     *     threats_found: int,
     *     max_confidence: float,
     *     details: array<string, array>
     * }
     */
    public function detectBatch(array $inputs): array
    {
        $detected = false;
        $threatsFound = 0;
        $maxConfidence = 0.0;
        $details = [];

        foreach ($inputs as $key => $value) {
            if (!is_string($value)) {
                continue;
            }

            $result = $this->detect($value);
            $details[$key] = $result;

            if ($result['detected']) {
                $detected = true;
                $threatsFound++;
                $maxConfidence = max($maxConfidence, $result['confidence']);
            }
        }

        return [
            'detected' => $detected,
            'total_checked' => count($inputs),
            'threats_found' => $threatsFound,
            'max_confidence' => $maxConfidence,
            'details' => $details,
        ];
    }

    /**
     * Quick check (for high-performance scenarios)
     *
     * @param string $input Input to check
     * @return bool True if SQLi detected
     */
    public function isInjection(string $input): bool
    {
        return $this->detect($input)['detected'];
    }

    /**
     * Set detection threshold
     *
     * @param float $threshold 0.0 to 1.0
     */
    public function setThreshold(float $threshold): self
    {
        $this->threshold = max(0.0, min(1.0, $threshold));
        return $this;
    }

    /**
     * Generate attack fingerprint for tracking
     */
    private function generateFingerprint(string $input, array $result): string
    {
        $data = [
            'type' => $result['attack_type'] ?? 'unknown',
            'tokens' => $result['tokens_analyzed'] ?? 0,
            'len' => strlen($input),
        ];

        // Add hash of dangerous tokens
        if (!empty($result['dangerous_tokens'])) {
            $tokenStr = implode('|', array_map(
                fn($t) => $t['type'] . ':' . strtoupper($t['value']),
                array_slice($result['dangerous_tokens'], 0, 5)
            ));
            $data['sig'] = hash('xxh3', $tokenStr);
        }

        return 'sqli_' . hash('xxh3', json_encode($data));
    }

    /**
     * Get analyzer instance (for advanced use)
     */
    public function getAnalyzer(): SQLInjectionAnalyzer
    {
        return $this->analyzer;
    }
}
