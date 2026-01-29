<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Detection;

use AdosLabs\EnterpriseSecurityShield\Detection\Parser\XSSAnalyzer;

/**
 * Advanced XSS Detector
 *
 * Enterprise-grade XSS detection using real HTML/JS parsing.
 * This replaces regex-based detection with actual context-aware analysis.
 *
 * CAPABILITIES:
 * - Parses HTML structure
 * - Identifies script contexts
 * - Detects event handlers (200+ handlers)
 * - Handles encoding bypasses
 * - Recognizes SVG/MathML XSS
 * - Detects template injection
 * - Identifies DOM clobbering
 *
 * @version 2.0.0
 */
final class AdvancedXSSDetector
{
    private XSSAnalyzer $analyzer;
    private float $threshold;

    public function __construct(float $threshold = 0.5)
    {
        $this->analyzer = new XSSAnalyzer();
        $this->threshold = $threshold;
    }

    /**
     * Detect XSS in input
     *
     * @param string $input User input to analyze
     * @return array{
     *     detected: bool,
     *     confidence: float,
     *     risk_level: string,
     *     attack_type: string|null,
     *     evidence: array<string>,
     *     vectors: array<array{type: string, payload: string, confidence: float}>
     * }
     */
    public function detect(string $input): array
    {
        $result = $this->analyzer->analyze($input);

        return [
            'detected' => $result['detected'] && $result['confidence'] >= $this->threshold,
            'confidence' => $result['confidence'] * 100, // Convert to percentage
            'risk_level' => $result['risk_level'],
            'attack_type' => $result['attack_type'],
            'evidence' => $result['evidence'],
            'vectors' => $result['vectors'],
        ];
    }

    /**
     * Detect XSS in multiple inputs (batch)
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
     * @return bool True if XSS detected
     */
    public function isXSS(string $input): bool
    {
        return $this->detect($input)['detected'];
    }

    /**
     * Sanitize input by removing dangerous content
     *
     * WARNING: Sanitization is NOT recommended as primary defense.
     * Use output encoding instead. This is for legacy compatibility only.
     *
     * @param string $input Input to sanitize
     * @return string Sanitized input
     */
    public function sanitize(string $input): string
    {
        // Remove script tags completely
        $output = preg_replace('/<\s*script[^>]*>.*?<\s*\/\s*script\s*>/is', '', $input) ?? $input;

        // Remove event handlers
        $output = preg_replace('/\s+on\w+\s*=\s*["\'][^"\']*["\']/i', '', $output) ?? $output;
        $output = preg_replace('/\s+on\w+\s*=\s*[^\s>]*/i', '', $output) ?? $output;

        // Remove javascript: URIs
        $output = preg_replace('/javascript\s*:/i', '', $output) ?? $output;

        // Remove data: URIs with HTML/script content
        $output = preg_replace('/data\s*:\s*text\/html[^"\'>\s]*/i', '', $output) ?? $output;

        // Encode remaining special characters
        return htmlspecialchars($output, ENT_QUOTES | ENT_HTML5, 'UTF-8', false);
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
     * Get analyzer instance (for advanced use)
     */
    public function getAnalyzer(): XSSAnalyzer
    {
        return $this->analyzer;
    }
}
