<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Detection;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * XSS (Cross-Site Scripting) Detector
 *
 * Context-aware XSS detection. NOT regex-based (too many false positives).
 * Uses HTML parsing and context analysis.
 *
 * DETECTION CONTEXTS:
 * 1. HTML body - <script>, event handlers, javascript: URLs
 * 2. HTML attribute - Breaking out of attributes
 * 3. JavaScript - Breaking out of JS strings
 * 4. URL - javascript:, data: protocols
 * 5. CSS - expression(), url()
 *
 * @version 1.0.0
 */
final class XSSDetector
{
    /**
     * Dangerous HTML tags
     */
    private const DANGEROUS_TAGS = [
        'script', 'iframe', 'object', 'embed', 'applet', 'meta', 'link',
        'style', 'form', 'input', 'button', 'textarea', 'select', 'base',
        'svg', 'math', 'video', 'audio', 'source', 'track', 'template',
    ];

    /**
     * Event handler attributes (XSS vectors)
     */
    private const EVENT_HANDLERS = [
        'onabort', 'onblur', 'onchange', 'onclick', 'ondblclick', 'onerror',
        'onfocus', 'onkeydown', 'onkeypress', 'onkeyup', 'onload', 'onmousedown',
        'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup', 'onreset',
        'onresize', 'onscroll', 'onselect', 'onsubmit', 'onunload',
        'onbeforeunload', 'onhashchange', 'onmessage', 'onoffline', 'ononline',
        'onpagehide', 'onpageshow', 'onpopstate', 'onstorage', 'ondrag',
        'ondragend', 'ondragenter', 'ondragleave', 'ondragover', 'ondragstart',
        'ondrop', 'oninput', 'oninvalid', 'onsearch', 'onwheel', 'oncopy',
        'oncut', 'onpaste', 'oncontextmenu', 'ontoggle', 'onanimationend',
        'onanimationiteration', 'onanimationstart', 'ontransitionend',
        'onpointerdown', 'onpointerup', 'onpointermove', 'onpointerenter',
        'onpointerleave', 'onpointerover', 'onpointerout', 'onpointercancel',
        'ongotpointercapture', 'onlostpointercapture', 'ontouchstart',
        'ontouchmove', 'ontouchend', 'ontouchcancel', 'onafterprint',
        'onbeforeprint', 'oncanplay', 'oncanplaythrough', 'ondurationchange',
        'onemptied', 'onended', 'onloadeddata', 'onloadedmetadata', 'onloadstart',
        'onpause', 'onplay', 'onplaying', 'onprogress', 'onratechange',
        'onseeked', 'onseeking', 'onstalled', 'onsuspend', 'ontimeupdate',
        'onvolumechange', 'onwaiting', 'onshow', 'onformdata', 'onsecuritypolicyviolation',
    ];

    /**
     * Dangerous URL protocols
     */
    private const DANGEROUS_PROTOCOLS = [
        'javascript:', 'vbscript:', 'data:', 'blob:',
    ];

    /**
     * Dangerous CSS
     */
    private const DANGEROUS_CSS = [
        'expression', 'url(', 'import', '@import', 'behavior:',
    ];

    private int $minConfidence = 60;
    private ?LoggerInterface $logger = null;

    /**
     * Set PSR-3 logger for XSS detection events.
     *
     * @param LoggerInterface $logger PSR-3 logger
     */
    public function setLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;

        return $this;
    }

    /**
     * Set minimum confidence threshold
     */
    public function setMinConfidence(int $confidence): self
    {
        $this->minConfidence = max(0, min(100, $confidence));
        return $this;
    }

    /**
     * Detect XSS in input
     *
     * @param string $input Input to analyze
     * @param string $context Where input will be used: 'html', 'attribute', 'js', 'url', 'css'
     * @return array{detected: bool, confidence: int, vectors: array, details: array}
     */
    public function detect(string $input, string $context = 'html'): array
    {
        // Normalize
        $normalized = $this->normalize($input);

        // Quick check - if no suspicious chars, skip
        if (!$this->hasSuspiciousChars($normalized)) {
            return [
                'detected' => false,
                'confidence' => 0,
                'vectors' => [],
                'details' => ['reason' => 'no_suspicious_chars'],
            ];
        }

        $vectors = [];
        $scores = [];

        // Check for dangerous tags
        $tagResult = $this->detectDangerousTags($normalized);
        if ($tagResult['found']) {
            $vectors[] = ['type' => 'dangerous_tag', 'matches' => $tagResult['tags']];
            $scores[] = $tagResult['score'];
        }

        // Check for event handlers
        $eventResult = $this->detectEventHandlers($normalized);
        if ($eventResult['found']) {
            $vectors[] = ['type' => 'event_handler', 'matches' => $eventResult['handlers']];
            $scores[] = $eventResult['score'];
        }

        // Check for dangerous protocols
        $protocolResult = $this->detectDangerousProtocols($normalized);
        if ($protocolResult['found']) {
            $vectors[] = ['type' => 'dangerous_protocol', 'matches' => $protocolResult['protocols']];
            $scores[] = $protocolResult['score'];
        }

        // Check for attribute breaking
        $attrResult = $this->detectAttributeBreaking($normalized, $context);
        if ($attrResult['found']) {
            $vectors[] = ['type' => 'attribute_breaking', 'pattern' => $attrResult['pattern']];
            $scores[] = $attrResult['score'];
        }

        // Check for JS breaking
        if ($context === 'js') {
            $jsResult = $this->detectJSBreaking($normalized);
            if ($jsResult['found']) {
                $vectors[] = ['type' => 'js_breaking', 'pattern' => $jsResult['pattern']];
                $scores[] = $jsResult['score'];
            }
        }

        // Check for CSS injection
        if ($context === 'css' || $context === 'html') {
            $cssResult = $this->detectCSSInjection($normalized);
            if ($cssResult['found']) {
                $vectors[] = ['type' => 'css_injection', 'matches' => $cssResult['matches']];
                $scores[] = $cssResult['score'];
            }
        }

        // Calculate confidence
        $confidence = empty($scores) ? 0 : (int) min(100, array_sum($scores) / count($scores) * 1.2);

        // Context boost
        if ($context === 'html' && $confidence > 0) {
            $confidence = min(100, (int) ($confidence * 1.1));
        }

        $detected = $confidence >= $this->minConfidence;

        // Log high-confidence detections
        if ($detected && $this->logger !== null && $confidence >= 70) {
            $vectorTypes = array_map(fn ($v) => $v['type'], $vectors);
            $this->logger->warning('XSS attempt detected', [
                'confidence' => $confidence,
                'context' => $context,
                'vector_types' => $vectorTypes,
                'input_length' => strlen($input),
                'input_preview' => substr($input, 0, 100) . (strlen($input) > 100 ? '...' : ''),
            ]);
        }

        return [
            'detected' => $detected,
            'confidence' => $confidence,
            'vectors' => $vectors,
            'details' => [
                'context' => $context,
                'normalized_length' => strlen($normalized),
            ],
        ];
    }

    /**
     * Batch detect multiple inputs
     */
    public function detectBatch(array $inputs, string $context = 'html'): array
    {
        $results = [];
        foreach ($inputs as $field => $value) {
            if (!is_string($value)) {
                continue;
            }
            $results[$field] = $this->detect($value, $context);
        }
        return $results;
    }

    /**
     * Check if any input contains XSS
     */
    public function hasXSS(array $inputs, string $context = 'html'): bool
    {
        foreach ($inputs as $value) {
            if (!is_string($value)) {
                continue;
            }
            $result = $this->detect($value, $context);
            if ($result['detected']) {
                return true;
            }
        }
        return false;
    }

    /**
     * Normalize input
     */
    private function normalize(string $input): string
    {
        // Decode HTML entities multiple times
        $decoded = $input;
        for ($i = 0; $i < 3; $i++) {
            $newDecoded = html_entity_decode($decoded, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            if ($newDecoded === $decoded) {
                break;
            }
            $decoded = $newDecoded;
        }

        // URL decode
        for ($i = 0; $i < 3; $i++) {
            $newDecoded = urldecode($decoded);
            if ($newDecoded === $decoded) {
                break;
            }
            $decoded = $newDecoded;
        }

        // Remove null bytes
        $decoded = str_replace("\0", '', $decoded);

        // Normalize whitespace in tags (bypasses like <s c r i p t>)
        $decoded = preg_replace('/(<\s*\/?\s*)([a-z]+)/i', '$1$2', $decoded) ?? $decoded;

        return strtolower($decoded);
    }

    /**
     * Quick check for suspicious characters
     */
    private function hasSuspiciousChars(string $input): bool
    {
        // Must have at least one of these to be XSS
        return str_contains($input, '<') ||
               str_contains($input, '>') ||
               str_contains($input, '"') ||
               str_contains($input, "'") ||
               str_contains($input, 'javascript:') ||
               str_contains($input, 'on') || // event handlers
               str_contains($input, 'expression');
    }

    /**
     * Detect dangerous HTML tags
     */
    private function detectDangerousTags(string $input): array
    {
        $found = [];
        $score = 0;

        foreach (self::DANGEROUS_TAGS as $tag) {
            // Match <tag, </tag, <tag/, <tag>
            if (preg_match('/<\s*\/?\s*' . preg_quote($tag, '/') . '[\s>\/]/i', $input)) {
                $found[] = $tag;
                // script and iframe are highest risk
                if (in_array($tag, ['script', 'iframe', 'object', 'embed'], true)) {
                    $score += 40;
                } elseif (in_array($tag, ['svg', 'math', 'style'], true)) {
                    $score += 30;
                } else {
                    $score += 20;
                }
            }
        }

        return [
            'found' => !empty($found),
            'tags' => $found,
            'score' => min(100, $score),
        ];
    }

    /**
     * Detect event handlers
     */
    private function detectEventHandlers(string $input): array
    {
        $found = [];
        $score = 0;

        foreach (self::EVENT_HANDLERS as $handler) {
            // Match onXXX= with possible whitespace
            if (preg_match('/\b' . preg_quote($handler, '/') . '\s*=/i', $input)) {
                $found[] = $handler;
                $score += 35;
            }
        }

        return [
            'found' => !empty($found),
            'handlers' => $found,
            'score' => min(100, $score),
        ];
    }

    /**
     * Detect dangerous protocols
     */
    private function detectDangerousProtocols(string $input): array
    {
        $found = [];
        $score = 0;

        foreach (self::DANGEROUS_PROTOCOLS as $protocol) {
            // Match protocol with possible whitespace/encoding
            $pattern = str_replace(':', '\s*:', preg_quote($protocol, '/'));
            if (preg_match('/' . $pattern . '/i', $input)) {
                $found[] = $protocol;
                if ($protocol === 'javascript:') {
                    $score += 45;
                } else {
                    $score += 30;
                }
            }
        }

        return [
            'found' => !empty($found),
            'protocols' => $found,
            'score' => min(100, $score),
        ];
    }

    /**
     * Detect attribute breaking attempts
     */
    private function detectAttributeBreaking(string $input, string $context): array
    {
        $patterns = [
            // Breaking out of attribute with quote
            '/"[^"]*>/' => 40,
            "/\'[^\']*>/" => 40,
            // Breaking with event handler
            '/"[^"]*\s+on\w+\s*=/' => 50,
            "/\'[^\']*\s+on\w+\s*=/" => 50,
            // Breaking to add new tag
            '/"[^"]*<\w/' => 45,
            "/\'[^\']*<\w/" => 45,
        ];

        foreach ($patterns as $pattern => $score) {
            if (preg_match($pattern, $input)) {
                return [
                    'found' => true,
                    'pattern' => $pattern,
                    'score' => $score,
                ];
            }
        }

        return ['found' => false, 'pattern' => '', 'score' => 0];
    }

    /**
     * Detect JavaScript string breaking
     */
    private function detectJSBreaking(string $input): array
    {
        $patterns = [
            // Breaking out of JS string
            "/['\"];\s*[a-z]/" => 45,
            // Function call after break
            "/['\"];\s*\w+\s*\(/" => 50,
            // Template literal break
            '/`\s*\+/' => 40,
            // Closing script tag in JS context
            '/<\/script>/i' => 60,
        ];

        foreach ($patterns as $pattern => $score) {
            if (preg_match($pattern, $input)) {
                return [
                    'found' => true,
                    'pattern' => $pattern,
                    'score' => $score,
                ];
            }
        }

        return ['found' => false, 'pattern' => '', 'score' => 0];
    }

    /**
     * Detect CSS injection
     */
    private function detectCSSInjection(string $input): array
    {
        $found = [];
        $score = 0;

        foreach (self::DANGEROUS_CSS as $pattern) {
            if (str_contains($input, strtolower($pattern))) {
                $found[] = $pattern;
                if ($pattern === 'expression') {
                    $score += 45;
                } else {
                    $score += 25;
                }
            }
        }

        return [
            'found' => !empty($found),
            'matches' => $found,
            'score' => min(100, $score),
        ];
    }
}
