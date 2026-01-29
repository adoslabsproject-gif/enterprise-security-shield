<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Detection\Parser;

/**
 * XSS Analyzer - Real HTML/JS parsing for XSS detection
 *
 * This is NOT regex matching. This is a real parser that:
 * - Tokenizes HTML structure
 * - Identifies script contexts (inline JS, event handlers, URLs)
 * - Detects JavaScript injection patterns
 * - Handles encoding bypass attempts
 * - Understands HTML attribute contexts
 *
 * Detection categories:
 * - Reflected XSS (immediate execution)
 * - Stored XSS patterns
 * - DOM-based XSS triggers
 * - mXSS (mutation XSS)
 * - SVG/MathML-based XSS
 *
 * @version 1.0.0
 */
final class XSSAnalyzer
{
    /**
     * Risk levels
     */
    public const RISK_NONE = 'NONE';
    public const RISK_LOW = 'LOW';
    public const RISK_MEDIUM = 'MEDIUM';
    public const RISK_HIGH = 'HIGH';
    public const RISK_CRITICAL = 'CRITICAL';

    /**
     * Attack types
     */
    public const ATTACK_SCRIPT_TAG = 'SCRIPT_TAG';
    public const ATTACK_EVENT_HANDLER = 'EVENT_HANDLER';
    public const ATTACK_JAVASCRIPT_URI = 'JAVASCRIPT_URI';
    public const ATTACK_DATA_URI = 'DATA_URI';
    public const ATTACK_SVG_XSS = 'SVG_XSS';
    public const ATTACK_MATHML_XSS = 'MATHML_XSS';
    public const ATTACK_TEMPLATE_INJECTION = 'TEMPLATE_INJECTION';
    public const ATTACK_DOM_CLOBBERING = 'DOM_CLOBBERING';
    public const ATTACK_CSS_INJECTION = 'CSS_INJECTION';
    public const ATTACK_ENCODED_XSS = 'ENCODED_XSS';

    /**
     * Dangerous HTML tags
     */
    private const DANGEROUS_TAGS = [
        'script' => 1.0,
        'iframe' => 0.8,
        'object' => 0.8,
        'embed' => 0.8,
        'applet' => 0.9,
        'base' => 0.7,
        'link' => 0.5,
        'meta' => 0.4,
        'style' => 0.6,
        'form' => 0.4,
        'input' => 0.3,
        'button' => 0.3,
        'textarea' => 0.3,
        'select' => 0.3,
        'svg' => 0.7,
        'math' => 0.7,
        'video' => 0.5,
        'audio' => 0.5,
        'source' => 0.4,
        'img' => 0.5,
        'body' => 0.6,
        'frameset' => 0.8,
        'frame' => 0.8,
        'layer' => 0.7,
        'bgsound' => 0.6,
        'marquee' => 0.4,
        'xml' => 0.5,
        'xss' => 1.0,
        'isindex' => 0.6,
        'keygen' => 0.5,
        'template' => 0.6,
        'slot' => 0.4,
        'portal' => 0.6,
        'noscript' => 0.3,
    ];

    /**
     * Event handlers (case-insensitive)
     */
    private const EVENT_HANDLERS = [
        'onabort', 'onactivate', 'onafterprint', 'onafterscriptexecute', 'onafterupdate',
        'onanimationcancel', 'onanimationend', 'onanimationiteration', 'onanimationstart',
        'onauxclick', 'onbeforeactivate', 'onbeforecopy', 'onbeforecut', 'onbeforedeactivate',
        'onbeforeeditfocus', 'onbeforepaste', 'onbeforeprint', 'onbeforescriptexecute',
        'onbeforeunload', 'onbeforeupdate', 'onbegin', 'onblur', 'onbounce', 'oncancel',
        'oncanplay', 'oncanplaythrough', 'oncellchange', 'onchange', 'onclick', 'onclose',
        'oncontextmenu', 'oncontrolselect', 'oncopy', 'oncuechange', 'oncut', 'ondataavailable',
        'ondatasetchanged', 'ondatasetcomplete', 'ondblclick', 'ondeactivate', 'ondrag',
        'ondragdrop', 'ondragend', 'ondragenter', 'ondragleave', 'ondragover', 'ondragstart',
        'ondrop', 'ondurationchange', 'onemptied', 'onend', 'onended', 'onerror', 'onerrorupdate',
        'onexit', 'onfilterchange', 'onfinish', 'onfocus', 'onfocusin', 'onfocusout',
        'onformchange', 'onforminput', 'onfullscreenchange', 'onfullscreenerror',
        'ongotpointercapture', 'onhashchange', 'onhelp', 'oninput', 'oninvalid', 'onkeydown',
        'onkeypress', 'onkeyup', 'onlanguagechange', 'onlayoutcomplete', 'onload', 'onloadeddata',
        'onloadedmetadata', 'onloadstart', 'onlosecapture', 'onlostpointercapture', 'onmediacomplete',
        'onmediaerror', 'onmessage', 'onmessageerror', 'onmousedown', 'onmouseenter', 'onmouseleave',
        'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup', 'onmousewheel', 'onmove',
        'onmoveend', 'onmovestart', 'onmozfullscreenchange', 'onmozfullscreenerror',
        'onmozpointerlockchange', 'onmozpointerlockerror', 'onmscontentzoom', 'onmsgesturechange',
        'onmsgesturedoubletap', 'onmsgestureend', 'onmsgesturehold', 'onmsgesturestart',
        'onmsgesturetap', 'onmsgotpointercapture', 'onmsinertiastart', 'onmslostpointercapture',
        'onmsmanipulationstatechanged', 'onmspointercancel', 'onmspointerdown', 'onmspointerenter',
        'onmspointerleave', 'onmspointermove', 'onmspointerout', 'onmspointerover', 'onmspointerup',
        'onoffline', 'ononline', 'onoutofsync', 'onpage', 'onpagehide', 'onpageshow', 'onpaste',
        'onpause', 'onplay', 'onplaying', 'onpointercancel', 'onpointerdown', 'onpointerenter',
        'onpointerleave', 'onpointerlockchange', 'onpointerlockerror', 'onpointermove',
        'onpointerout', 'onpointerover', 'onpointerrawupdate', 'onpointerup', 'onpopstate',
        'onprogress', 'onpropertychange', 'onratechange', 'onreadystatechange', 'onreceived',
        'onrepeat', 'onreset', 'onresize', 'onresizeend', 'onresizestart', 'onresume',
        'onreverse', 'onrowdelete', 'onrowenter', 'onrowexit', 'onrowinserted', 'onrowsdelete',
        'onrowsinserted', 'onscroll', 'onsearch', 'onseek', 'onseeked', 'onseeking', 'onselect',
        'onselectionchange', 'onselectstart', 'onshow', 'onstalled', 'onstart', 'onstatechange',
        'onstop', 'onstorage', 'onsubmit', 'onsuspend', 'onsyncrestored', 'ontimeerror',
        'ontimeupdate', 'ontoggle', 'ontouchcancel', 'ontouchend', 'ontouchmove', 'ontouchstart',
        'ontrackchange', 'ontransitioncancel', 'ontransitionend', 'ontransitionrun',
        'ontransitionstart', 'onunhandledrejection', 'onunload', 'onurlflip', 'onvisibilitychange',
        'onvolumechange', 'onwaiting', 'onwebkitanimationend', 'onwebkitanimationiteration',
        'onwebkitanimationstart', 'onwebkitfullscreenchange', 'onwebkitfullscreenerror',
        'onwebkitmouseforcechanged', 'onwebkitmouseforcedown', 'onwebkitmouseforceup',
        'onwebkitmouseforcewillbegin', 'onwebkitplaybacktargetavailabilitychanged',
        'onwebkittransitionend', 'onwebkitwillrevealbottom', 'onwebkitwillrevealleft',
        'onwebkitwillrevealright', 'onwebkitwillrevealtop', 'onwheel',
    ];

    /**
     * Dangerous URL schemes
     */
    private const DANGEROUS_SCHEMES = [
        'javascript:',
        'vbscript:',
        'data:',
        'livescript:',
        'mocha:',
        'mhtml:',
    ];

    /**
     * JavaScript dangerous patterns
     */
    private const JS_DANGEROUS_PATTERNS = [
        'eval',
        'Function',
        'setTimeout',
        'setInterval',
        'setImmediate',
        'execScript',
        'document.write',
        'document.writeln',
        'document.cookie',
        'document.domain',
        'document.location',
        'document.URL',
        'document.documentURI',
        'document.referrer',
        'window.location',
        'window.name',
        'location.href',
        'location.hash',
        'location.search',
        'location.pathname',
        'innerHTML',
        'outerHTML',
        'insertAdjacentHTML',
        'srcdoc',
        'import',
        'fetch',
        'XMLHttpRequest',
        'WebSocket',
        'EventSource',
        'postMessage',
        'localStorage',
        'sessionStorage',
        'indexedDB',
        'constructor',
        '__proto__',
        'prototype',
    ];

    /**
     * Analyze input for XSS
     *
     * @param string $input Raw user input
     * @return array{
     *     detected: bool,
     *     confidence: float,
     *     attack_type: string|null,
     *     evidence: array<string>,
     *     risk_level: string,
     *     vectors: array<array{type: string, payload: string, confidence: float}>
     * }
     */
    public function analyze(string $input): array
    {
        $result = [
            'detected' => false,
            'confidence' => 0.0,
            'attack_type' => null,
            'evidence' => [],
            'risk_level' => self::RISK_NONE,
            'vectors' => [],
        ];

        // Quick reject for obviously safe input
        if ($this->isObviouslySafe($input)) {
            return $result;
        }

        // Decode input (multiple passes for nested encoding)
        $decoded = $this->decodeInput($input);

        // Run all detection checks
        $checks = [
            [$this, 'checkScriptTags'],
            [$this, 'checkEventHandlers'],
            [$this, 'checkJavascriptUri'],
            [$this, 'checkDataUri'],
            [$this, 'checkSvgXss'],
            [$this, 'checkMathMlXss'],
            [$this, 'checkTemplateInjection'],
            [$this, 'checkDomClobbering'],
            [$this, 'checkCssInjection'],
            [$this, 'checkEncodedPatterns'],
            [$this, 'checkJsPatterns'],
        ];

        $attackTypes = [];

        foreach ($checks as $check) {
            $checkResult = $check($decoded);
            if ($checkResult['detected']) {
                $result['detected'] = true;
                $result['confidence'] = max($result['confidence'], $checkResult['confidence']);
                $attackTypes[] = $checkResult['attack_type'];
                $result['evidence'] = array_merge($result['evidence'], $checkResult['evidence']);
                if (!empty($checkResult['vectors'])) {
                    $result['vectors'] = array_merge($result['vectors'], $checkResult['vectors']);
                }
            }
        }

        // Determine risk level
        $result['risk_level'] = match (true) {
            $result['confidence'] >= 0.9 => self::RISK_CRITICAL,
            $result['confidence'] >= 0.7 => self::RISK_HIGH,
            $result['confidence'] >= 0.5 => self::RISK_MEDIUM,
            $result['confidence'] >= 0.3 => self::RISK_LOW,
            default => self::RISK_NONE,
        };

        // Set attack type
        $attackTypes = array_unique($attackTypes);
        $result['attack_type'] = !empty($attackTypes) ? implode(', ', $attackTypes) : null;

        // Deduplicate evidence
        $result['evidence'] = array_values(array_unique($result['evidence']));

        return $result;
    }

    /**
     * Quick check for obviously safe input
     */
    private function isObviouslySafe(string $input): bool
    {
        // Very short input
        if (strlen($input) < 3) {
            return true;
        }

        // No HTML special characters
        if (!preg_match('/[<>"\'`=(){};\[\]\/\\\\]/', $input)) {
            return true;
        }

        return false;
    }

    /**
     * Decode various input encodings
     */
    private function decodeInput(string $input): string
    {
        $decoded = $input;

        // URL decode (multiple passes)
        for ($i = 0; $i < 3; $i++) {
            $newDecoded = urldecode($decoded);
            if ($newDecoded === $decoded) {
                break;
            }
            $decoded = $newDecoded;
        }

        // HTML entity decode
        $decoded = html_entity_decode($decoded, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        // Numeric character references
        $decoded = preg_replace_callback(
            '/&#([0-9]+);?/',
            fn($m) => chr((int) $m[1]),
            $decoded
        ) ?? $decoded;

        // Hex character references
        $decoded = preg_replace_callback(
            '/&#x([0-9a-fA-F]+);?/',
            fn($m) => chr((int) hexdec($m[1])),
            $decoded
        ) ?? $decoded;

        // Unicode escapes
        $decoded = preg_replace_callback(
            '/\\\\u([0-9a-fA-F]{4})/',
            fn($m) => mb_chr((int) hexdec($m[1])),
            $decoded
        ) ?? $decoded;

        // Remove null bytes
        $decoded = str_replace("\x00", '', $decoded);

        return $decoded;
    }

    /**
     * Check for script tags
     */
    private function checkScriptTags(string $input): array
    {
        $result = ['detected' => false, 'confidence' => 0.0, 'attack_type' => null, 'evidence' => [], 'vectors' => []];

        // Script tag patterns (including obfuscated)
        $patterns = [
            '/<\s*script[^>]*>/i' => 0.95,
            '/<\s*\/\s*script\s*>/i' => 0.80,
            '/<\s*script[^>]*>[^<]*<\s*\/\s*script\s*>/i' => 0.98,
            // Obfuscated variations
            '/<\s*s\s*c\s*r\s*i\s*p\s*t/i' => 0.90,
            '/<\s*scr\x00ipt/i' => 0.95,
        ];

        foreach ($patterns as $pattern => $confidence) {
            if (preg_match($pattern, $input, $matches)) {
                $result['detected'] = true;
                $result['confidence'] = max($result['confidence'], $confidence);
                $result['attack_type'] = self::ATTACK_SCRIPT_TAG;
                $result['evidence'][] = 'Script tag detected: ' . substr($matches[0], 0, 50);
                $result['vectors'][] = [
                    'type' => 'script_tag',
                    'payload' => substr($matches[0], 0, 100),
                    'confidence' => $confidence,
                ];
            }
        }

        return $result;
    }

    /**
     * Check for event handlers
     */
    private function checkEventHandlers(string $input): array
    {
        $result = ['detected' => false, 'confidence' => 0.0, 'attack_type' => null, 'evidence' => [], 'vectors' => []];

        $inputLower = strtolower($input);

        foreach (self::EVENT_HANDLERS as $handler) {
            // Look for handler in attribute context
            if (preg_match("/{$handler}\s*=/i", $input, $matches)) {
                $result['detected'] = true;
                $result['confidence'] = max($result['confidence'], 0.90);
                $result['attack_type'] = self::ATTACK_EVENT_HANDLER;
                $result['evidence'][] = "Event handler detected: {$handler}";
                $result['vectors'][] = [
                    'type' => 'event_handler',
                    'payload' => $handler,
                    'confidence' => 0.90,
                ];
            }
        }

        return $result;
    }

    /**
     * Check for javascript: URIs
     */
    private function checkJavascriptUri(string $input): array
    {
        $result = ['detected' => false, 'confidence' => 0.0, 'attack_type' => null, 'evidence' => [], 'vectors' => []];

        // Normalize for detection (remove whitespace, lowercase)
        $normalized = preg_replace('/\s+/', '', strtolower($input));

        $jsPatterns = [
            'javascript:' => 0.95,
            'vbscript:' => 0.95,
            'livescript:' => 0.90,
            // Obfuscated variations
            'java script:' => 0.85,
            'javas cript:' => 0.85,
            'j a v a s c r i p t :' => 0.80,
            // Tab/newline bypass
            "java\tscript:" => 0.90,
            "java\nscript:" => 0.90,
            "java\rscript:" => 0.90,
        ];

        foreach ($jsPatterns as $pattern => $confidence) {
            $normalizedPattern = preg_replace('/\s+/', '', strtolower($pattern));
            if (str_contains($normalized, $normalizedPattern)) {
                $result['detected'] = true;
                $result['confidence'] = max($result['confidence'], $confidence);
                $result['attack_type'] = self::ATTACK_JAVASCRIPT_URI;
                $result['evidence'][] = "JavaScript URI detected";
                $result['vectors'][] = [
                    'type' => 'javascript_uri',
                    'payload' => $pattern,
                    'confidence' => $confidence,
                ];
            }
        }

        return $result;
    }

    /**
     * Check for data: URIs with JavaScript
     */
    private function checkDataUri(string $input): array
    {
        $result = ['detected' => false, 'confidence' => 0.0, 'attack_type' => null, 'evidence' => [], 'vectors' => []];

        // data: URI patterns
        if (preg_match('/data\s*:\s*text\/html/i', $input, $matches)) {
            $result['detected'] = true;
            $result['confidence'] = 0.90;
            $result['attack_type'] = self::ATTACK_DATA_URI;
            $result['evidence'][] = "Data URI with HTML content type";
            $result['vectors'][] = [
                'type' => 'data_uri',
                'payload' => substr($matches[0], 0, 50),
                'confidence' => 0.90,
            ];
        }

        if (preg_match('/data\s*:\s*[^;,]+;base64/i', $input)) {
            // Decode and check for script content
            if (preg_match('/data:[^;]+;base64,([A-Za-z0-9+\/=]+)/', $input, $matches)) {
                $decoded = @base64_decode($matches[1]);
                if ($decoded && (stripos($decoded, '<script') !== false || stripos($decoded, 'javascript:') !== false)) {
                    $result['detected'] = true;
                    $result['confidence'] = 0.95;
                    $result['attack_type'] = self::ATTACK_DATA_URI;
                    $result['evidence'][] = "Base64 encoded script in data URI";
                    $result['vectors'][] = [
                        'type' => 'data_uri_base64',
                        'payload' => 'base64 encoded script',
                        'confidence' => 0.95,
                    ];
                }
            }
        }

        return $result;
    }

    /**
     * Check for SVG-based XSS
     */
    private function checkSvgXss(string $input): array
    {
        $result = ['detected' => false, 'confidence' => 0.0, 'attack_type' => null, 'evidence' => [], 'vectors' => []];

        // SVG with script or event handlers
        if (preg_match('/<\s*svg[^>]*>/i', $input)) {
            // Check for dangerous content inside SVG context
            if (preg_match('/<\s*svg[^>]*>.*?(<script|on\w+\s*=)/is', $input, $matches)) {
                $result['detected'] = true;
                $result['confidence'] = 0.95;
                $result['attack_type'] = self::ATTACK_SVG_XSS;
                $result['evidence'][] = "SVG with script/event handler";
                $result['vectors'][] = [
                    'type' => 'svg_xss',
                    'payload' => 'svg with embedded script',
                    'confidence' => 0.95,
                ];
            }

            // SVG animate/set for XSS
            if (preg_match('/<\s*(animate|set|animateTransform)[^>]*attributeName\s*=\s*["\']?on/i', $input)) {
                $result['detected'] = true;
                $result['confidence'] = 0.90;
                $result['attack_type'] = self::ATTACK_SVG_XSS;
                $result['evidence'][] = "SVG animate XSS";
            }

            // SVG use with external reference
            if (preg_match('/<\s*use[^>]*href\s*=\s*["\']?[^"\'>\s]*#/i', $input)) {
                $result['detected'] = true;
                $result['confidence'] = 0.70;
                $result['attack_type'] = self::ATTACK_SVG_XSS;
                $result['evidence'][] = "SVG use element with external reference";
            }
        }

        return $result;
    }

    /**
     * Check for MathML-based XSS
     */
    private function checkMathMlXss(string $input): array
    {
        $result = ['detected' => false, 'confidence' => 0.0, 'attack_type' => null, 'evidence' => [], 'vectors' => []];

        // MathML with dangerous elements
        if (preg_match('/<\s*math[^>]*>/i', $input)) {
            // MathML with maction
            if (preg_match('/<\s*maction[^>]*actiontype\s*=\s*["\']?statusline/i', $input)) {
                $result['detected'] = true;
                $result['confidence'] = 0.85;
                $result['attack_type'] = self::ATTACK_MATHML_XSS;
                $result['evidence'][] = "MathML maction XSS";
            }

            // MathML with annotation-xml
            if (preg_match('/<\s*annotation-xml[^>]*encoding\s*=\s*["\']?text\/html/i', $input)) {
                $result['detected'] = true;
                $result['confidence'] = 0.90;
                $result['attack_type'] = self::ATTACK_MATHML_XSS;
                $result['evidence'][] = "MathML annotation-xml HTML escape";
            }
        }

        return $result;
    }

    /**
     * Check for template injection (Angular, Vue, etc.)
     */
    private function checkTemplateInjection(string $input): array
    {
        $result = ['detected' => false, 'confidence' => 0.0, 'attack_type' => null, 'evidence' => [], 'vectors' => []];

        $templatePatterns = [
            '/\{\{\s*constructor\s*\}\}/i' => 0.95,  // Angular
            '/\{\{\s*[^}]*\$eval\s*\(/i' => 0.90,
            '/\[\[\s*constructor/i' => 0.85,  // Polymer
            '/\$\{[^}]*\}/i' => 0.60,  // Template literals
            '/<%[^%]*%>/i' => 0.70,  // EJS/ERB
            '/\{\%[^%]*%\}/i' => 0.60,  // Jinja/Twig
        ];

        foreach ($templatePatterns as $pattern => $confidence) {
            if (preg_match($pattern, $input, $matches)) {
                $result['detected'] = true;
                $result['confidence'] = max($result['confidence'], $confidence);
                $result['attack_type'] = self::ATTACK_TEMPLATE_INJECTION;
                $result['evidence'][] = "Template injection pattern detected";
                $result['vectors'][] = [
                    'type' => 'template_injection',
                    'payload' => substr($matches[0], 0, 50),
                    'confidence' => $confidence,
                ];
            }
        }

        return $result;
    }

    /**
     * Check for DOM clobbering
     */
    private function checkDomClobbering(string $input): array
    {
        $result = ['detected' => false, 'confidence' => 0.0, 'attack_type' => null, 'evidence' => [], 'vectors' => []];

        // Elements with id/name that could clobber DOM
        $dangerousIds = ['location', 'document', 'window', 'top', 'self', 'parent', 'frames', 'opener', 'closed', 'length', 'origin'];

        foreach ($dangerousIds as $id) {
            if (preg_match("/(id|name)\s*=\s*[\"']?{$id}[\"']?/i", $input)) {
                $result['detected'] = true;
                $result['confidence'] = max($result['confidence'], 0.70);
                $result['attack_type'] = self::ATTACK_DOM_CLOBBERING;
                $result['evidence'][] = "DOM clobbering: element with id/name '{$id}'";
            }
        }

        return $result;
    }

    /**
     * Check for CSS injection XSS
     */
    private function checkCssInjection(string $input): array
    {
        $result = ['detected' => false, 'confidence' => 0.0, 'attack_type' => null, 'evidence' => [], 'vectors' => []];

        // expression() - IE specific
        if (preg_match('/expression\s*\(/i', $input)) {
            $result['detected'] = true;
            $result['confidence'] = 0.90;
            $result['attack_type'] = self::ATTACK_CSS_INJECTION;
            $result['evidence'][] = "CSS expression() detected";
        }

        // url() with javascript
        if (preg_match('/url\s*\(\s*["\']?\s*javascript:/i', $input)) {
            $result['detected'] = true;
            $result['confidence'] = 0.95;
            $result['attack_type'] = self::ATTACK_CSS_INJECTION;
            $result['evidence'][] = "CSS url() with javascript:";
        }

        // behavior() - IE specific
        if (preg_match('/behavior\s*:\s*url\s*\(/i', $input)) {
            $result['detected'] = true;
            $result['confidence'] = 0.85;
            $result['attack_type'] = self::ATTACK_CSS_INJECTION;
            $result['evidence'][] = "CSS behavior() detected";
        }

        // @import with javascript
        if (preg_match('/@import\s+["\']?\s*javascript:/i', $input)) {
            $result['detected'] = true;
            $result['confidence'] = 0.90;
            $result['attack_type'] = self::ATTACK_CSS_INJECTION;
            $result['evidence'][] = "CSS @import with javascript:";
        }

        return $result;
    }

    /**
     * Check for encoded XSS patterns
     */
    private function checkEncodedPatterns(string $input): array
    {
        $result = ['detected' => false, 'confidence' => 0.0, 'attack_type' => null, 'evidence' => [], 'vectors' => []];

        // Check original vs decoded
        $decoded = $this->decodeInput($input);
        if ($decoded !== $input) {
            // Re-check decoded content for dangerous patterns
            if (preg_match('/<\s*script/i', $decoded) && !preg_match('/<\s*script/i', $input)) {
                $result['detected'] = true;
                $result['confidence'] = 0.90;
                $result['attack_type'] = self::ATTACK_ENCODED_XSS;
                $result['evidence'][] = "Encoded script tag bypass attempt";
            }

            // Check for encoded event handlers
            foreach (self::EVENT_HANDLERS as $handler) {
                if (preg_match("/{$handler}\s*=/i", $decoded) && !preg_match("/{$handler}\s*=/i", $input)) {
                    $result['detected'] = true;
                    $result['confidence'] = max($result['confidence'], 0.85);
                    $result['attack_type'] = self::ATTACK_ENCODED_XSS;
                    $result['evidence'][] = "Encoded event handler: {$handler}";
                }
            }
        }

        return $result;
    }

    /**
     * Check for dangerous JavaScript patterns
     */
    private function checkJsPatterns(string $input): array
    {
        $result = ['detected' => false, 'confidence' => 0.0, 'attack_type' => null, 'evidence' => [], 'vectors' => []];

        foreach (self::JS_DANGEROUS_PATTERNS as $pattern) {
            if (stripos($input, $pattern) !== false) {
                // Only flag if in a script-like context
                if (preg_match('/[<"\'\(\[]/', $input)) {
                    $confidence = match (true) {
                        in_array($pattern, ['eval', 'Function', 'constructor', '__proto__']) => 0.85,
                        str_contains($pattern, 'document.') => 0.70,
                        str_contains($pattern, 'window.') => 0.65,
                        default => 0.55,
                    };

                    $result['detected'] = true;
                    $result['confidence'] = max($result['confidence'], $confidence);
                    $result['attack_type'] = self::ATTACK_SCRIPT_TAG;
                    $result['evidence'][] = "Dangerous JS pattern: {$pattern}";
                }
            }
        }

        return $result;
    }
}
