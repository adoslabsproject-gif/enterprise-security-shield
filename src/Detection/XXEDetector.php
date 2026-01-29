<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Detection;

/**
 * XXE (XML External Entity) Detector
 *
 * Detects XML External Entity injection attempts.
 * XXE can lead to:
 * - Local file disclosure
 * - Server-side request forgery (SSRF)
 * - Denial of service (billion laughs)
 * - Remote code execution (in some configurations)
 *
 * DETECTS:
 * - DOCTYPE declarations
 * - ENTITY declarations (internal/external/parameter)
 * - SYSTEM identifiers
 * - PUBLIC identifiers
 * - XInclude
 * - DTD references
 * - Billion laughs patterns
 * - PHP filter wrappers
 *
 * @version 1.0.0
 */
final class XXEDetector
{
    public const RISK_NONE = 'NONE';
    public const RISK_LOW = 'LOW';
    public const RISK_MEDIUM = 'MEDIUM';
    public const RISK_HIGH = 'HIGH';
    public const RISK_CRITICAL = 'CRITICAL';

    public const ATTACK_FILE_DISCLOSURE = 'FILE_DISCLOSURE';
    public const ATTACK_SSRF = 'SSRF';
    public const ATTACK_DOS = 'DENIAL_OF_SERVICE';
    public const ATTACK_RCE = 'REMOTE_CODE_EXECUTION';
    public const ATTACK_PARAMETER_ENTITY = 'PARAMETER_ENTITY';

    /**
     * XXE patterns with confidence scores
     */
    private const XXE_PATTERNS = [
        // DOCTYPE declarations
        '/<!DOCTYPE\s+[^>]*>/i' => [
            'confidence' => 0.60,
            'type' => 'DOCTYPE',
            'evidence' => 'DOCTYPE declaration found',
        ],

        // External ENTITY with SYSTEM
        '/<!ENTITY\s+\S+\s+SYSTEM\s+["\'][^"\']+["\']\s*>/i' => [
            'confidence' => 0.95,
            'type' => self::ATTACK_FILE_DISCLOSURE,
            'evidence' => 'External ENTITY with SYSTEM identifier',
        ],

        // External ENTITY with PUBLIC
        '/<!ENTITY\s+\S+\s+PUBLIC\s+["\'][^"\']*["\']\s+["\'][^"\']+["\']\s*>/i' => [
            'confidence' => 0.90,
            'type' => self::ATTACK_SSRF,
            'evidence' => 'External ENTITY with PUBLIC identifier',
        ],

        // Parameter entity
        '/<!ENTITY\s+%\s+\S+\s+SYSTEM\s+["\'][^"\']+["\']\s*>/i' => [
            'confidence' => 0.98,
            'type' => self::ATTACK_PARAMETER_ENTITY,
            'evidence' => 'Parameter entity with SYSTEM (blind XXE)',
        ],

        // Parameter entity reference in DTD
        '/<!ENTITY\s+%\s+\S+\s+["\'][^"\']*%[^"\']*["\']\s*>/i' => [
            'confidence' => 0.95,
            'type' => self::ATTACK_PARAMETER_ENTITY,
            'evidence' => 'Parameter entity with entity reference',
        ],

        // File protocol
        '/SYSTEM\s+["\']file:\/\/[^"\']+["\']/i' => [
            'confidence' => 0.99,
            'type' => self::ATTACK_FILE_DISCLOSURE,
            'evidence' => 'file:// protocol in SYSTEM identifier',
        ],

        // PHP filter wrapper
        '/SYSTEM\s+["\']php:\/\/filter[^"\']+["\']/i' => [
            'confidence' => 0.99,
            'type' => self::ATTACK_FILE_DISCLOSURE,
            'evidence' => 'PHP filter wrapper (base64 file read)',
        ],

        // expect:// wrapper (RCE)
        '/SYSTEM\s+["\']expect:\/\/[^"\']+["\']/i' => [
            'confidence' => 1.0,
            'type' => self::ATTACK_RCE,
            'evidence' => 'expect:// protocol (command execution)',
        ],

        // HTTP/HTTPS external entity
        '/SYSTEM\s+["\']https?:\/\/[^"\']+["\']/i' => [
            'confidence' => 0.90,
            'type' => self::ATTACK_SSRF,
            'evidence' => 'HTTP(S) URL in SYSTEM identifier (SSRF)',
        ],

        // FTP external entity
        '/SYSTEM\s+["\']ftp:\/\/[^"\']+["\']/i' => [
            'confidence' => 0.92,
            'type' => self::ATTACK_SSRF,
            'evidence' => 'FTP URL in SYSTEM identifier',
        ],

        // Gopher protocol (SSRF)
        '/SYSTEM\s+["\']gopher:\/\/[^"\']+["\']/i' => [
            'confidence' => 0.95,
            'type' => self::ATTACK_SSRF,
            'evidence' => 'gopher:// protocol (advanced SSRF)',
        ],

        // Dict protocol
        '/SYSTEM\s+["\']dict:\/\/[^"\']+["\']/i' => [
            'confidence' => 0.90,
            'type' => self::ATTACK_SSRF,
            'evidence' => 'dict:// protocol',
        ],

        // netdoc protocol (Java)
        '/SYSTEM\s+["\']netdoc:\/\/[^"\']+["\']/i' => [
            'confidence' => 0.88,
            'type' => self::ATTACK_SSRF,
            'evidence' => 'netdoc:// protocol (Java)',
        ],

        // jar protocol (Java)
        '/SYSTEM\s+["\']jar:\/\/[^"\']+["\']/i' => [
            'confidence' => 0.88,
            'type' => self::ATTACK_SSRF,
            'evidence' => 'jar:// protocol (Java)',
        ],

        // data: protocol
        '/SYSTEM\s+["\']data:[^"\']+["\']/i' => [
            'confidence' => 0.85,
            'type' => self::ATTACK_FILE_DISCLOSURE,
            'evidence' => 'data: protocol in SYSTEM',
        ],

        // XInclude
        '/<xi:include\s+[^>]*href\s*=\s*["\'][^"\']+["\']/i' => [
            'confidence' => 0.92,
            'type' => self::ATTACK_FILE_DISCLOSURE,
            'evidence' => 'XInclude with href',
        ],

        // XInclude namespace
        '/xmlns:xi\s*=\s*["\']http:\/\/www\.w3\.org\/2001\/XInclude["\']/i' => [
            'confidence' => 0.75,
            'type' => 'XINCLUDE_NS',
            'evidence' => 'XInclude namespace declaration',
        ],

        // Billion laughs / Entity expansion
        '/<!ENTITY\s+\S+\s+["\'](&\S+;)+["\']\s*>/i' => [
            'confidence' => 0.95,
            'type' => self::ATTACK_DOS,
            'evidence' => 'Entity expansion (potential billion laughs)',
        ],

        // CDATA with entity
        '/<!\[CDATA\[.*?&\S+;.*?\]\]>/is' => [
            'confidence' => 0.50,
            'type' => 'CDATA_ENTITY',
            'evidence' => 'CDATA with entity reference',
        ],

        // /etc/passwd target
        '/SYSTEM\s+["\'][^"\']*\/etc\/passwd["\']/i' => [
            'confidence' => 0.99,
            'type' => self::ATTACK_FILE_DISCLOSURE,
            'evidence' => '/etc/passwd file disclosure attempt',
        ],

        // /etc/shadow target
        '/SYSTEM\s+["\'][^"\']*\/etc\/shadow["\']/i' => [
            'confidence' => 0.99,
            'type' => self::ATTACK_FILE_DISCLOSURE,
            'evidence' => '/etc/shadow file disclosure attempt',
        ],

        // Windows file targets
        '/SYSTEM\s+["\'][^"\']*[cC]:\\\\[^"\']+["\']/i' => [
            'confidence' => 0.95,
            'type' => self::ATTACK_FILE_DISCLOSURE,
            'evidence' => 'Windows file path in SYSTEM',
        ],

        // AWS metadata
        '/SYSTEM\s+["\'][^"\']*169\.254\.169\.254[^"\']*["\']/i' => [
            'confidence' => 0.98,
            'type' => self::ATTACK_SSRF,
            'evidence' => 'AWS metadata endpoint (SSRF)',
        ],

        // NOTATION declaration
        '/<!NOTATION\s+\S+\s+SYSTEM\s+["\'][^"\']+["\']\s*>/i' => [
            'confidence' => 0.70,
            'type' => 'NOTATION',
            'evidence' => 'NOTATION with SYSTEM identifier',
        ],
    ];

    /**
     * Sensitive file paths to detect
     */
    private const SENSITIVE_FILES = [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/hosts',
        '/etc/hostname',
        '/etc/resolv.conf',
        '/etc/nginx/nginx.conf',
        '/etc/apache2/apache2.conf',
        '/etc/httpd/httpd.conf',
        '/proc/self/environ',
        '/proc/version',
        '/var/log/apache2/access.log',
        '/var/log/apache2/error.log',
        '/var/log/nginx/access.log',
        '/var/log/nginx/error.log',
        '.htaccess',
        'web.config',
        '.env',
        'wp-config.php',
        'configuration.php',
        'config.php',
        'settings.php',
        'database.yml',
        'secrets.yml',
    ];

    private float $threshold;

    public function __construct(float $threshold = 0.5)
    {
        $this->threshold = $threshold;
    }

    /**
     * Detect XXE in XML input
     *
     * @param string $input XML content or user input
     * @return array{
     *     detected: bool,
     *     confidence: float,
     *     risk_level: string,
     *     attack_types: array<string>,
     *     evidence: array<string>,
     *     has_doctype: bool,
     *     has_entity: bool,
     *     has_external: bool
     * }
     */
    public function detect(string $input): array
    {
        $evidence = [];
        $attackTypes = [];
        $maxConfidence = 0.0;

        // Decode input
        $decoded = $this->decodeInput($input);

        // Basic structure checks
        $hasDoctype = (bool) preg_match('/<!DOCTYPE/i', $decoded);
        $hasEntity = (bool) preg_match('/<!ENTITY/i', $decoded);
        $hasExternal = (bool) preg_match('/SYSTEM|PUBLIC/i', $decoded);

        // Run pattern checks
        foreach (self::XXE_PATTERNS as $pattern => $info) {
            if (preg_match($pattern, $decoded, $matches)) {
                $maxConfidence = max($maxConfidence, $info['confidence']);
                $evidence[] = $info['evidence'];
                if (isset($info['type']) && !str_starts_with($info['type'], 'DOCTYPE') && !str_starts_with($info['type'], 'XINCLUDE') && !str_starts_with($info['type'], 'NOTATION') && !str_starts_with($info['type'], 'CDATA')) {
                    $attackTypes[] = $info['type'];
                }
            }
        }

        // Check for sensitive file paths
        foreach (self::SENSITIVE_FILES as $file) {
            if (stripos($decoded, $file) !== false) {
                // Only flag if in entity/system context
                if ($hasEntity || $hasExternal || stripos($decoded, 'href') !== false) {
                    $maxConfidence = max($maxConfidence, 0.90);
                    $evidence[] = "Sensitive file path: {$file}";
                    $attackTypes[] = self::ATTACK_FILE_DISCLOSURE;
                }
            }
        }

        // Check for nested entities (billion laughs indicator)
        if (preg_match_all('/<!ENTITY\s+(\S+)/i', $decoded, $entities)) {
            $entityCount = count($entities[1]);
            if ($entityCount >= 3) {
                // Check if entities reference each other
                $entityNames = $entities[1];
                $referencedCount = 0;
                foreach ($entityNames as $name) {
                    if (preg_match('/&' . preg_quote($name, '/') . ';/', $decoded)) {
                        $referencedCount++;
                    }
                }
                if ($referencedCount >= 2) {
                    $maxConfidence = max($maxConfidence, 0.95);
                    $evidence[] = "Multiple self-referencing entities (billion laughs pattern)";
                    $attackTypes[] = self::ATTACK_DOS;
                }
            }
        }

        // Additional SSRF indicators
        if (preg_match('/https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)/i', $decoded)) {
            if ($hasExternal) {
                $maxConfidence = max($maxConfidence, 0.95);
                $evidence[] = "Internal IP address in external reference (SSRF)";
                $attackTypes[] = self::ATTACK_SSRF;
            }
        }

        // Determine if detected
        $detected = $maxConfidence >= $this->threshold;

        // Determine risk level
        $riskLevel = match (true) {
            $maxConfidence >= 0.9 => self::RISK_CRITICAL,
            $maxConfidence >= 0.7 => self::RISK_HIGH,
            $maxConfidence >= 0.5 => self::RISK_MEDIUM,
            $maxConfidence >= 0.3 => self::RISK_LOW,
            default => self::RISK_NONE,
        };

        return [
            'detected' => $detected,
            'confidence' => round($maxConfidence * 100, 2),
            'risk_level' => $riskLevel,
            'attack_types' => array_unique($attackTypes),
            'evidence' => array_unique($evidence),
            'has_doctype' => $hasDoctype,
            'has_entity' => $hasEntity,
            'has_external' => $hasExternal,
        ];
    }

    /**
     * Quick check
     */
    public function isXXE(string $input): bool
    {
        return $this->detect($input)['detected'];
    }

    /**
     * Sanitize XML to remove XXE vectors
     *
     * WARNING: This should be used with caution. Prefer disabling
     * external entities at the XML parser level.
     *
     * @param string $xml XML content
     * @return string Sanitized XML
     */
    public function sanitize(string $xml): string
    {
        // Remove DOCTYPE completely
        $sanitized = preg_replace('/<!DOCTYPE[^>]*>/i', '', $xml) ?? $xml;

        // Remove ENTITY declarations
        $sanitized = preg_replace('/<!ENTITY[^>]*>/i', '', $sanitized) ?? $sanitized;

        // Remove XInclude elements
        $sanitized = preg_replace('/<xi:include[^>]*\/?>/i', '', $sanitized) ?? $sanitized;
        $sanitized = preg_replace('/<\/xi:include>/i', '', $sanitized) ?? $sanitized;

        // Remove entity references that look suspicious
        $sanitized = preg_replace('/&[a-zA-Z0-9_]+;/', '', $sanitized) ?? $sanitized;

        return $sanitized;
    }

    /**
     * Get safe XML parser configuration
     *
     * Returns configuration that should be used when parsing XML
     * to prevent XXE attacks.
     *
     * @return array<string, mixed>
     */
    public static function getSafeParserConfig(): array
    {
        return [
            'libxml_options' => LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR,
            'disable_external_entities' => true,
            'php_settings' => [
                // Call these before XML parsing:
                // libxml_disable_entity_loader(true); // Deprecated in PHP 8.0
                // For PHP 8.0+: Use LIBXML_NONET flag
            ],
            'recommended_flags' => LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING,
        ];
    }

    /**
     * Decode input
     */
    private function decodeInput(string $input): string
    {
        $decoded = $input;

        // URL decode
        for ($i = 0; $i < 3; $i++) {
            $newDecoded = urldecode($decoded);
            if ($newDecoded === $decoded) {
                break;
            }
            $decoded = $newDecoded;
        }

        // HTML entities
        $decoded = html_entity_decode($decoded, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        return $decoded;
    }

    /**
     * Set threshold
     */
    public function setThreshold(float $threshold): self
    {
        $this->threshold = max(0.0, min(1.0, $threshold));
        return $this;
    }
}
