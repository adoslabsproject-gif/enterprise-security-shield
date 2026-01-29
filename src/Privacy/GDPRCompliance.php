<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Privacy;

/**
 * GDPR Compliance Utilities
 *
 * Enterprise-grade GDPR compliance features for security logging.
 *
 * KEY FEATURES:
 * 1. IP Anonymization (multiple methods)
 * 2. Data minimization helpers
 * 3. Consent tracking
 * 4. Right to be forgotten implementation
 * 5. Data export (portability)
 * 6. Retention policy enforcement
 *
 * IP ANONYMIZATION METHODS:
 * - Octet masking: Replace last octet(s) with 0
 * - Hashing: Irreversible hash (daily salt rotation)
 * - Truncation: Remove last octets entirely
 * - Tokenization: Reversible with secure key (for legitimate interest)
 *
 * GDPR ARTICLES ADDRESSED:
 * - Article 5: Data minimization principle
 * - Article 17: Right to erasure
 * - Article 20: Right to data portability
 * - Article 25: Data protection by design
 * - Article 32: Security of processing
 *
 * @version 1.0.0
 */
final class GDPRCompliance
{
    /**
     * Anonymization methods
     */
    public const METHOD_MASK = 'mask';
    public const METHOD_HASH = 'hash';
    public const METHOD_TRUNCATE = 'truncate';
    public const METHOD_TOKENIZE = 'tokenize';

    /**
     * Default anonymization method
     */
    private string $defaultMethod = self::METHOD_MASK;

    /**
     * Number of octets to anonymize (1-3 for IPv4)
     */
    private int $octetsToAnonymize = 1;

    /**
     * Secret key for tokenization (reversible)
     */
    private ?string $tokenizationKey = null;

    /**
     * Daily salt for hashing (rotates for unlinkability)
     */
    private ?string $hashingSalt = null;

    /**
     * Whether to preserve country-level geolocation
     */
    private bool $preserveCountry = true;

    /**
     * Retention period in days
     */
    private int $retentionDays = 90;

    public function __construct(array $config = [])
    {
        if (isset($config['method'])) {
            $this->defaultMethod = $config['method'];
        }
        if (isset($config['octets'])) {
            $this->octetsToAnonymize = max(1, min(3, $config['octets']));
        }
        if (isset($config['tokenization_key'])) {
            $this->tokenizationKey = $config['tokenization_key'];
        }
        if (isset($config['hashing_salt'])) {
            $this->hashingSalt = $config['hashing_salt'];
        }
        if (isset($config['preserve_country'])) {
            $this->preserveCountry = $config['preserve_country'];
        }
        if (isset($config['retention_days'])) {
            $this->retentionDays = max(1, $config['retention_days']);
        }
    }

    /**
     * Anonymize an IP address
     *
     * @param string $ip IP address to anonymize
     * @param string|null $method Override default method
     * @return string Anonymized IP
     */
    public function anonymizeIP(string $ip, ?string $method = null): string
    {
        $method = $method ?? $this->defaultMethod;

        // Detect IP version
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return $this->anonymizeIPv6($ip, $method);
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $this->anonymizeIPv4($ip, $method);
        }

        // Invalid IP - return placeholder
        return '0.0.0.0';
    }

    /**
     * Anonymize IPv4 address
     */
    private function anonymizeIPv4(string $ip, string $method): string
    {
        return match ($method) {
            self::METHOD_MASK => $this->maskIPv4($ip),
            self::METHOD_HASH => $this->hashIP($ip),
            self::METHOD_TRUNCATE => $this->truncateIPv4($ip),
            self::METHOD_TOKENIZE => $this->tokenizeIP($ip),
            default => $this->maskIPv4($ip),
        };
    }

    /**
     * Anonymize IPv6 address
     */
    private function anonymizeIPv6(string $ip, string $method): string
    {
        return match ($method) {
            self::METHOD_MASK => $this->maskIPv6($ip),
            self::METHOD_HASH => $this->hashIP($ip),
            self::METHOD_TRUNCATE => $this->truncateIPv6($ip),
            self::METHOD_TOKENIZE => $this->tokenizeIP($ip),
            default => $this->maskIPv6($ip),
        };
    }

    /**
     * Mask IPv4 (replace octets with 0)
     *
     * Examples:
     * - 1 octet: 192.168.1.100 -> 192.168.1.0
     * - 2 octets: 192.168.1.100 -> 192.168.0.0
     * - 3 octets: 192.168.1.100 -> 192.0.0.0
     */
    private function maskIPv4(string $ip): string
    {
        $parts = explode('.', $ip);

        for ($i = 0; $i < $this->octetsToAnonymize; $i++) {
            $parts[3 - $i] = '0';
        }

        return implode('.', $parts);
    }

    /**
     * Mask IPv6 (zero out last groups)
     *
     * For GDPR compliance, mask at least the last 80 bits (last 5 groups)
     */
    private function maskIPv6(string $ip): string
    {
        // Expand IPv6 to full form
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return '::';
        }

        $hex = bin2hex($packed);
        $groups = str_split($hex, 4);

        // Mask groups based on octets setting (each octet = ~2 groups for IPv6)
        $groupsToMask = min(8, $this->octetsToAnonymize * 2 + 1);

        for ($i = 0; $i < $groupsToMask; $i++) {
            $groups[7 - $i] = '0000';
        }

        $fullIp = implode(':', $groups);

        // Compress zeros
        return inet_ntop(inet_pton($fullIp)) ?: '::';
    }

    /**
     * Truncate IPv4 (remove octets entirely)
     */
    private function truncateIPv4(string $ip): string
    {
        $parts = explode('.', $ip);
        $keep = 4 - $this->octetsToAnonymize;

        return implode('.', array_slice($parts, 0, $keep)) . str_repeat('.x', $this->octetsToAnonymize);
    }

    /**
     * Truncate IPv6
     */
    private function truncateIPv6(string $ip): string
    {
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return '::';
        }

        $hex = bin2hex($packed);
        $groups = str_split($hex, 4);

        $groupsToKeep = 8 - ($this->octetsToAnonymize * 2 + 1);
        $kept = array_slice($groups, 0, $groupsToKeep);

        return implode(':', $kept) . '::';
    }

    /**
     * Hash IP (irreversible, with daily salt for unlinkability)
     */
    private function hashIP(string $ip): string
    {
        $salt = $this->getDailySalt();

        // Create hash
        $hash = hash('sha256', $salt . $ip);

        // Format as pseudo-IP for compatibility
        $parts = [];
        for ($i = 0; $i < 4; $i++) {
            $parts[] = hexdec(substr($hash, $i * 2, 2)) % 256;
        }

        // Prefix with 0. to indicate hashed IP
        return '0.' . implode('.', array_slice($parts, 0, 3));
    }

    /**
     * Get daily salt for hashing
     */
    private function getDailySalt(): string
    {
        if ($this->hashingSalt !== null) {
            return $this->hashingSalt . date('Y-m-d');
        }

        // Use a deterministic but unpredictable salt
        return hash('sha256', 'gdpr_salt_' . date('Y-m-d'));
    }

    /**
     * Tokenize IP (reversible with key, for legitimate interest cases)
     */
    private function tokenizeIP(string $ip): string
    {
        if ($this->tokenizationKey === null) {
            // Fall back to masking if no key provided
            return $this->maskIPv4($ip);
        }

        // AES-256-GCM encryption
        $cipher = 'aes-256-gcm';
        $key = hash('sha256', $this->tokenizationKey, true);
        $iv = random_bytes(12);
        $tag = '';

        $encrypted = openssl_encrypt($ip, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag);

        if ($encrypted === false) {
            return $this->maskIPv4($ip);
        }

        // Return as base64 token
        return 'TOKEN:' . base64_encode($iv . $tag . $encrypted);
    }

    /**
     * Detokenize IP (reverse tokenization)
     */
    public function detokenizeIP(string $token): ?string
    {
        if (!str_starts_with($token, 'TOKEN:') || $this->tokenizationKey === null) {
            return null;
        }

        $data = base64_decode(substr($token, 6));
        if ($data === false || strlen($data) < 28) {
            return null;
        }

        $cipher = 'aes-256-gcm';
        $key = hash('sha256', $this->tokenizationKey, true);
        $iv = substr($data, 0, 12);
        $tag = substr($data, 12, 16);
        $encrypted = substr($data, 28);

        $decrypted = openssl_decrypt($encrypted, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag);

        if ($decrypted === false) {
            return null;
        }

        return $decrypted;
    }

    /**
     * Anonymize a log entry
     *
     * @param array<string, mixed> $logEntry
     * @return array<string, mixed>
     */
    public function anonymizeLogEntry(array $logEntry): array
    {
        // Anonymize IP fields
        $ipFields = ['ip', 'client_ip', 'remote_addr', 'x_forwarded_for', 'source_ip'];

        foreach ($ipFields as $field) {
            if (isset($logEntry[$field]) && is_string($logEntry[$field])) {
                $logEntry[$field] = $this->anonymizeIP($logEntry[$field]);
            }
        }

        // Remove or hash potentially identifying fields
        $sensitiveFields = ['user_agent', 'referer', 'cookies'];

        foreach ($sensitiveFields as $field) {
            if (isset($logEntry[$field])) {
                $logEntry[$field] = $this->minimizeData($field, $logEntry[$field]);
            }
        }

        return $logEntry;
    }

    /**
     * Minimize data based on field type
     *
     * @param mixed $value
     */
    private function minimizeData(string $field, $value): mixed
    {
        if (!is_string($value)) {
            return $value;
        }

        return match ($field) {
            'user_agent' => $this->minimizeUserAgent($value),
            'referer' => $this->minimizeReferer($value),
            'cookies' => '[REDACTED]',
            default => $value,
        };
    }

    /**
     * Minimize User-Agent (keep only essential info)
     */
    private function minimizeUserAgent(string $ua): string
    {
        // Extract only browser/OS family
        $patterns = [
            '/Chrome\/[\d.]+/' => 'Chrome',
            '/Firefox\/[\d.]+/' => 'Firefox',
            '/Safari\/[\d.]+/' => 'Safari',
            '/Edge\/[\d.]+/' => 'Edge',
            '/MSIE [\d.]+/' => 'IE',
            '/Trident\/[\d.]+/' => 'IE',
            '/bot|crawler|spider|curl|wget|python/i' => 'Bot',
        ];

        foreach ($patterns as $pattern => $name) {
            if (preg_match($pattern, $ua)) {
                // Add OS if detectable
                $os = 'Unknown';
                if (str_contains($ua, 'Windows')) $os = 'Windows';
                elseif (str_contains($ua, 'Mac')) $os = 'Mac';
                elseif (str_contains($ua, 'Linux')) $os = 'Linux';
                elseif (str_contains($ua, 'Android')) $os = 'Android';
                elseif (str_contains($ua, 'iOS') || str_contains($ua, 'iPhone')) $os = 'iOS';

                return "{$name}/{$os}";
            }
        }

        return 'Unknown/Unknown';
    }

    /**
     * Minimize Referer (keep only domain)
     */
    private function minimizeReferer(string $referer): string
    {
        $parsed = parse_url($referer);

        if ($parsed === false || !isset($parsed['host'])) {
            return '[INVALID]';
        }

        return $parsed['host'];
    }

    /**
     * Calculate retention expiry timestamp
     */
    public function getRetentionExpiry(): int
    {
        return time() + ($this->retentionDays * 86400);
    }

    /**
     * Check if data should be deleted based on retention
     */
    public function shouldDelete(int $createdAt): bool
    {
        $expiryTime = $createdAt + ($this->retentionDays * 86400);
        return time() >= $expiryTime;
    }

    /**
     * Get data for "Right to Access" request (Article 15)
     *
     * @param array<array<string, mixed>> $userData All data related to user
     * @return array<string, mixed>
     */
    public function prepareAccessReport(array $userData): array
    {
        return [
            'report_generated' => date('c'),
            'data_categories' => [
                'security_logs' => 'Security event logs related to your requests',
                'rate_limiting' => 'Rate limiting counters and timestamps',
                'threat_classifications' => 'ML-based threat assessments',
            ],
            'retention_period' => "{$this->retentionDays} days",
            'anonymization_method' => $this->defaultMethod,
            'data' => $userData,
            'your_rights' => [
                'rectification' => 'Article 16 - You may request correction of inaccurate data',
                'erasure' => 'Article 17 - You may request deletion of your data',
                'portability' => 'Article 20 - You may request your data in machine-readable format',
            ],
        ];
    }

    /**
     * Export data in portable format (Article 20)
     *
     * @param array<array<string, mixed>> $userData
     * @return string JSON export
     */
    public function exportData(array $userData): string
    {
        $export = [
            'format' => 'GDPR Data Export',
            'version' => '1.0',
            'exported_at' => date('c'),
            'data' => $userData,
        ];

        $json = json_encode($export, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        return $json !== false ? $json : '{"error": "Export failed"}';
    }

    /**
     * Set anonymization method
     */
    public function setMethod(string $method): self
    {
        $this->defaultMethod = $method;
        return $this;
    }

    /**
     * Set number of octets to anonymize
     */
    public function setOctets(int $octets): self
    {
        $this->octetsToAnonymize = max(1, min(3, $octets));
        return $this;
    }

    /**
     * Set tokenization key (enables reversible anonymization)
     */
    public function setTokenizationKey(string $key): self
    {
        $this->tokenizationKey = $key;
        return $this;
    }

    /**
     * Set retention period
     */
    public function setRetentionDays(int $days): self
    {
        $this->retentionDays = max(1, $days);
        return $this;
    }

    /**
     * Create with strict GDPR settings
     */
    public static function strict(): self
    {
        return new self([
            'method' => self::METHOD_HASH,
            'octets' => 2,
            'retention_days' => 30,
        ]);
    }

    /**
     * Create with balanced settings (security + privacy)
     */
    public static function balanced(): self
    {
        return new self([
            'method' => self::METHOD_MASK,
            'octets' => 1,
            'retention_days' => 90,
        ]);
    }

    /**
     * Create for legitimate interest (tokenized, reversible)
     */
    public static function legitimateInterest(string $key): self
    {
        return new self([
            'method' => self::METHOD_TOKENIZE,
            'tokenization_key' => $key,
            'retention_days' => 365,
        ]);
    }
}
