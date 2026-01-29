<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Privacy;

use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

/**
 * Anonymizing Logger Decorator.
 *
 * PSR-3 Logger decorator that automatically anonymizes sensitive data
 * before passing to the underlying logger.
 *
 * FEATURES:
 * 1. Automatic IP anonymization in log context
 * 2. Sensitive field redaction
 * 3. Configurable anonymization rules
 * 4. Preserves log levels and structure
 *
 * USAGE:
 * ```php
 * $gdpr = GDPRCompliance::balanced();
 * $anonymizingLogger = new AnonymizingLoggerDecorator($realLogger, $gdpr);
 *
 * // IPs in context are automatically anonymized
 * $anonymizingLogger->info('Request received', [
 *     'ip' => '192.168.1.100',  // Becomes 192.168.1.0
 *     'user_agent' => 'Mozilla/5.0...',  // Becomes Chrome/Windows
 * ]);
 * ```
 *
 * @version 1.0.0
 */
final class AnonymizingLoggerDecorator implements LoggerInterface
{
    private LoggerInterface $logger;

    private GDPRCompliance $gdpr;

    /**
     * Fields that contain IP addresses.
     *
     * @var array<string>
     */
    private array $ipFields = [
        'ip',
        'client_ip',
        'remote_addr',
        'source_ip',
        'x_forwarded_for',
        'x_real_ip',
        'cf_connecting_ip',
    ];

    /**
     * Fields that should be minimized.
     *
     * @var array<string>
     */
    private array $minimizeFields = [
        'user_agent',
        'referer',
        'referrer',
    ];

    /**
     * Fields that should be redacted.
     *
     * @var array<string>
     */
    private array $redactFields = [
        'password',
        'token',
        'secret',
        'api_key',
        'apikey',
        'authorization',
        'cookie',
        'cookies',
        'session',
        'credit_card',
        'card_number',
        'cvv',
        'ssn',
    ];

    /**
     * Enable/disable anonymization.
     */
    private bool $enabled = true;

    public function __construct(
        LoggerInterface $logger,
        ?GDPRCompliance $gdpr = null,
        array $config = [],
    ) {
        $this->logger = $logger;
        $this->gdpr = $gdpr ?? GDPRCompliance::balanced();

        if (isset($config['ip_fields'])) {
            $this->ipFields = array_merge($this->ipFields, $config['ip_fields']);
        }
        if (isset($config['minimize_fields'])) {
            $this->minimizeFields = array_merge($this->minimizeFields, $config['minimize_fields']);
        }
        if (isset($config['redact_fields'])) {
            $this->redactFields = array_merge($this->redactFields, $config['redact_fields']);
        }
        if (isset($config['enabled'])) {
            $this->enabled = $config['enabled'];
        }
    }

    /**
     * Enable or disable anonymization.
     */
    public function setEnabled(bool $enabled): self
    {
        $this->enabled = $enabled;

        return $this;
    }

    /**
     * Add custom IP field.
     */
    public function addIPField(string $field): self
    {
        $this->ipFields[] = $field;

        return $this;
    }

    /**
     * Add custom redact field.
     */
    public function addRedactField(string $field): self
    {
        $this->redactFields[] = $field;

        return $this;
    }

    // PSR-3 LoggerInterface implementation

    public function emergency(string|\Stringable $message, array $context = []): void
    {
        $this->log(LogLevel::EMERGENCY, $message, $context);
    }

    public function alert(string|\Stringable $message, array $context = []): void
    {
        $this->log(LogLevel::ALERT, $message, $context);
    }

    public function critical(string|\Stringable $message, array $context = []): void
    {
        $this->log(LogLevel::CRITICAL, $message, $context);
    }

    public function error(string|\Stringable $message, array $context = []): void
    {
        $this->log(LogLevel::ERROR, $message, $context);
    }

    public function warning(string|\Stringable $message, array $context = []): void
    {
        $this->log(LogLevel::WARNING, $message, $context);
    }

    public function notice(string|\Stringable $message, array $context = []): void
    {
        $this->log(LogLevel::NOTICE, $message, $context);
    }

    public function info(string|\Stringable $message, array $context = []): void
    {
        $this->log(LogLevel::INFO, $message, $context);
    }

    public function debug(string|\Stringable $message, array $context = []): void
    {
        $this->log(LogLevel::DEBUG, $message, $context);
    }

    public function log($level, string|\Stringable $message, array $context = []): void
    {
        if ($this->enabled) {
            $context = $this->anonymizeContext($context);
            $message = $this->anonymizeMessage((string) $message);
        }

        $this->logger->log($level, $message, $context);
    }

    /**
     * Anonymize context array.
     *
     * @param array<string, mixed> $context
     *
     * @return array<string, mixed>
     */
    private function anonymizeContext(array $context): array
    {
        return $this->processArray($context);
    }

    /**
     * Process array recursively.
     *
     * @param array<string, mixed> $data
     *
     * @return array<string, mixed>
     */
    private function processArray(array $data): array
    {
        $result = [];

        foreach ($data as $key => $value) {
            $keyLower = strtolower((string) $key);

            // Check for redact fields
            if ($this->shouldRedact($keyLower)) {
                $result[$key] = '[REDACTED]';
                continue;
            }

            // Check for IP fields
            if ($this->isIPField($keyLower)) {
                $result[$key] = $this->anonymizeIPValue($value);
                continue;
            }

            // Check for minimize fields
            if ($this->shouldMinimize($keyLower)) {
                $result[$key] = $this->minimizeValue($keyLower, $value);
                continue;
            }

            // Process nested arrays
            if (is_array($value)) {
                $result[$key] = $this->processArray($value);
                continue;
            }

            // Check if value looks like an IP
            if (is_string($value) && $this->looksLikeIP($value)) {
                $result[$key] = $this->gdpr->anonymizeIP($value);
                continue;
            }

            $result[$key] = $value;
        }

        return $result;
    }

    /**
     * Check if field should be redacted.
     */
    private function shouldRedact(string $key): bool
    {
        foreach ($this->redactFields as $field) {
            if (str_contains($key, $field)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if field is an IP field.
     */
    private function isIPField(string $key): bool
    {
        return in_array($key, $this->ipFields, true);
    }

    /**
     * Check if field should be minimized.
     */
    private function shouldMinimize(string $key): bool
    {
        return in_array($key, $this->minimizeFields, true);
    }

    /**
     * Anonymize IP value (handles single IP or comma-separated list).
     *
     * @param mixed $value
     */
    private function anonymizeIPValue($value): string
    {
        if (!is_string($value)) {
            return '[INVALID]';
        }

        // Handle comma-separated IPs (X-Forwarded-For)
        if (str_contains($value, ',')) {
            $ips = array_map('trim', explode(',', $value));
            $anonymized = array_map(fn ($ip) => $this->gdpr->anonymizeIP($ip), $ips);

            return implode(', ', $anonymized);
        }

        return $this->gdpr->anonymizeIP($value);
    }

    /**
     * Minimize value based on field type.
     *
     * @param mixed $value
     */
    private function minimizeValue(string $field, $value): string
    {
        if (!is_string($value)) {
            return '[INVALID]';
        }

        if (str_contains($field, 'user_agent')) {
            return $this->minimizeUserAgent($value);
        }

        if (str_contains($field, 'refer')) {
            return $this->minimizeReferer($value);
        }

        return substr($value, 0, 50) . (strlen($value) > 50 ? '...' : '');
    }

    /**
     * Minimize User-Agent.
     */
    private function minimizeUserAgent(string $ua): string
    {
        $browser = 'Unknown';
        $os = 'Unknown';

        // Detect browser
        if (str_contains($ua, 'Chrome')) {
            $browser = 'Chrome';
        } elseif (str_contains($ua, 'Firefox')) {
            $browser = 'Firefox';
        } elseif (str_contains($ua, 'Safari')) {
            $browser = 'Safari';
        } elseif (str_contains($ua, 'Edge')) {
            $browser = 'Edge';
        } elseif (str_contains($ua, 'MSIE') || str_contains($ua, 'Trident')) {
            $browser = 'IE';
        } elseif (preg_match('/bot|crawler|spider|curl|wget|python/i', $ua)) {
            $browser = 'Bot';
        }

        // Detect OS
        if (str_contains($ua, 'Windows')) {
            $os = 'Windows';
        } elseif (str_contains($ua, 'Mac')) {
            $os = 'Mac';
        } elseif (str_contains($ua, 'Linux')) {
            $os = 'Linux';
        } elseif (str_contains($ua, 'Android')) {
            $os = 'Android';
        } elseif (str_contains($ua, 'iOS') || str_contains($ua, 'iPhone')) {
            $os = 'iOS';
        }

        return "{$browser}/{$os}";
    }

    /**
     * Minimize Referer.
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
     * Check if value looks like an IP address.
     */
    private function looksLikeIP(string $value): bool
    {
        return (bool) filter_var($value, FILTER_VALIDATE_IP);
    }

    /**
     * Anonymize message string (looks for IP patterns).
     */
    private function anonymizeMessage(string $message): string
    {
        // IPv4 pattern
        $message = preg_replace_callback(
            '/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/',
            fn ($m) => $this->gdpr->anonymizeIP($m[1]),
            $message,
        ) ?? $message;

        return $message;
    }

    /**
     * Get the underlying logger.
     */
    public function getInnerLogger(): LoggerInterface
    {
        return $this->logger;
    }
}
