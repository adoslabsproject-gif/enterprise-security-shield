<?php

namespace Senza1dio\SecurityShield\Config;

use Senza1dio\SecurityShield\Contracts\StorageInterface;
use Senza1dio\SecurityShield\Contracts\LoggerInterface;

/**
 * Security Configuration - Fluent Builder API
 *
 * Zero-config defaults for instant protection:
 * - Score threshold: 50 points (auto-ban)
 * - Ban duration: 24 hours
 * - Tracking window: 1 hour
 * - Honeypot: enabled
 * - Bot verification: enabled with DNS
 *
 * Enterprise customization available via fluent API
 */
class SecurityConfig
{
    /** @var int Threat score threshold for auto-ban (default: 50) */
    private int $scoreThreshold = 50;

    /** @var int Ban duration in seconds (default: 24h) */
    private int $banDuration = 86400;

    /** @var int Tracking window in seconds (default: 1h) */
    private int $trackingWindow = 3600;

    /** @var int Honeypot ban duration in seconds (default: 7 days) */
    private int $honeypotBanDuration = 604800;

    /** @var bool Enable honeypot trap endpoints */
    private bool $honeypotEnabled = true;

    /** @var bool Enable bot verification with DNS */
    private bool $botVerificationEnabled = true;

    /** @var int Bot verification cache TTL in seconds (default: 7 days) */
    private int $botCacheTTL = 604800;

    /** @var StorageInterface|null Storage backend (Redis, Database, Memory) */
    private ?StorageInterface $storage = null;

    /** @var LoggerInterface|null Logger instance (Monolog, Laravel, Symfony) */
    private ?LoggerInterface $logger = null;

    /** @var array<int, array{pattern: string, score: int, description: string}> Custom threat patterns to detect */
    private array $customPatterns = [];

    /** @var array<int, string> IP whitelist (never ban these IPs) */
    private array $ipWhitelist = [];

    /** @var array<int, string> IP blacklist (always ban these IPs) */
    private array $ipBlacklist = [];

    /** @var bool Enable intelligence gathering for honeypot */
    private bool $intelligenceEnabled = true;

    /** @var bool Send alerts on critical events */
    private bool $alertsEnabled = false;

    /** @var string|null Alert webhook URL */
    private ?string $alertWebhook = null;

    /** @var string Environment (production, staging, development) */
    private string $environment = 'production';

    /** @var int Rate limit requests per minute (default: 100) */
    private int $rateLimitPerMinute = 100;

    /** @var bool Enable SQL injection detection */
    private bool $sqlInjectionDetection = true;

    /** @var bool Enable XSS payload detection */
    private bool $xssDetection = true;

    /**
     * Set threat score threshold for auto-ban
     *
     * @param int $threshold Score threshold (1-1000)
     * @return self
     */
    public function setScoreThreshold(int $threshold): self
    {
        if ($threshold < 1 || $threshold > 1000) {
            throw new \InvalidArgumentException('Score threshold must be between 1 and 1000');
        }
        $this->scoreThreshold = $threshold;
        return $this;
    }

    /**
     * Set ban duration in seconds
     *
     * @param int $seconds Ban duration (60-2592000, max 30 days)
     * @return self
     */
    public function setBanDuration(int $seconds): self
    {
        if ($seconds < 60 || $seconds > 2592000) {
            throw new \InvalidArgumentException('Ban duration must be between 60s and 30 days');
        }
        $this->banDuration = $seconds;
        return $this;
    }

    /**
     * Set tracking window in seconds
     *
     * @param int $seconds Tracking window (60-86400, max 24h)
     * @return self
     */
    public function setTrackingWindow(int $seconds): self
    {
        if ($seconds < 60 || $seconds > 86400) {
            throw new \InvalidArgumentException('Tracking window must be between 60s and 24h');
        }
        $this->trackingWindow = $seconds;
        return $this;
    }

    /**
     * Set honeypot ban duration in seconds
     *
     * @param int $seconds Ban duration (3600-2592000, max 30 days)
     * @return self
     */
    public function setHoneypotBanDuration(int $seconds): self
    {
        if ($seconds < 3600 || $seconds > 2592000) {
            throw new \InvalidArgumentException('Honeypot ban must be between 1h and 30 days');
        }
        $this->honeypotBanDuration = $seconds;
        return $this;
    }

    /**
     * Enable or disable honeypot trap endpoints
     *
     * @param bool $enabled
     * @return self
     */
    public function enableHoneypot(bool $enabled): self
    {
        $this->honeypotEnabled = $enabled;
        return $this;
    }

    /**
     * Enable or disable bot verification with DNS
     *
     * @param bool $enabled
     * @return self
     */
    public function enableBotVerification(bool $enabled): self
    {
        $this->botVerificationEnabled = $enabled;
        return $this;
    }

    /**
     * Set bot verification cache TTL
     *
     * @param int $seconds Cache TTL (3600-2592000, max 30 days)
     * @return self
     */
    public function setBotCacheTTL(int $seconds): self
    {
        if ($seconds < 3600 || $seconds > 2592000) {
            throw new \InvalidArgumentException('Bot cache TTL must be between 1h and 30 days');
        }
        $this->botCacheTTL = $seconds;
        return $this;
    }

    /**
     * Set storage backend
     *
     * @param StorageInterface $storage
     * @return self
     */
    public function setStorage(StorageInterface $storage): self
    {
        $this->storage = $storage;
        return $this;
    }

    /**
     * Set logger instance
     *
     * @param LoggerInterface $logger
     * @return self
     */
    public function setLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;
        return $this;
    }

    /**
     * Add custom threat pattern
     *
     * @param string $pattern Regex pattern
     * @param int $score Score to add (1-100)
     * @param string $description Pattern description
     * @return self
     */
    public function addThreatPattern(string $pattern, int $score, string $description = ''): self
    {
        if ($score < 1 || $score > 100) {
            throw new \InvalidArgumentException('Pattern score must be between 1 and 100');
        }
        $this->customPatterns[] = [
            'pattern' => $pattern,
            'score' => $score,
            'description' => $description,
        ];
        return $this;
    }

    /**
     * Add IP to whitelist (never ban)
     *
     * @param string|array<int, string> $ips Single IP or array of IPs
     * @return self
     */
    public function addIPWhitelist(string|array $ips): self
    {
        $ips = is_array($ips) ? $ips : [$ips];
        foreach ($ips as $ip) {
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                throw new \InvalidArgumentException("Invalid IP address: {$ip}");
            }
            $this->ipWhitelist[] = $ip;
        }
        return $this;
    }

    /**
     * Add IP to blacklist (always ban)
     *
     * @param string|array<int, string> $ips Single IP or array of IPs
     * @return self
     */
    public function addIPBlacklist(string|array $ips): self
    {
        $ips = is_array($ips) ? $ips : [$ips];
        foreach ($ips as $ip) {
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                throw new \InvalidArgumentException("Invalid IP address: {$ip}");
            }
            $this->ipBlacklist[] = $ip;
        }
        return $this;
    }

    /**
     * Enable or disable intelligence gathering
     *
     * @param bool $enabled
     * @return self
     */
    public function enableIntelligence(bool $enabled): self
    {
        $this->intelligenceEnabled = $enabled;
        return $this;
    }

    /**
     * Enable or disable critical alerts
     *
     * @param bool $enabled
     * @param string|null $webhook Webhook URL for alerts
     * @return self
     */
    public function enableAlerts(bool $enabled, ?string $webhook = null): self
    {
        $this->alertsEnabled = $enabled;
        if ($webhook) {
            if (!filter_var($webhook, FILTER_VALIDATE_URL)) {
                throw new \InvalidArgumentException('Invalid webhook URL');
            }
            $this->alertWebhook = $webhook;
        }
        return $this;
    }

    /**
     * Set environment (production, staging, development)
     *
     * @param string $environment
     * @return self
     */
    public function setEnvironment(string $environment): self
    {
        $allowed = ['production', 'staging', 'development'];
        if (!in_array($environment, $allowed)) {
            throw new \InvalidArgumentException('Environment must be: ' . implode(', ', $allowed));
        }
        $this->environment = $environment;
        return $this;
    }

    /**
     * Set rate limit (requests per minute)
     *
     * Controls how many requests a single IP can make per minute.
     * Exceeding this limit adds threat score points.
     *
     * RECOMMENDED VALUES:
     * - API endpoints: 60-100 requests/minute
     * - Web applications: 100-200 requests/minute
     * - High-traffic sites: 200-500 requests/minute
     *
     * @param int $limit Requests per minute (1-1000)
     * @return self
     */
    public function setRateLimitPerMinute(int $limit): self
    {
        if ($limit < 1 || $limit > 1000) {
            throw new \InvalidArgumentException('Rate limit must be between 1 and 1000 requests/minute');
        }
        $this->rateLimitPerMinute = $limit;
        return $this;
    }

    /**
     * Enable or disable SQL injection detection
     *
     * When enabled, scans all GET/POST parameters for SQL injection patterns.
     * Detected attempts add 40 points to threat score.
     *
     * PERFORMANCE IMPACT: ~1-5ms per request with parameters
     * RECOMMENDATION: Always enabled in production
     *
     * @param bool $enabled
     * @return self
     */
    public function enableSQLInjectionDetection(bool $enabled): self
    {
        $this->sqlInjectionDetection = $enabled;
        return $this;
    }

    /**
     * Enable or disable XSS payload detection
     *
     * When enabled, scans all GET/POST parameters for XSS attack patterns.
     * Detected attempts add 30 points to threat score.
     *
     * PERFORMANCE IMPACT: ~1-5ms per request with parameters
     * RECOMMENDATION: Always enabled in production
     *
     * @param bool $enabled
     * @return self
     */
    public function enableXSSDetection(bool $enabled): self
    {
        $this->xssDetection = $enabled;
        return $this;
    }

    /**
     * Create config from array (Laravel/Symfony style)
     *
     * @param array<string, mixed> $config Configuration array
     * @return self
     */
    public static function fromArray(array $config): self
    {
        $instance = new self();

        if (isset($config['score_threshold']) && is_int($config['score_threshold'])) {
            $instance->setScoreThreshold($config['score_threshold']);
        }
        if (isset($config['ban_duration']) && is_int($config['ban_duration'])) {
            $instance->setBanDuration($config['ban_duration']);
        }
        if (isset($config['tracking_window']) && is_int($config['tracking_window'])) {
            $instance->setTrackingWindow($config['tracking_window']);
        }
        if (isset($config['honeypot_ban_duration']) && is_int($config['honeypot_ban_duration'])) {
            $instance->setHoneypotBanDuration($config['honeypot_ban_duration']);
        }
        if (isset($config['honeypot_enabled']) && is_bool($config['honeypot_enabled'])) {
            $instance->enableHoneypot($config['honeypot_enabled']);
        }
        if (isset($config['bot_verification_enabled']) && is_bool($config['bot_verification_enabled'])) {
            $instance->enableBotVerification($config['bot_verification_enabled']);
        }
        if (isset($config['bot_cache_ttl']) && is_int($config['bot_cache_ttl'])) {
            $instance->setBotCacheTTL($config['bot_cache_ttl']);
        }
        if (isset($config['storage']) && $config['storage'] instanceof StorageInterface) {
            $instance->setStorage($config['storage']);
        }
        if (isset($config['logger']) && $config['logger'] instanceof LoggerInterface) {
            $instance->setLogger($config['logger']);
        }
        if (isset($config['ip_whitelist']) && (is_string($config['ip_whitelist']) || is_array($config['ip_whitelist']))) {
            $instance->addIPWhitelist($config['ip_whitelist']);
        }
        if (isset($config['ip_blacklist']) && (is_string($config['ip_blacklist']) || is_array($config['ip_blacklist']))) {
            $instance->addIPBlacklist($config['ip_blacklist']);
        }
        if (isset($config['intelligence_enabled']) && is_bool($config['intelligence_enabled'])) {
            $instance->enableIntelligence($config['intelligence_enabled']);
        }
        if (isset($config['alerts_enabled']) && is_bool($config['alerts_enabled'])) {
            $webhook = isset($config['alert_webhook']) && is_string($config['alert_webhook']) ? $config['alert_webhook'] : null;
            $instance->enableAlerts($config['alerts_enabled'], $webhook);
        }
        if (isset($config['environment']) && is_string($config['environment'])) {
            $instance->setEnvironment($config['environment']);
        }
        if (isset($config['rate_limit_per_minute']) && is_int($config['rate_limit_per_minute'])) {
            $instance->setRateLimitPerMinute($config['rate_limit_per_minute']);
        }
        if (isset($config['sql_injection_detection']) && is_bool($config['sql_injection_detection'])) {
            $instance->enableSQLInjectionDetection($config['sql_injection_detection']);
        }
        if (isset($config['xss_detection']) && is_bool($config['xss_detection'])) {
            $instance->enableXSSDetection($config['xss_detection']);
        }

        return $instance;
    }

    // Getters

    public function getScoreThreshold(): int { return $this->scoreThreshold; }
    public function getBanDuration(): int { return $this->banDuration; }
    public function getTrackingWindow(): int { return $this->trackingWindow; }
    public function getHoneypotBanDuration(): int { return $this->honeypotBanDuration; }
    public function isHoneypotEnabled(): bool { return $this->honeypotEnabled; }
    public function isBotVerificationEnabled(): bool { return $this->botVerificationEnabled; }
    public function getBotCacheTTL(): int { return $this->botCacheTTL; }
    public function getStorage(): ?StorageInterface { return $this->storage; }
    public function getLogger(): ?LoggerInterface { return $this->logger; }
    /** @return array<int, array{pattern: string, score: int, description: string}> */
    public function getCustomPatterns(): array { return $this->customPatterns; }
    /** @return array<int, string> */
    public function getIPWhitelist(): array { return $this->ipWhitelist; }
    /** @return array<int, string> */
    public function getIPBlacklist(): array { return $this->ipBlacklist; }
    public function isIntelligenceEnabled(): bool { return $this->intelligenceEnabled; }
    public function isAlertsEnabled(): bool { return $this->alertsEnabled; }
    public function getAlertWebhook(): ?string { return $this->alertWebhook; }
    public function getEnvironment(): string { return $this->environment; }
    public function getRateLimitPerMinute(): int { return $this->rateLimitPerMinute; }
    public function isSQLInjectionDetectionEnabled(): bool { return $this->sqlInjectionDetection; }
    public function isXSSDetectionEnabled(): bool { return $this->xssDetection; }
}
