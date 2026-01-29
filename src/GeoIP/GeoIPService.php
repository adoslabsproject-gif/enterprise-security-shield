<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\GeoIP;

/**
 * GeoIP Service
 *
 * IP geolocation using MaxMind GeoLite2 database.
 * Provides country, city, ASN, and organization lookup.
 *
 * USAGE:
 * 1. Download GeoLite2-Country.mmdb from MaxMind (free account required)
 * 2. Place in configured path or set GEOIP_DATABASE_PATH env
 *
 * FEATURES:
 * - Country/City lookup
 * - ASN (Autonomous System Number) lookup
 * - Organization name lookup
 * - Caching for performance
 * - Country blocking
 * - ASN blocking (block entire hosting providers)
 *
 * @version 1.0.0
 */
final class GeoIPService
{
    private ?string $databasePath = null;
    private ?object $reader = null;
    private bool $initialized = false;
    private string $lastError = '';

    /**
     * In-memory cache for lookups
     * @var array<string, array>
     */
    private array $cache = [];
    private int $cacheMaxSize = 10000;

    /**
     * Blocked countries (ISO 3166-1 alpha-2 codes)
     * @var array<string>
     */
    private array $blockedCountries = [];

    /**
     * Blocked ASNs
     * @var array<int>
     */
    private array $blockedASNs = [];

    /**
     * Known malicious ASNs (hosting providers often used for attacks)
     */
    private const SUSPICIOUS_ASNS = [
        // Note: These are examples - you should verify and update
        // Some legitimate services also use these
    ];

    /**
     * High-risk countries for certain attacks
     */
    private const HIGH_RISK_COUNTRIES = [
        // Countries with historically high attack rates
        // This is data-driven, not political
    ];

    public function __construct(?string $databasePath = null)
    {
        $this->databasePath = $databasePath
            ?? $_ENV['GEOIP_DATABASE_PATH']
            ?? getenv('GEOIP_DATABASE_PATH')
            ?: null;
    }

    /**
     * Set database path
     */
    public function setDatabasePath(string $path): self
    {
        $this->databasePath = $path;
        $this->initialized = false;
        $this->reader = null;
        return $this;
    }

    /**
     * Set blocked countries
     *
     * @param array<string> $countries ISO 3166-1 alpha-2 codes (e.g., ['CN', 'RU'])
     */
    public function setBlockedCountries(array $countries): self
    {
        $this->blockedCountries = array_map('strtoupper', $countries);
        return $this;
    }

    /**
     * Add country to block list
     */
    public function blockCountry(string $countryCode): self
    {
        $code = strtoupper($countryCode);
        if (!in_array($code, $this->blockedCountries, true)) {
            $this->blockedCountries[] = $code;
        }
        return $this;
    }

    /**
     * Set blocked ASNs
     *
     * @param array<int> $asns ASN numbers
     */
    public function setBlockedASNs(array $asns): self
    {
        $this->blockedASNs = array_map('intval', $asns);
        return $this;
    }

    /**
     * Block an ASN
     */
    public function blockASN(int $asn): self
    {
        if (!in_array($asn, $this->blockedASNs, true)) {
            $this->blockedASNs[] = $asn;
        }
        return $this;
    }

    /**
     * Lookup IP geolocation
     *
     * @param string $ip IP address
     * @return array{
     *     country_code: string|null,
     *     country_name: string|null,
     *     city: string|null,
     *     region: string|null,
     *     timezone: string|null,
     *     latitude: float|null,
     *     longitude: float|null,
     *     asn: int|null,
     *     organization: string|null,
     *     is_blocked: bool,
     *     block_reason: string|null,
     *     risk_score: int
     * }
     */
    public function lookup(string $ip): array
    {
        // Check cache
        if (isset($this->cache[$ip])) {
            return $this->cache[$ip];
        }

        // Validate IP
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return $this->emptyResult('Invalid IP address');
        }

        // Private/reserved IPs
        if ($this->isPrivateIP($ip)) {
            return $this->cacheResult($ip, [
                'country_code' => 'XX',
                'country_name' => 'Private Network',
                'city' => null,
                'region' => null,
                'timezone' => null,
                'latitude' => null,
                'longitude' => null,
                'asn' => null,
                'organization' => 'Private/Reserved',
                'is_blocked' => false,
                'block_reason' => null,
                'risk_score' => 0,
            ]);
        }

        // Initialize reader
        if (!$this->initialize()) {
            // Fallback to IP-API (free, no database required)
            return $this->lookupFallback($ip);
        }

        try {
            $record = $this->reader->country($ip);

            $countryCode = $record->country->isoCode ?? null;
            $countryName = $record->country->name ?? null;

            // Check if blocked
            $isBlocked = false;
            $blockReason = null;

            if ($countryCode !== null && in_array($countryCode, $this->blockedCountries, true)) {
                $isBlocked = true;
                $blockReason = "Country blocked: {$countryCode}";
            }

            // Calculate risk score
            $riskScore = $this->calculateRiskScore($countryCode, null);

            $result = [
                'country_code' => $countryCode,
                'country_name' => $countryName,
                'city' => null, // Requires City database
                'region' => null,
                'timezone' => $record->location->timeZone ?? null,
                'latitude' => $record->location->latitude ?? null,
                'longitude' => $record->location->longitude ?? null,
                'asn' => null, // Requires ASN database
                'organization' => null,
                'is_blocked' => $isBlocked,
                'block_reason' => $blockReason,
                'risk_score' => $riskScore,
            ];

            return $this->cacheResult($ip, $result);
        } catch (\Throwable $e) {
            $this->lastError = $e->getMessage();
            return $this->lookupFallback($ip);
        }
    }

    /**
     * Check if IP is from a blocked country
     */
    public function isBlocked(string $ip): bool
    {
        $result = $this->lookup($ip);
        return $result['is_blocked'];
    }

    /**
     * Get country code for IP
     */
    public function getCountry(string $ip): ?string
    {
        $result = $this->lookup($ip);
        return $result['country_code'];
    }

    /**
     * Get ASN for IP
     */
    public function getASN(string $ip): ?int
    {
        $result = $this->lookup($ip);
        return $result['asn'];
    }

    /**
     * Get risk score for IP (0-100)
     */
    public function getRiskScore(string $ip): int
    {
        $result = $this->lookup($ip);
        return $result['risk_score'];
    }

    /**
     * Batch lookup multiple IPs
     *
     * @param array<string> $ips
     * @return array<string, array>
     */
    public function lookupBatch(array $ips): array
    {
        $results = [];
        foreach ($ips as $ip) {
            $results[$ip] = $this->lookup($ip);
        }
        return $results;
    }

    /**
     * Get last error message
     */
    public function getLastError(): string
    {
        return $this->lastError;
    }

    /**
     * Check if GeoIP database is available
     */
    public function isAvailable(): bool
    {
        return $this->initialize();
    }

    /**
     * Initialize MaxMind reader
     */
    private function initialize(): bool
    {
        if ($this->initialized) {
            return $this->reader !== null;
        }

        $this->initialized = true;

        if ($this->databasePath === null) {
            $this->lastError = 'GeoIP database path not configured';
            return false;
        }

        if (!file_exists($this->databasePath)) {
            $this->lastError = "GeoIP database not found: {$this->databasePath}";
            return false;
        }

        // Check for MaxMind Reader
        if (!class_exists('GeoIp2\Database\Reader')) {
            // Try to use pure PHP reader
            if (!class_exists('MaxMind\Db\Reader')) {
                $this->lastError = 'MaxMind GeoIP2 library not installed. Run: composer require geoip2/geoip2';
                return false;
            }
        }

        try {
            $this->reader = new \GeoIp2\Database\Reader($this->databasePath);
            return true;
        } catch (\Throwable $e) {
            $this->lastError = 'Failed to initialize GeoIP reader: ' . $e->getMessage();
            return false;
        }
    }

    /**
     * Fallback lookup using free IP-API service
     * Rate limited: 45 requests per minute
     */
    private function lookupFallback(string $ip): array
    {
        // Check cache first
        if (isset($this->cache[$ip])) {
            return $this->cache[$ip];
        }

        try {
            $ctx = stream_context_create([
                'http' => [
                    'timeout' => 2,
                    'ignore_errors' => true,
                ],
            ]);

            $response = @file_get_contents(
                "http://ip-api.com/json/{$ip}?fields=status,country,countryCode,regionName,city,timezone,lat,lon,as,org,isp",
                false,
                $ctx
            );

            if ($response === false) {
                return $this->emptyResult('Fallback lookup failed');
            }

            $data = json_decode($response, true);

            if (!is_array($data) || ($data['status'] ?? '') !== 'success') {
                return $this->emptyResult('Invalid response from fallback');
            }

            $countryCode = $data['countryCode'] ?? null;

            // Parse ASN from 'as' field (format: "AS12345 Organization Name")
            $asn = null;
            if (!empty($data['as']) && preg_match('/^AS(\d+)/', $data['as'], $matches)) {
                $asn = (int) $matches[1];
            }

            // Check if blocked
            $isBlocked = false;
            $blockReason = null;

            if ($countryCode !== null && in_array($countryCode, $this->blockedCountries, true)) {
                $isBlocked = true;
                $blockReason = "Country blocked: {$countryCode}";
            }

            if ($asn !== null && in_array($asn, $this->blockedASNs, true)) {
                $isBlocked = true;
                $blockReason = "ASN blocked: {$asn}";
            }

            $riskScore = $this->calculateRiskScore($countryCode, $asn);

            $result = [
                'country_code' => $countryCode,
                'country_name' => $data['country'] ?? null,
                'city' => $data['city'] ?? null,
                'region' => $data['regionName'] ?? null,
                'timezone' => $data['timezone'] ?? null,
                'latitude' => isset($data['lat']) ? (float) $data['lat'] : null,
                'longitude' => isset($data['lon']) ? (float) $data['lon'] : null,
                'asn' => $asn,
                'organization' => $data['org'] ?? $data['isp'] ?? null,
                'is_blocked' => $isBlocked,
                'block_reason' => $blockReason,
                'risk_score' => $riskScore,
            ];

            return $this->cacheResult($ip, $result);
        } catch (\Throwable $e) {
            $this->lastError = 'Fallback lookup exception: ' . $e->getMessage();
            return $this->emptyResult($this->lastError);
        }
    }

    /**
     * Check if IP is private/reserved
     */
    private function isPrivateIP(string $ip): bool
    {
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) === false;
    }

    /**
     * Calculate risk score based on country and ASN
     */
    private function calculateRiskScore(?string $countryCode, ?int $asn): int
    {
        $score = 0;

        // High-risk countries
        if ($countryCode !== null && in_array($countryCode, self::HIGH_RISK_COUNTRIES, true)) {
            $score += 20;
        }

        // Suspicious ASNs
        if ($asn !== null && in_array($asn, self::SUSPICIOUS_ASNS, true)) {
            $score += 30;
        }

        // Blocked country/ASN = high risk
        if ($countryCode !== null && in_array($countryCode, $this->blockedCountries, true)) {
            $score += 50;
        }

        if ($asn !== null && in_array($asn, $this->blockedASNs, true)) {
            $score += 50;
        }

        return min(100, $score);
    }

    /**
     * Cache result
     */
    private function cacheResult(string $ip, array $result): array
    {
        // Evict oldest entries if cache is full
        if (count($this->cache) >= $this->cacheMaxSize) {
            // Remove oldest 10%
            $this->cache = array_slice($this->cache, (int) ($this->cacheMaxSize * 0.1), null, true);
        }

        $this->cache[$ip] = $result;
        return $result;
    }

    /**
     * Empty result template
     */
    private function emptyResult(string $error = ''): array
    {
        if ($error !== '') {
            $this->lastError = $error;
        }

        return [
            'country_code' => null,
            'country_name' => null,
            'city' => null,
            'region' => null,
            'timezone' => null,
            'latitude' => null,
            'longitude' => null,
            'asn' => null,
            'organization' => null,
            'is_blocked' => false,
            'block_reason' => null,
            'risk_score' => 0,
        ];
    }

    /**
     * Clear cache
     */
    public function clearCache(): void
    {
        $this->cache = [];
    }
}
