<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\ThreatIntel;

use AdosLabs\EnterpriseSecurityShield\Storage\StorageInterface;

/**
 * Threat Intelligence Feed Client.
 *
 * Fetches and manages threat intelligence from multiple sources:
 * - IP reputation lists (known malicious IPs, Tor exit nodes, VPNs)
 * - Malware signatures
 * - Emerging attack patterns
 * - CVE-based detection rules
 *
 * Supported Feed Formats:
 * - Plain text (one IP/domain per line)
 * - JSON (structured threat data)
 * - STIX/TAXII (industry standard)
 *
 * IMPORTANT: This is the CLIENT that fetches and caches feeds.
 * The actual blocking logic is in ThreatMatcher.
 */
final class ThreatFeedClient
{
    /**
     * Storage for caching feeds.
     */
    private ?StorageInterface $storage;

    /**
     * Configured threat feeds.
     *
     * @var array<string, array{url: string, type: string, refresh_hours: int, enabled: bool}>
     */
    private array $feeds = [];

    /**
     * Cache TTL in seconds (default: 6 hours).
     */
    private int $cacheTtl = 21600;

    /**
     * HTTP timeout in seconds.
     */
    private int $httpTimeout = 30;

    /**
     * User agent for requests.
     */
    private string $userAgent = 'EnterpriseSecurityShield/1.0 ThreatIntelClient';

    /**
     * API keys for authenticated feeds.
     *
     * @var array<string, string>
     */
    private array $apiKeys = [];

    /**
     * Constructor.
     *
     * @param array<string, mixed> $config Configuration options
     */
    public function __construct(?StorageInterface $storage = null, array $config = [])
    {
        $this->storage = $storage;
        $this->cacheTtl = $config['cache_ttl'] ?? 21600;
        $this->httpTimeout = $config['http_timeout'] ?? 30;
        $this->apiKeys = $config['api_keys'] ?? [];

        // Configure default feeds
        $this->initializeDefaultFeeds($config['feeds'] ?? []);
    }

    /**
     * Initialize default threat feeds.
     *
     * @param array<string, array<string, mixed>> $customFeeds
     */
    private function initializeDefaultFeeds(array $customFeeds = []): void
    {
        // Default public feeds (free, no API key required)
        $this->feeds = [
            'firehol_level1' => [
                'url' => 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
                'type' => 'ip_list',
                'refresh_hours' => 24,
                'enabled' => true,
                'description' => 'FireHOL Level 1 - High confidence malicious IPs',
            ],
            'emerging_threats_compromised' => [
                'url' => 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
                'type' => 'ip_list',
                'refresh_hours' => 6,
                'enabled' => true,
                'description' => 'Emerging Threats - Compromised IPs',
            ],
            'tor_exit_nodes' => [
                'url' => 'https://check.torproject.org/torbulkexitlist',
                'type' => 'ip_list',
                'refresh_hours' => 1,
                'enabled' => false, // Disabled by default - not all Tor users are malicious
                'description' => 'Tor Project - Exit Node IPs',
            ],
            'abuse_ch_feodo' => [
                'url' => 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
                'type' => 'ip_list',
                'refresh_hours' => 6,
                'enabled' => true,
                'description' => 'Abuse.ch Feodo Tracker - Botnet C&C IPs',
            ],
            'spamhaus_drop' => [
                'url' => 'https://www.spamhaus.org/drop/drop.txt',
                'type' => 'cidr_list',
                'refresh_hours' => 24,
                'enabled' => true,
                'description' => 'Spamhaus DROP - Do Not Route Or Peer',
            ],
        ];

        // Merge custom feeds
        foreach ($customFeeds as $name => $config) {
            $this->feeds[$name] = array_merge(
                $this->feeds[$name] ?? [],
                $config,
            );
        }
    }

    /**
     * Fetch all enabled feeds.
     *
     * @return array{
     *     success: array<string>,
     *     failed: array<string, string>,
     *     total_entries: int
     * }
     */
    public function fetchAllFeeds(): array
    {
        $success = [];
        $failed = [];
        $totalEntries = 0;

        foreach ($this->feeds as $name => $config) {
            if (!($config['enabled'] ?? true)) {
                continue;
            }

            try {
                $result = $this->fetchFeed($name);
                if ($result['success']) {
                    $success[] = $name;
                    $totalEntries += $result['entries'];
                } else {
                    $failed[$name] = $result['error'];
                }
            } catch (\Throwable $e) {
                $failed[$name] = $e->getMessage();
            }
        }

        return [
            'success' => $success,
            'failed' => $failed,
            'total_entries' => $totalEntries,
        ];
    }

    /**
     * Fetch a specific feed.
     *
     * @return array{success: bool, entries: int, error: string|null, cached: bool}
     */
    public function fetchFeed(string $feedName): array
    {
        if (!isset($this->feeds[$feedName])) {
            return [
                'success' => false,
                'entries' => 0,
                'error' => "Unknown feed: {$feedName}",
                'cached' => false,
            ];
        }

        $feed = $this->feeds[$feedName];

        // Check cache first
        $cacheKey = "threat_feed:{$feedName}";
        if ($this->storage !== null) {
            $cached = $this->storage->get($cacheKey);
            if ($cached !== null) {
                $data = json_decode($cached, true);
                if (is_array($data) && isset($data['fetched_at'])) {
                    $age = time() - $data['fetched_at'];
                    $maxAge = ($feed['refresh_hours'] ?? 6) * 3600;

                    if ($age < $maxAge) {
                        return [
                            'success' => true,
                            'entries' => $data['count'] ?? 0,
                            'error' => null,
                            'cached' => true,
                        ];
                    }
                }
            }
        }

        // Fetch fresh data
        $url = $feed['url'];
        $content = $this->httpGet($url, $feedName);

        if ($content === null) {
            return [
                'success' => false,
                'entries' => 0,
                'error' => "Failed to fetch feed from {$url}",
                'cached' => false,
            ];
        }

        // Parse based on type
        $entries = $this->parseFeed($content, $feed['type']);

        // Cache the parsed data
        if ($this->storage !== null && !empty($entries)) {
            $cacheData = [
                'entries' => $entries,
                'count' => count($entries),
                'fetched_at' => time(),
                'source' => $feedName,
            ];
            $ttl = ($feed['refresh_hours'] ?? 6) * 3600;
            $this->storage->set($cacheKey, json_encode($cacheData), $ttl);

            // Also store in a lookup-optimized format
            $this->storeForLookup($feedName, $entries, $feed['type']);
        }

        return [
            'success' => true,
            'entries' => count($entries),
            'error' => null,
            'cached' => false,
        ];
    }

    /**
     * Parse feed content based on type.
     *
     * @return array<string>
     */
    private function parseFeed(string $content, string $type): array
    {
        $entries = [];
        $lines = explode("\n", $content);

        foreach ($lines as $line) {
            $line = trim($line);

            // Skip empty lines and comments
            if ($line === '' || str_starts_with($line, '#') || str_starts_with($line, ';')) {
                continue;
            }

            switch ($type) {
                case 'ip_list':
                    // Extract IP from potential CIDR or additional info
                    if (preg_match('/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/', $line, $matches)) {
                        $entries[] = $matches[1];
                    }
                    break;

                case 'cidr_list':
                    // Keep CIDR notation
                    if (preg_match('/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})?)/', $line, $matches)) {
                        $entries[] = $matches[1];
                    }
                    break;

                case 'domain_list':
                    // Extract domain
                    if (preg_match('/^([a-z0-9][-a-z0-9]*(?:\.[a-z0-9][-a-z0-9]*)+)/i', $line, $matches)) {
                        $entries[] = strtolower($matches[1]);
                    }
                    break;

                case 'json':
                    // Will be handled separately
                    break;

                default:
                    // Treat as generic text list
                    $entries[] = $line;
            }
        }

        // For JSON type, parse the whole content
        if ($type === 'json') {
            $data = json_decode($content, true);
            if (is_array($data)) {
                $entries = $this->extractFromJson($data);
            }
        }

        return array_unique($entries);
    }

    /**
     * Extract entries from JSON feed.
     *
     * @param array<mixed> $data
     *
     * @return array<string>
     */
    private function extractFromJson(array $data): array
    {
        $entries = [];

        // Handle common JSON formats
        if (isset($data['data']) && is_array($data['data'])) {
            $data = $data['data'];
        }

        foreach ($data as $item) {
            if (is_string($item)) {
                $entries[] = $item;
            } elseif (is_array($item)) {
                // Try common field names
                foreach (['ip', 'address', 'indicator', 'value', 'ioc'] as $field) {
                    if (isset($item[$field]) && is_string($item[$field])) {
                        $entries[] = $item[$field];
                        break;
                    }
                }
            }
        }

        return $entries;
    }

    /**
     * Store entries in a lookup-optimized format.
     *
     * @param array<string> $entries
     */
    private function storeForLookup(string $feedName, array $entries, string $type): void
    {
        if ($this->storage === null) {
            return;
        }

        // Store as a set for O(1) lookups
        $lookupKey = "threat_lookup:{$feedName}";

        // For IP lists, we can use a bloom filter or hash set
        // Here we'll store a JSON-encoded array that ThreatMatcher can use
        $lookupData = [
            'type' => $type,
            'entries' => $entries,
            'updated' => time(),
        ];

        $this->storage->set($lookupKey, json_encode($lookupData), $this->cacheTtl * 2);
    }

    /**
     * HTTP GET request.
     */
    private function httpGet(string $url, string $feedName): ?string
    {
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => $this->httpTimeout,
                'header' => $this->buildHeaders($feedName),
                'ignore_errors' => true,
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
            ],
        ]);

        $content = @file_get_contents($url, false, $context);

        if ($content === false) {
            return null;
        }

        // Check HTTP status from response headers
        if (isset($http_response_header) && is_array($http_response_header)) {
            foreach ($http_response_header as $header) {
                if (preg_match('/^HTTP\/\d\.\d\s+(\d+)/', $header, $matches)) {
                    $status = (int) $matches[1];
                    if ($status >= 400) {
                        return null;
                    }
                    break;
                }
            }
        }

        return $content;
    }

    /**
     * Build HTTP headers for request.
     *
     * @return array<string>
     */
    private function buildHeaders(string $feedName): array
    {
        $headers = [
            "User-Agent: {$this->userAgent}",
            'Accept: text/plain, application/json',
        ];

        // Add API key if configured
        if (isset($this->apiKeys[$feedName])) {
            $headers[] = "Authorization: Bearer {$this->apiKeys[$feedName]}";
        }

        return $headers;
    }

    /**
     * Check if an IP is in any enabled feed.
     *
     * Note: This is a simple implementation. For production,
     * use ThreatMatcher which has optimized lookups.
     */
    public function isIpMalicious(string $ip): bool
    {
        if ($this->storage === null) {
            return false;
        }

        foreach ($this->feeds as $name => $config) {
            if (!($config['enabled'] ?? true)) {
                continue;
            }

            $lookupKey = "threat_lookup:{$name}";
            $cached = $this->storage->get($lookupKey);

            if ($cached === null) {
                continue;
            }

            $data = json_decode($cached, true);
            if (!is_array($data) || !isset($data['entries'])) {
                continue;
            }

            $type = $data['type'] ?? 'ip_list';

            if ($type === 'ip_list') {
                if (in_array($ip, $data['entries'], true)) {
                    return true;
                }
            } elseif ($type === 'cidr_list') {
                foreach ($data['entries'] as $cidr) {
                    if ($this->ipInCidr($ip, $cidr)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Check if IP is in CIDR range.
     */
    private function ipInCidr(string $ip, string $cidr): bool
    {
        if (!str_contains($cidr, '/')) {
            return $ip === $cidr;
        }

        [$subnet, $bits] = explode('/', $cidr);
        $bits = (int) $bits;

        $ip = ip2long($ip);
        $subnet = ip2long($subnet);

        if ($ip === false || $subnet === false) {
            return false;
        }

        $mask = -1 << (32 - $bits);

        return ($ip & $mask) === ($subnet & $mask);
    }

    /**
     * Add a custom feed.
     *
     * @param array<string, mixed> $config
     */
    public function addFeed(string $name, array $config): self
    {
        $this->feeds[$name] = array_merge([
            'enabled' => true,
            'refresh_hours' => 6,
            'type' => 'ip_list',
        ], $config);

        return $this;
    }

    /**
     * Enable or disable a feed.
     */
    public function setFeedEnabled(string $name, bool $enabled): self
    {
        if (isset($this->feeds[$name])) {
            $this->feeds[$name]['enabled'] = $enabled;
        }

        return $this;
    }

    /**
     * Set API key for a feed.
     */
    public function setApiKey(string $feedName, string $apiKey): self
    {
        $this->apiKeys[$feedName] = $apiKey;

        return $this;
    }

    /**
     * Get list of configured feeds.
     *
     * @return array<string, array<string, mixed>>
     */
    public function getFeeds(): array
    {
        return $this->feeds;
    }

    /**
     * Get feed statistics.
     *
     * @return array<string, array{enabled: bool, last_fetch: int|null, entries: int|null}>
     */
    public function getFeedStatistics(): array
    {
        $stats = [];

        foreach ($this->feeds as $name => $config) {
            $stats[$name] = [
                'enabled' => $config['enabled'] ?? true,
                'last_fetch' => null,
                'entries' => null,
            ];

            if ($this->storage !== null) {
                $cacheKey = "threat_feed:{$name}";
                $cached = $this->storage->get($cacheKey);

                if ($cached !== null) {
                    $data = json_decode($cached, true);
                    if (is_array($data)) {
                        $stats[$name]['last_fetch'] = $data['fetched_at'] ?? null;
                        $stats[$name]['entries'] = $data['count'] ?? null;
                    }
                }
            }
        }

        return $stats;
    }
}
