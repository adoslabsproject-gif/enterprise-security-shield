<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\RateLimiting;

use AdosLabs\EnterpriseSecurityShield\Storage\StorageInterface;

/**
 * API-Specific Rate Limiter.
 *
 * Advanced rate limiting designed for API endpoints:
 * - Per-endpoint limits (different limits for different routes)
 * - Per-API-key limits (authenticated users get higher limits)
 * - Per-tenant limits (for multi-tenant applications)
 * - Burst allowance with refill
 * - Cost-based limiting (expensive endpoints cost more)
 * - Quota management with reset periods
 *
 * Implements multiple limiting strategies:
 * - Token Bucket (default): Smooth rate with burst allowance
 * - Sliding Window: More accurate but higher storage cost
 * - Fixed Window: Simple but susceptible to burst at boundaries
 */
final class APIRateLimiter
{
    /**
     * Storage backend.
     */
    private StorageInterface $storage;

    /**
     * Default rate limit (requests per minute).
     */
    private int $defaultLimit = 60;

    /**
     * Default window size in seconds.
     */
    private int $defaultWindow = 60;

    /**
     * Per-endpoint configurations.
     *
     * @var array<string, array{limit: int, window: int, cost: int}>
     */
    private array $endpointLimits = [];

    /**
     * Per-API-key configurations.
     *
     * @var array<string, array{limit: int, window: int, tier: string}>
     */
    private array $apiKeyLimits = [];

    /**
     * Tier definitions.
     *
     * @var array<string, array{limit: int, window: int, burst: int}>
     */
    private array $tiers = [
        'free' => ['limit' => 60, 'window' => 60, 'burst' => 10],
        'basic' => ['limit' => 300, 'window' => 60, 'burst' => 50],
        'pro' => ['limit' => 1000, 'window' => 60, 'burst' => 200],
        'enterprise' => ['limit' => 10000, 'window' => 60, 'burst' => 2000],
        'unlimited' => ['limit' => PHP_INT_MAX, 'window' => 60, 'burst' => PHP_INT_MAX],
    ];

    /**
     * Algorithm to use.
     */
    private string $algorithm = 'token_bucket';

    /**
     * Constructor.
     *
     * @param array<string, mixed> $config Configuration options
     */
    public function __construct(StorageInterface $storage, array $config = [])
    {
        $this->storage = $storage;
        $this->defaultLimit = $config['default_limit'] ?? 60;
        $this->defaultWindow = $config['default_window'] ?? 60;
        $this->algorithm = $config['algorithm'] ?? 'token_bucket';

        if (isset($config['endpoint_limits'])) {
            $this->endpointLimits = $config['endpoint_limits'];
        }

        if (isset($config['api_key_limits'])) {
            $this->apiKeyLimits = $config['api_key_limits'];
        }

        if (isset($config['tiers'])) {
            $this->tiers = array_merge($this->tiers, $config['tiers']);
        }
    }

    /**
     * Check if request is allowed.
     *
     * @param string $identifier Client identifier (IP, API key, user ID)
     * @param string $endpoint API endpoint path
     * @param string|null $apiKey API key if authenticated
     * @param int $cost Request cost (default 1)
     *
     * @return array{
     *     allowed: bool,
     *     limit: int,
     *     remaining: int,
     *     reset: int,
     *     retry_after: int|null,
     *     tier: string|null
     * }
     */
    public function check(
        string $identifier,
        string $endpoint = '/',
        ?string $apiKey = null,
        int $cost = 1,
    ): array {
        // Determine the effective limit configuration
        $config = $this->getEffectiveConfig($endpoint, $apiKey);
        $tier = $config['tier'] ?? null;

        // Get endpoint cost multiplier
        $endpointCost = $this->getEndpointCost($endpoint);
        $totalCost = $cost * $endpointCost;

        // Build the rate limit key
        $key = $this->buildKey($identifier, $endpoint, $apiKey);

        // Apply rate limiting based on algorithm
        $result = match ($this->algorithm) {
            'sliding_window' => $this->slidingWindow($key, $config['limit'], $config['window'], $totalCost),
            'fixed_window' => $this->fixedWindow($key, $config['limit'], $config['window'], $totalCost),
            default => $this->tokenBucket($key, $config['limit'], $config['window'], $config['burst'] ?? 0, $totalCost),
        };

        $result['tier'] = $tier;

        return $result;
    }

    /**
     * Token Bucket algorithm.
     *
     * Allows smooth rate limiting with burst capacity.
     *
     * @return array{allowed: bool, limit: int, remaining: int, reset: int, retry_after: int|null}
     */
    private function tokenBucket(
        string $key,
        int $limit,
        int $window,
        int $burst,
        int $cost,
    ): array {
        $now = time();
        $bucketKey = "api_rate:bucket:{$key}";

        // Get current bucket state
        $state = $this->storage->get($bucketKey);
        $tokens = $limit + $burst; // Start full
        $lastRefill = $now;

        if ($state !== null) {
            $data = json_decode($state, true);
            if (is_array($data)) {
                $tokens = $data['tokens'] ?? $tokens;
                $lastRefill = $data['last_refill'] ?? $now;
            }
        }

        // Calculate tokens to add based on time passed
        $elapsed = $now - $lastRefill;
        $refillRate = $limit / $window; // Tokens per second
        $tokensToAdd = (int) ($elapsed * $refillRate);

        $tokens = min($limit + $burst, $tokens + $tokensToAdd);

        // Check if we have enough tokens
        $allowed = $tokens >= $cost;

        if ($allowed) {
            $tokens -= $cost;
        }

        // Calculate when tokens will be available
        $retryAfter = null;
        if (!$allowed && $refillRate > 0) {
            $tokensNeeded = $cost - $tokens;
            $retryAfter = (int) ceil($tokensNeeded / $refillRate);
        }

        // Save state
        $newState = json_encode([
            'tokens' => $tokens,
            'last_refill' => $now,
        ]);
        $this->storage->set($bucketKey, $newState, $window * 2);

        return [
            'allowed' => $allowed,
            'limit' => $limit,
            'remaining' => max(0, (int) $tokens),
            'reset' => $now + $window,
            'retry_after' => $retryAfter,
        ];
    }

    /**
     * Sliding Window algorithm.
     *
     * More accurate than fixed window but uses more storage.
     *
     * @return array{allowed: bool, limit: int, remaining: int, reset: int, retry_after: int|null}
     */
    private function slidingWindow(
        string $key,
        int $limit,
        int $window,
        int $cost,
    ): array {
        $now = time();
        $windowStart = $now - $window;
        $windowKey = "api_rate:sliding:{$key}";

        // Get timestamps of recent requests
        $state = $this->storage->get($windowKey);
        $timestamps = [];

        if ($state !== null) {
            $timestamps = json_decode($state, true) ?? [];
        }

        // Remove timestamps outside the window
        $timestamps = array_filter($timestamps, fn ($ts) => $ts > $windowStart);

        // Count requests in window
        $currentCount = count($timestamps);

        $allowed = ($currentCount + $cost) <= $limit;

        if ($allowed) {
            // Add new timestamps for each unit of cost
            for ($i = 0; $i < $cost; $i++) {
                $timestamps[] = $now;
            }
        }

        // Limit stored timestamps to prevent memory bloat
        if (count($timestamps) > $limit * 2) {
            $timestamps = array_slice($timestamps, -$limit);
        }

        // Save state
        $this->storage->set($windowKey, json_encode(array_values($timestamps)), $window * 2);

        // Calculate retry after
        $retryAfter = null;
        if (!$allowed && !empty($timestamps)) {
            $oldestInWindow = min($timestamps);
            $retryAfter = max(1, $oldestInWindow + $window - $now);
        }

        return [
            'allowed' => $allowed,
            'limit' => $limit,
            'remaining' => max(0, $limit - $currentCount),
            'reset' => $now + $window,
            'retry_after' => $retryAfter,
        ];
    }

    /**
     * Fixed Window algorithm.
     *
     * Simple and fast but allows burst at window boundaries.
     *
     * @return array{allowed: bool, limit: int, remaining: int, reset: int, retry_after: int|null}
     */
    private function fixedWindow(
        string $key,
        int $limit,
        int $window,
        int $cost,
    ): array {
        $now = time();
        $windowNumber = (int) ($now / $window);
        $windowKey = "api_rate:fixed:{$key}:{$windowNumber}";

        // Increment counter
        $count = $this->storage->incrementScore($windowKey, $cost, $window + 1);

        $allowed = $count <= $limit;

        // Calculate reset time (end of current window)
        $windowEnd = ($windowNumber + 1) * $window;

        $retryAfter = null;
        if (!$allowed) {
            $retryAfter = $windowEnd - $now;
        }

        return [
            'allowed' => $allowed,
            'limit' => $limit,
            'remaining' => max(0, $limit - $count),
            'reset' => $windowEnd,
            'retry_after' => $retryAfter,
        ];
    }

    /**
     * Get effective rate limit configuration.
     *
     * Priority: API key > Endpoint > Default
     *
     * @return array{limit: int, window: int, burst: int, tier: string|null}
     */
    private function getEffectiveConfig(string $endpoint, ?string $apiKey): array
    {
        // Start with defaults
        $config = [
            'limit' => $this->defaultLimit,
            'window' => $this->defaultWindow,
            'burst' => 0,
            'tier' => null,
        ];

        // Check endpoint-specific limits
        foreach ($this->endpointLimits as $pattern => $limits) {
            if ($this->matchEndpoint($endpoint, $pattern)) {
                $config = array_merge($config, $limits);
                break;
            }
        }

        // Check API key limits (highest priority)
        if ($apiKey !== null) {
            if (isset($this->apiKeyLimits[$apiKey])) {
                $keyConfig = $this->apiKeyLimits[$apiKey];
                $config = array_merge($config, $keyConfig);

                // If tier is specified, apply tier limits
                if (isset($keyConfig['tier']) && isset($this->tiers[$keyConfig['tier']])) {
                    $tierConfig = $this->tiers[$keyConfig['tier']];
                    $config = array_merge($config, $tierConfig);
                    $config['tier'] = $keyConfig['tier'];
                }
            } else {
                // Default tier for authenticated but unknown API keys
                $config['tier'] = 'free';
                if (isset($this->tiers['free'])) {
                    $config = array_merge($config, $this->tiers['free']);
                }
            }
        }

        return $config;
    }

    /**
     * Match endpoint against pattern.
     */
    private function matchEndpoint(string $endpoint, string $pattern): bool
    {
        // Exact match
        if ($endpoint === $pattern) {
            return true;
        }

        // Wildcard pattern
        if (str_contains($pattern, '*')) {
            $regex = '/^' . str_replace(['*', '/'], ['.*', '\\/'], $pattern) . '$/';

            return (bool) preg_match($regex, $endpoint);
        }

        // Prefix match (pattern ends with /)
        if (str_ends_with($pattern, '/')) {
            return str_starts_with($endpoint, $pattern);
        }

        return false;
    }

    /**
     * Get endpoint cost multiplier.
     */
    private function getEndpointCost(string $endpoint): int
    {
        if (isset($this->endpointLimits[$endpoint]['cost'])) {
            return $this->endpointLimits[$endpoint]['cost'];
        }

        // Check pattern matches
        foreach ($this->endpointLimits as $pattern => $limits) {
            if ($this->matchEndpoint($endpoint, $pattern) && isset($limits['cost'])) {
                return $limits['cost'];
            }
        }

        return 1;
    }

    /**
     * Build rate limit key.
     */
    private function buildKey(string $identifier, string $endpoint, ?string $apiKey): string
    {
        $parts = [$identifier];

        // Use API key as primary identifier if available
        if ($apiKey !== null) {
            $parts = [hash('sha256', $apiKey)];
        }

        // Normalize endpoint for key
        $normalizedEndpoint = preg_replace('/\/\d+/', '/:id', $endpoint);
        $parts[] = $normalizedEndpoint;

        return implode(':', $parts);
    }

    /**
     * Get current usage for an identifier.
     *
     * @return array{
     *     current: int,
     *     limit: int,
     *     remaining: int,
     *     reset: int,
     *     tier: string|null
     * }
     */
    public function getUsage(string $identifier, string $endpoint = '/', ?string $apiKey = null): array
    {
        $config = $this->getEffectiveConfig($endpoint, $apiKey);
        $key = $this->buildKey($identifier, $endpoint, $apiKey);
        $now = time();

        // Get current count based on algorithm
        $current = 0;

        switch ($this->algorithm) {
            case 'token_bucket':
                $bucketKey = "api_rate:bucket:{$key}";
                $state = $this->storage->get($bucketKey);
                if ($state !== null) {
                    $data = json_decode($state, true);
                    $tokens = $data['tokens'] ?? ($config['limit'] + ($config['burst'] ?? 0));
                    $current = $config['limit'] + ($config['burst'] ?? 0) - $tokens;
                }
                break;

            case 'sliding_window':
                $windowKey = "api_rate:sliding:{$key}";
                $state = $this->storage->get($windowKey);
                if ($state !== null) {
                    $timestamps = json_decode($state, true) ?? [];
                    $windowStart = $now - $config['window'];
                    $timestamps = array_filter($timestamps, fn ($ts) => $ts > $windowStart);
                    $current = count($timestamps);
                }
                break;

            case 'fixed_window':
                $windowNumber = (int) ($now / $config['window']);
                $windowKey = "api_rate:fixed:{$key}:{$windowNumber}";
                $state = $this->storage->get($windowKey);
                if ($state !== null) {
                    $current = (int) $state;
                }
                break;
        }

        return [
            'current' => $current,
            'limit' => $config['limit'],
            'remaining' => max(0, $config['limit'] - $current),
            'reset' => $now + $config['window'],
            'tier' => $config['tier'] ?? null,
        ];
    }

    /**
     * Register an API key with a tier.
     */
    public function registerApiKey(string $apiKey, string $tier, array $overrides = []): self
    {
        $this->apiKeyLimits[$apiKey] = array_merge(
            ['tier' => $tier],
            $overrides,
        );

        return $this;
    }

    /**
     * Set endpoint limit.
     *
     * @param array{limit?: int, window?: int, cost?: int} $config
     */
    public function setEndpointLimit(string $pattern, array $config): self
    {
        $this->endpointLimits[$pattern] = $config;

        return $this;
    }

    /**
     * Define a tier.
     *
     * @param array{limit: int, window?: int, burst?: int} $config
     */
    public function defineTier(string $name, array $config): self
    {
        $this->tiers[$name] = array_merge(
            ['window' => $this->defaultWindow, 'burst' => 0],
            $config,
        );

        return $this;
    }

    /**
     * Get rate limit headers for HTTP response.
     *
     * @param array{limit: int, remaining: int, reset: int, retry_after?: int|null} $result
     *
     * @return array<string, string>
     */
    public function getHeaders(array $result): array
    {
        $headers = [
            'X-RateLimit-Limit' => (string) $result['limit'],
            'X-RateLimit-Remaining' => (string) $result['remaining'],
            'X-RateLimit-Reset' => (string) $result['reset'],
        ];

        if (isset($result['retry_after']) && $result['retry_after'] !== null) {
            $headers['Retry-After'] = (string) $result['retry_after'];
        }

        return $headers;
    }

    /**
     * Reset rate limit for an identifier.
     */
    public function reset(string $identifier, string $endpoint = '/', ?string $apiKey = null): void
    {
        $key = $this->buildKey($identifier, $endpoint, $apiKey);

        // Clear all algorithm keys
        $patterns = [
            "api_rate:bucket:{$key}",
            "api_rate:sliding:{$key}",
        ];

        foreach ($patterns as $pattern) {
            $this->storage->delete($pattern);
        }

        // For fixed window, we can't easily delete without knowing the window number
        // The key will naturally expire
    }
}
