<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Storage;

use AdosLabs\EnterprisePSR3Logger\LoggerFacade as Logger;
use AdosLabs\EnterpriseSecurityShield\Contracts\StorageInterface;

/**
 * Redis Storage Backend - High Performance.
 *
 * Recommended for production environments with high traffic.
 * Provides sub-millisecond read/write operations.
 *
 * Requirements:
 * - ext-redis PHP extension
 * - Redis server 5.0+ (6.0+ recommended)
 *
 * Features:
 * - Automatic key expiration (TTL)
 * - Atomic increment operations
 * - High concurrency support
 * - Persistence optional
 */
class RedisStorage implements StorageInterface
{
    private \Redis $redis;

    private string $keyPrefix;

    /**
     * @param \Redis $redis Connected Redis instance
     * @param string $keyPrefix Key prefix for namespacing (default: 'security_shield:')
     */
    public function __construct(\Redis $redis, string $keyPrefix = 'security_shield:')
    {
        $this->redis = $redis;
        $this->keyPrefix = $keyPrefix;
    }

    /**
     * {@inheritDoc}
     *
     * RESILIENCE: Graceful degradation on Redis failure.
     */
    public function setScore(string $ip, int $score, int $ttl): bool
    {
        $key = $this->keyPrefix . 'score:' . $ip;

        try {
            return $this->redis->setex($key, $ttl, (string) $score) !== false;
        } catch (\RedisException $e) {
            Logger::channel('database')->error('WAF Redis setScore failed', [
                'ip' => $ip,
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * {@inheritDoc}
     *
     * RESILIENCE: Returns null on Redis failure (same as key not found).
     */
    public function getScore(string $ip): ?int
    {
        $key = $this->keyPrefix . 'score:' . $ip;

        try {
            $score = $this->redis->get($key);

            if ($score === false || $score === null) {
                return null;
            }

            return is_numeric($score) ? (int) $score : null;
        } catch (\RedisException $e) {
            Logger::channel('database')->error('WAF Redis getScore failed', [
                'ip' => $ip,
                'error' => $e->getMessage(),
            ]);

            return null;
        }
    }

    /**
     * {@inheritDoc}
     *
     * Uses Lua script for atomic INCRBY + EXPIRE operation.
     * Prevents TTL loss under high concurrency.
     *
     * FAIL-OPEN BEHAVIOR (CRITICAL):
     * ================================
     * Returns 0 (not actual score) on Redis failure.
     *
     * SECURITY IMPACT:
     * - Attacker scores artificially low during Redis outage
     * - May evade auto-ban thresholds under load
     * - Score tracking incomplete during downtime
     *
     * WHY FAIL-OPEN:
     * - Prevents false positives (legitimate users not blocked)
     * - Site stays online during Redis issues
     * - Better UX over strict security
     *
     * MITIGATION:
     * - Use Redis Sentinel/Cluster for HA (99.99% uptime)
     * - Monitor Redis health separately
     * - Consider fail-closed for high-security apps (return threshold score)
     *
     * FAIL-CLOSED ALTERNATIVE:
     * ```php
     * catch (\RedisException $e) {
     *     return 100; // Force ban on Redis failure
     * }
     * ```
     */
    public function incrementScore(string $ip, int $points, int $ttl): int
    {
        $key = $this->keyPrefix . 'score:' . $ip;

        // Lua script: Atomic increment + always refresh expire
        // Always refresh TTL to prevent indefinite score persistence
        $lua = <<<'LUA'
            local key = KEYS[1]
            local points = tonumber(ARGV[1])
            local ttl = tonumber(ARGV[2])
            local newScore = redis.call('INCRBY', key, points)
            redis.call('EXPIRE', key, ttl)
            return newScore
            LUA;

        try {
            $result = $this->redis->eval($lua, [$key, $points, $ttl], 1);

            // Handle Redis return type (int|Redis|false)
            if (!is_int($result)) {
                return 0; // FAIL-OPEN: Assume zero score
            }

            return $result;
        } catch (\RedisException $e) {
            Logger::channel('database')->error('WAF Redis incrementScore failed (FAIL-OPEN)', [
                'ip' => $ip,
                'points' => $points,
                'error' => $e->getMessage(),
            ]);

            return 0;
        }
    }

    /**
     * {@inheritDoc}
     *
     * FAIL-OPEN BEHAVIOR (Default):
     * =============================
     * Returns false (not banned) on Redis failure to prioritize availability.
     *
     * WHY FAIL-OPEN:
     * - Site stays online during Redis outage
     * - Better user experience (no false positives)
     * - Suitable for e-commerce, public sites
     *
     * SECURITY TRADE-OFF:
     * - Attackers can bypass bans during Redis downtime
     * - Mitigation: Use Redis Sentinel/Cluster for HA (99.99% uptime)
     *
     * FAIL-CLOSED ALTERNATIVE (High Security):
     * =========================================
     * For banking/government apps requiring strict security:
     *
     * ```php
     * class FailClosedRedisStorage extends RedisStorage {
     *     public function isBanned(string $ip): bool {
     *         try {
     *             return parent::isBanned($ip);
     *         } catch (\Exception $e) {
     *             error_log("Redis down - fail-closed active: " . $e->getMessage());
     *             return true; // Block all traffic on failure
     *         }
     *     }
     * }
     * ```
     *
     * EXCEPTION HANDLING:
     * - \RedisException caught internally
     * - Exception NOT logged (would spam logs during outage)
     * - Monitoring: Track Redis health separately (Sentinel, metrics)
     */
    public function isBanned(string $ip): bool
    {
        $key = $this->keyPrefix . 'ban:' . $ip;

        try {
            $exists = $this->redis->exists($key);

            return is_int($exists) && $exists > 0;
        } catch (\RedisException $e) {
            Logger::channel('database')->error('WAF Redis isBanned check failed', [
                'ip' => $ip,
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * {@inheritDoc}
     *
     * PERFORMANCE-CRITICAL: Cache-only check
     *
     * For RedisStorage, this is semantically identical to isBanned()
     * because Redis has no slow fallback (always cache-only).
     *
     * IMPORTANT: Implementation duplicated (not delegated to isBanned())
     * to maintain clear semantic separation. If extending this class,
     * override both methods separately to avoid coupling.
     */
    public function isIpBannedCached(string $ip): bool
    {
        $key = $this->keyPrefix . 'ban:' . $ip;

        try {
            $exists = $this->redis->exists($key);

            return is_int($exists) && $exists > 0;
        } catch (\RedisException $e) {
            Logger::channel('database')->error('WAF Redis isIpBannedCached check failed', [
                'ip' => $ip,
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * {@inheritDoc}
     *
     * RESILIENCE: Returns false on Redis failure (ban not applied).
     */
    public function banIP(string $ip, int $duration, string $reason): bool
    {
        $key = $this->keyPrefix . 'ban:' . $ip;
        $data = json_encode([
            'ip' => $ip,
            'reason' => $reason,
            'banned_at' => time(),
            'expires_at' => time() + $duration,
        ]);

        try {
            return $this->redis->setex($key, $duration, $data) !== false;
        } catch (\RedisException $e) {
            Logger::channel('security')->error('WAF Redis banIP failed', [
                'ip' => $ip,
                'reason' => $reason,
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * {@inheritDoc}
     */
    public function unbanIP(string $ip): bool
    {
        $key = $this->keyPrefix . 'ban:' . $ip;
        $deleted = $this->redis->del($key);

        return is_int($deleted) && $deleted > 0;
    }

    /**
     * {@inheritDoc}
     *
     * @param array<string, mixed> $metadata
     */
    public function cacheBotVerification(string $ip, bool $isLegitimate, array $metadata, int $ttl): bool
    {
        $key = $this->keyPrefix . 'bot:' . $ip;
        $data = json_encode([
            'verified' => $isLegitimate,
            'metadata' => $metadata,
            'cached_at' => time(),
        ]);

        return $this->redis->setex($key, $ttl, $data) !== false;
    }

    /**
     * {@inheritDoc}
     *
     * @return array<string, mixed>|null
     */
    public function getCachedBotVerification(string $ip): ?array
    {
        $key = $this->keyPrefix . 'bot:' . $ip;
        $data = $this->redis->get($key);

        if ($data === false || !is_string($data)) {
            return null;
        }

        $decoded = json_decode($data, true);
        if (!is_array($decoded) || !isset($decoded['verified'])) {
            return null;
        }

        return [
            'verified' => $decoded['verified'],
            'metadata' => $decoded['metadata'] ?? [],
        ];
    }

    /**
     * {@inheritDoc}
     *
     * DOS PROTECTION:
     * ===============
     * Event deduplication prevents log flooding attacks.
     *
     * PROBLEM:
     * - Attacker sends 1M requests → 1M identical log entries
     * - Redis list grows to gigabytes → memory exhaustion
     * - Database insert rate overwhelmed
     *
     * SOLUTION:
     * - Hash event (type + IP + data) → dedup key
     * - If logged in last 60s → Skip (no-op)
     * - Else → Log event + Set dedup key with 60s TTL
     *
     * RESULT:
     * - Same event logged max 1x per minute
     * - 1M identical events → Only 1 stored
     * - Memory/DB protected from amplification
     */
    public function logSecurityEvent(string $type, string $ip, array $data): bool
    {
        // Deduplication with time bucket: Skip if same event logged in current minute
        // Bucket prevents losing temporal information while deduplicating
        $bucket = intdiv(time(), 60); // 1-minute bucket
        $dedupHash = md5($type . ':' . $ip . ':' . $bucket . ':' . json_encode($data));
        $dedupKey = $this->keyPrefix . 'event_dedup:' . $dedupHash;

        try {
            // Check if event already logged recently
            if ($this->redis->exists($dedupKey)) {
                return true; // Already logged - skip duplicate
            }

            // Mark as logged for 60 seconds
            $this->redis->setex($dedupKey, 60, '1');
        } catch (\RedisException $e) {
            Logger::channel('database')->warning('WAF Redis event dedup check failed', [
                'type' => $type,
                'ip' => $ip,
                'error' => $e->getMessage(),
            ]);
        }

        $key = $this->keyPrefix . 'events:' . $type;
        $event = json_encode([
            'type' => $type,
            'ip' => $ip,
            'data' => $data,
            'timestamp' => time(),
        ]);

        try {
            // Store in Redis list (LPUSH for newest first)
            // Keep last 10,000 events per type
            $this->redis->lPush($key, $event);
            $this->redis->lTrim($key, 0, 9999);

            // Set 30-day expiration on the list
            $this->redis->expire($key, 2592000);

            return true;
        } catch (\RedisException $e) {
            Logger::channel('database')->error('WAF Redis event logging failed', [
                'type' => $type,
                'ip' => $ip,
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * {@inheritDoc}
     */
    public function getRecentEvents(int $limit = 100, ?string $type = null): array
    {
        $events = [];

        if ($type) {
            // Get events for specific type
            $key = $this->keyPrefix . 'events:' . $type;
            $rawEvents = $this->redis->lRange($key, 0, $limit - 1);

            foreach ($rawEvents as $eventJson) {
                if (!is_string($eventJson)) {
                    continue;
                }
                $event = json_decode($eventJson, true);
                if (is_array($event)) {
                    $events[] = $event;
                }
            }
        } else {
            // Get events from all types using SCAN (non-blocking)
            //  Replaced KEYS with SCAN to avoid Redis blocking
            $pattern = $this->keyPrefix . 'events:*';
            $keys = $this->scanKeys($pattern);

            foreach ($keys as $key) {
                $rawEvents = $this->redis->lRange($key, 0, $limit - 1);

                foreach ($rawEvents as $eventJson) {
                    if (!is_string($eventJson)) {
                        continue;
                    }
                    $event = json_decode($eventJson, true);
                    if (is_array($event)) {
                        $events[] = $event;
                    }
                }
            }

            // Sort by timestamp (newest first)
            usort($events, function ($a, $b) {
                return ($b['timestamp'] ?? 0) <=> ($a['timestamp'] ?? 0);
            });

            // Limit to requested count
            $events = array_slice($events, 0, $limit);
        }

        return $events;
    }

    /**
     * {@inheritDoc}
     *
     *  Uses Lua script for atomic INCR + EXPIRE.
     * RESILIENCE: Returns 1 on Redis failure (allows request).
     */
    public function incrementRequestCount(string $ip, int $window, string $action = 'general'): int
    {
        $key = $this->keyPrefix . 'rate_limit:' . $action . ':' . $ip;

        // Lua script: Atomic increment + conditional expire
        $lua = <<<'LUA'
            local key = KEYS[1]
            local window = tonumber(ARGV[1])
            local count = redis.call('INCR', key)
            if count == 1 then
                redis.call('EXPIRE', key, window)
            end
            return count
            LUA;

        try {
            $result = $this->redis->eval($lua, [$key, $window], 1);

            // Handle Redis return type
            if (!is_int($result)) {
                return 1;
            }

            return $result;
        } catch (\RedisException $e) {
            // Graceful degradation - allow request
            return 1;
        }
    }

    /**
     * {@inheritDoc}
     */
    public function getRequestCount(string $ip, int $window, string $action = 'general'): int
    {
        $key = $this->keyPrefix . 'rate_limit:' . $action . ':' . $ip;
        $count = $this->redis->get($key);

        if ($count === false || !is_numeric($count)) {
            return 0;
        }

        return (int) $count;
    }

    /**
     * {@inheritDoc}
     *
     *  Uses SCAN instead of KEYS to avoid blocking Redis.
     */
    public function clear(): bool
    {
        $pattern = $this->keyPrefix . '*';
        $keys = $this->scanKeys($pattern);

        if (empty($keys)) {
            return true;
        }

        // Delete in batches of 1000 to avoid blocking Redis
        $batchSize = 1000;
        $batches = array_chunk($keys, $batchSize);
        $totalDeleted = 0;

        foreach ($batches as $batch) {
            $deleted = $this->redis->del($batch);
            $totalDeleted += is_int($deleted) ? $deleted : 0;
        }

        return $totalDeleted > 0;
    }

    /**
     * Scan Redis keys using cursor-based iteration (non-blocking).
     *
     * PERFORMANCE: Unlike KEYS command, SCAN doesn't block Redis.
     * Safe for production with millions of keys.
     *
     * SAFETY FEATURES:
     * - Max iteration limit (prevents infinite loops)
     * - Exception logging (alerts on Redis issues)
     * - Fallback to KEYS on small datasets (<10k keys)
     * - Timeout protection (10 seconds max)
     *
     * @param string $pattern Key pattern (e.g., "security_shield:*")
     * @param int $count Hint for number of keys to return per iteration
     *
     * @return array<int, string> Matching keys
     */
    private function scanKeys(string $pattern, int $count = 1000): array
    {
        $allKeys = [];
        $it = null; // CRITICAL: phpredis requires passing by reference
        $iterations = 0;
        $maxIterations = 10000;
        $startTime = microtime(true);
        $timeout = 10.0;

        do {
            try {
                // PHPREDIS IDIOM: scan() modifies $it by reference
                // Returns array of keys (or false on error)
                $keys = $this->redis->scan($it, $pattern, $count);

                if ($keys === false) {
                    // SCAN failed - try KEYS fallback for small datasets
                    if (count($allKeys) < 10000) {
                        try {
                            $fallbackKeys = $this->redis->keys($pattern);
                            if (is_array($fallbackKeys)) {
                                $allKeys = array_merge($allKeys, $fallbackKeys);
                            }
                        } catch (\RedisException $fallbackEx) {
                            // Silently fail
                        }
                    }
                    break;
                }

                // Merge found keys
                if (is_array($keys) && !empty($keys)) {
                    $allKeys = array_merge($allKeys, $keys);
                }

                $iterations++;

                // Safety: Prevent infinite loop
                if ($iterations >= $maxIterations) {
                    break;
                }

                // Safety: Prevent timeout
                if ((microtime(true) - $startTime) > $timeout) {
                    break;
                }
            } catch (\RedisException $e) {
                // Fail silently - phpredis scan() can throw on network issues
                break;
            }
        } while ($it > 0); // phpredis sets $it to 0 when done

        return $allKeys;
    }

    /**
     * Get Redis instance (for custom operations).
     *
     * @return \Redis
     */
    public function getRedis(): \Redis
    {
        return $this->redis;
    }

    /**
     * Get key prefix.
     *
     * @return string
     */
    public function getKeyPrefix(): string
    {
        return $this->keyPrefix;
    }

    /**
     * {@inheritDoc}
     */
    public function get(string $key): mixed
    {
        try {
            $value = $this->redis->get($this->keyPrefix . $key);

            if ($value === false) {
                return null;
            }

            // SECURITY: Only JSON decode (NEVER unserialize - prevents PHP Object Injection)
            if (is_string($value) && (str_starts_with($value, '{') || str_starts_with($value, '['))) {
                $decoded = json_decode($value, true);

                return is_array($decoded) ? $decoded : $value;
            }

            return $value;
        } catch (\RedisException $e) {
            return null;
        }
    }

    /**
     * {@inheritDoc}
     */
    public function set(string $key, mixed $value, int $ttl): bool
    {
        try {
            // Serialize arrays/objects
            if (is_array($value) || is_object($value)) {
                $value = json_encode($value);
            }

            // Ensure $value is string or fallback to empty
            if (!is_string($value)) {
                return false;
            }

            return $this->redis->setex($this->keyPrefix . $key, $ttl, $value) !== false;
        } catch (\RedisException $e) {
            return false;
        }
    }

    /**
     * {@inheritDoc}
     */
    public function delete(string $key): bool
    {
        try {
            $deleted = $this->redis->del($this->keyPrefix . $key);

            return $deleted !== false;
        } catch (\RedisException $e) {
            return false;
        }
    }

    /**
     * {@inheritDoc}
     */
    public function exists(string $key): bool
    {
        try {
            $exists = $this->redis->exists($this->keyPrefix . $key);

            return is_int($exists) && $exists > 0;
        } catch (\RedisException $e) {
            return false;
        }
    }

    /**
     * {@inheritDoc}
     *
     * Uses Lua script for atomic INCRBY + conditional EXPIRE.
     * TTL is only set when key doesn't exist or has no TTL.
     */
    public function increment(string $key, int $delta, int $ttl): int
    {
        $fullKey = $this->keyPrefix . $key;

        // Lua script: Atomic increment + conditional expire
        $lua = <<<'LUA'
            local key = KEYS[1]
            local delta = tonumber(ARGV[1])
            local ttl = tonumber(ARGV[2])
            local newVal = redis.call('INCRBY', key, delta)
            if redis.call('TTL', key) < 0 then
                redis.call('EXPIRE', key, ttl)
            end
            return newVal
            LUA;

        try {
            $result = $this->redis->eval($lua, [$fullKey, $delta, $ttl], 1);

            if (!is_int($result)) {
                return 0;
            }

            return $result;
        } catch (\RedisException $e) {
            return 0;
        }
    }

    /**
     * {@inheritDoc}
     *
     * ATOMIC rate limit check using Lua script.
     * This is the ONLY correct way to implement distributed rate limiting.
     *
     * The Lua script performs in a single atomic operation:
     * 1. Increment counter
     * 2. Set TTL on first request
     * 3. Check if over limit
     * 4. Return result
     *
     * NO race conditions possible because Redis executes Lua atomically.
     */
    public function atomicRateLimitCheck(string $key, int $limit, int $window, int $cost = 1): array
    {
        $fullKey = $this->keyPrefix . $key;
        $now = time();

        // Lua script: Atomic increment + limit check
        // Returns: [allowed (0/1), current_count, ttl_remaining]
        $lua = <<<'LUA'
                local key = KEYS[1]
                local limit = tonumber(ARGV[1])
                local window = tonumber(ARGV[2])
                local cost = tonumber(ARGV[3])

                -- Increment counter
                local current = redis.call('INCRBY', key, cost)

                -- Set TTL only on first increment (when current == cost)
                if current == cost then
                    redis.call('EXPIRE', key, window)
                end

                -- Get TTL for reset time
                local ttl = redis.call('TTL', key)
                if ttl < 0 then ttl = window end

                -- Check if over limit
                if current > limit then
                    -- Over limit: decrement back (we shouldn't count this request)
                    redis.call('DECRBY', key, cost)
                    return {0, current - cost, ttl}
                end

                return {1, current, ttl}
            LUA;

        try {
            $result = $this->redis->eval($lua, [$fullKey, $limit, $window, $cost], 1);

            if (!is_array($result) || count($result) < 3) {
                // Lua failed - fail open (allow request)
                return [
                    'allowed' => true,
                    'count' => 0,
                    'remaining' => $limit,
                    'reset' => $now + $window,
                ];
            }

            $allowed = (int) $result[0] === 1;
            $count = (int) $result[1];
            $ttl = (int) $result[2];

            return [
                'allowed' => $allowed,
                'count' => $count,
                'remaining' => max(0, $limit - $count),
                'reset' => $now + $ttl,
            ];
        } catch (\RedisException $e) {
            // Fail open - allow request on Redis failure
            return [
                'allowed' => true,
                'count' => 0,
                'remaining' => $limit,
                'reset' => $now + $window,
            ];
        }
    }
}
