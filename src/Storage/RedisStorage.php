<?php

namespace Senza1dio\SecurityShield\Storage;

use Senza1dio\SecurityShield\Contracts\StorageInterface;

/**
 * Redis Storage Backend - High Performance
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
     */
    public function setScore(string $ip, int $score, int $ttl): bool
    {
        $key = $this->keyPrefix . 'score:' . $ip;
        return $this->redis->setex($key, $ttl, (string) $score) !== false;
    }

    /**
     * {@inheritDoc}
     */
    public function getScore(string $ip): ?int
    {
        $key = $this->keyPrefix . 'score:' . $ip;
        $score = $this->redis->get($key);

        if ($score === false || $score === null) {
            return null;
        }

        return is_numeric($score) ? (int) $score : null;
    }

    /**
     * {@inheritDoc}
     */
    public function incrementScore(string $ip, int $points, int $ttl): int
    {
        $key = $this->keyPrefix . 'score:' . $ip;

        // Atomic increment
        $newScore = $this->redis->incrBy($key, $points);

        // Handle Redis return type (int|bool)
        if (!is_int($newScore)) {
            return 0;
        }

        // Set TTL if key was just created
        if ($newScore === $points) {
            $this->redis->expire($key, $ttl);
        }

        return $newScore;
    }

    /**
     * {@inheritDoc}
     */
    public function isBanned(string $ip): bool
    {
        $key = $this->keyPrefix . 'ban:' . $ip;
        $exists = $this->redis->exists($key);
        return is_int($exists) && $exists > 0;
    }

    /**
     * {@inheritDoc}
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

        return $this->redis->setex($key, $duration, $data) !== false;
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
     */
    public function logSecurityEvent(string $type, string $ip, array $data): bool
    {
        $key = $this->keyPrefix . 'events:' . $type;
        $event = json_encode([
            'type' => $type,
            'ip' => $ip,
            'data' => $data,
            'timestamp' => time(),
        ]);

        // Store in Redis list (LPUSH for newest first)
        // Keep last 10,000 events per type
        $this->redis->lPush($key, $event);
        $this->redis->lTrim($key, 0, 9999);

        // Set 30-day expiration on the list
        $this->redis->expire($key, 2592000);

        return true;
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
            // Get events from all types
            $pattern = $this->keyPrefix . 'events:*';
            $keys = $this->redis->keys($pattern);

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
            usort($events, function($a, $b) {
                return ($b['timestamp'] ?? 0) <=> ($a['timestamp'] ?? 0);
            });

            // Limit to requested count
            $events = array_slice($events, 0, $limit);
        }

        return $events;
    }

    /**
     * {@inheritDoc}
     */
    public function incrementRequestCount(string $ip, int $window): int
    {
        $key = $this->keyPrefix . 'rate_limit:' . $ip;

        // Atomic increment
        $count = $this->redis->incr($key);

        // Handle Redis return type
        if (!is_int($count)) {
            return 1;
        }

        // Set TTL if key was just created (count == 1)
        if ($count === 1) {
            $this->redis->expire($key, $window);
        }

        return $count;
    }

    /**
     * {@inheritDoc}
     */
    public function getRequestCount(string $ip, int $window): int
    {
        $key = $this->keyPrefix . 'rate_limit:' . $ip;
        $count = $this->redis->get($key);

        if ($count === false || !is_numeric($count)) {
            return 0;
        }

        return (int) $count;
    }

    /**
     * {@inheritDoc}
     */
    public function clear(): bool
    {
        $pattern = $this->keyPrefix . '*';
        $keys = $this->redis->keys($pattern);

        if (empty($keys)) {
            return true;
        }

        $deleted = $this->redis->del($keys);
        return is_int($deleted) && $deleted > 0;
    }

    /**
     * Get Redis instance (for custom operations)
     *
     * @return \Redis
     */
    public function getRedis(): \Redis
    {
        return $this->redis;
    }

    /**
     * Get key prefix
     *
     * @return string
     */
    public function getKeyPrefix(): string
    {
        return $this->keyPrefix;
    }
}
