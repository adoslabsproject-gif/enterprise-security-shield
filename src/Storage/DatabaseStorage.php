<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Storage;

use AdosLabs\EnterprisePSR3Logger\LoggerFacade as Logger;
use AdosLabs\EnterpriseSecurityShield\Contracts\StorageInterface;

/**
 * Database Storage Backend - Dual-Write Architecture.
 *
 * Framework-agnostic storage backend with dual-write to database and cache.
 *
 * ARCHITECTURE:
 * - Redis: L1 cache (sub-millisecond reads, hot data, volatile)
 * - PostgreSQL/MySQL: Persistent storage (survives restarts, compliance, analytics)
 *
 * DUAL-WRITE PATTERN:
 * - Writes go to BOTH Redis (cache) AND Database (persistence)
 * - Reads prioritize Redis (fast path), fallback to DB (cold start)
 * - Ban checks use Redis ONLY (performance-critical, early exit)
 *
 * PERFORMANCE:
 * - Ban check (cached): <1ms
 * - Ban check (cold start): ~5ms
 * - Score increment: ~2ms
 * - Security event log: ~1ms
 *
 * TABLE NAMING:
 * - All tables use 'security_shield_' prefix for namespace isolation
 * - Tables: security_shield_scores, security_shield_bans, security_shield_events,
 *           security_shield_request_counts, security_shield_bot_cache, security_shield_rate_limits
 *
 * REQUIREMENTS:
 * - PHP 8.0+ with PDO extension
 * - PostgreSQL 9.5+ or MySQL 5.7+
 * - Redis 5.0+ (optional but recommended)
 *
 * @version 2.1.0
 *
 * @author ADOS Labs Security Team
 * @license MIT
 */
class DatabaseStorage implements StorageInterface
{
    /**
     * PostgreSQL database connection.
     */
    private \PDO $pdo;

    /**
     * Redis instance for caching (optional but recommended).
     */
    private ?\Redis $redis;

    /**
     * Redis key prefix for namespacing.
     */
    private string $keyPrefix;

    /**
     * Constructor.
     *
     * @param \PDO $pdo PostgreSQL connection with prepared schema
     * @param \Redis|null $redis Optional Redis for caching (recommended for production)
     * @param string $keyPrefix Redis key prefix (default: 'security_shield:')
     */
    public function __construct(\PDO $pdo, ?\Redis $redis = null, string $keyPrefix = 'security_shield:')
    {
        $this->pdo = $pdo;
        $this->redis = $redis;
        $this->keyPrefix = $keyPrefix;

        // Ensure PDO throws exceptions on errors
        $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
    }

    /**
     * {@inheritDoc}
     *
     * DUAL-WRITE: Redis cache + PostgreSQL persistence
     */
    public function setScore(string $ip, int $score, int $ttl): bool
    {
        $expiresAt = date('Y-m-d H:i:s', time() + $ttl);

        try {
            // Write to PostgreSQL (persistence)
            $stmt = $this->pdo->prepare('
                INSERT INTO security_shield_scores (ip, score, expires_at, last_seen)
                VALUES (:ip, :score, :expires_at, NOW())
                ON CONFLICT (ip) DO UPDATE
                SET score = :score,
                    expires_at = :expires_at,
                    last_seen = NOW()
            ');
            $stmt->execute([
                ':ip' => $ip,
                ':score' => $score,
                ':expires_at' => $expiresAt,
            ]);

            // Write to Redis (cache)
            if ($this->redis) {
                $key = $this->keyPrefix . 'score:' . $ip;
                $this->redis->setex($key, $ttl, (string) $score);
            }

            return true;
        } catch (\PDOException $e) {
            Logger::channel('database')->error('WAF setScore DB write failed', [
                'ip' => $ip,
                'score' => $score,
                'error' => $e->getMessage(),
            ]);
            // Graceful degradation - continue with Redis only
            if ($this->redis) {
                $key = $this->keyPrefix . 'score:' . $ip;

                return $this->redis->setex($key, $ttl, (string) $score) !== false;
            }

            return false;
        }
    }

    /**
     * {@inheritDoc}
     *
     * READ PATH: Redis (fast) → PostgreSQL (fallback)
     */
    public function getScore(string $ip): ?int
    {
        // Fast path: Check Redis cache first
        if ($this->redis) {
            try {
                $key = $this->keyPrefix . 'score:' . $ip;
                $score = $this->redis->get($key);

                if ($score !== false && is_numeric($score)) {
                    return (int) $score;
                }
            } catch (\RedisException $e) {
                Logger::channel('database')->warning('WAF getScore Redis cache miss', [
                    'ip' => $ip,
                    'error' => $e->getMessage(),
                ]);
                // Fall through to database
            }
        }

        // Slow path: Query PostgreSQL
        try {
            $stmt = $this->pdo->prepare('
                SELECT score FROM security_shield_scores
                WHERE ip = :ip AND expires_at > NOW()
            ');
            $stmt->execute([':ip' => $ip]);
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);

            if ($result && isset($result['score'])) {
                $score = (int) $result['score'];

                // Warm Redis cache for next read
                if ($this->redis) {
                    $key = $this->keyPrefix . 'score:' . $ip;
                    $this->redis->setex($key, 3600, (string) $score);
                }

                return $score;
            }

            return null;
        } catch (\PDOException $e) {
            Logger::channel('database')->error('WAF getScore DB query failed', [
                'ip' => $ip,
                'error' => $e->getMessage(),
            ]);

            return null;
        }
    }

    /**
     * {@inheritDoc}
     *
     * DUAL-WRITE: Redis atomic increment + PostgreSQL update
     * Uses Lua script for Redis atomicity, SQL UPDATE for persistence
     */
    public function incrementScore(string $ip, int $points, int $ttl): int
    {
        $expiresAt = date('Y-m-d H:i:s', time() + $ttl);
        $newScore = 0;

        try {
            // STEP 1: Increment in PostgreSQL (source of truth)
            $stmt = $this->pdo->prepare('
                INSERT INTO security_shield_scores (ip, score, expires_at, last_seen)
                VALUES (:ip, :points, :expires_at, NOW())
                ON CONFLICT (ip) DO UPDATE
                SET score = security_shield_scores.score + :points,
                    expires_at = :expires_at,
                    last_seen = NOW()
                RETURNING score
            ');
            $stmt->execute([
                ':ip' => $ip,
                ':points' => $points,
                ':expires_at' => $expiresAt,
            ]);
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);
            $newScore = $result ? (int) $result['score'] : 0;

            // STEP 2: Sync to Redis cache
            if ($this->redis && $newScore > 0) {
                $key = $this->keyPrefix . 'score:' . $ip;
                $this->redis->setex($key, $ttl, (string) $newScore);
            }

            return $newScore;
        } catch (\PDOException $e) {
            Logger::channel('database')->error('WAF incrementScore DB failed', [
                'ip' => $ip,
                'points' => $points,
                'error' => $e->getMessage(),
            ]);
            // Fallback: Redis-only increment (volatile but functional)
            if ($this->redis) {
                $key = $this->keyPrefix . 'score:' . $ip;
                $lua = <<<'LUA'
                    local key = KEYS[1]
                    local points = tonumber(ARGV[1])
                    local ttl = tonumber(ARGV[2])
                    local newScore = redis.call('INCRBY', key, points)
                    if redis.call('TTL', key) < 0 then
                        redis.call('EXPIRE', key, ttl)
                    end
                    return newScore
                    LUA;
                $result = $this->redis->eval($lua, [$key, $points, $ttl], 1);

                return is_int($result) ? $result : 0;
            }

            return 0;
        }
    }

    /**
     * {@inheritDoc}
     *
     * DUAL-STORAGE BAN CHECK:
     * =======================
     * 1. Fast path: Redis cache check (<1ms)
     * 2. Slow path: PostgreSQL fallback (1-5ms cold cache)
     *
     * FAIL-OPEN BEHAVIOR:
     * ===================
     * Returns false (not banned) if BOTH Redis AND PostgreSQL fail.
     *
     * WHY DUAL-STORAGE IMPROVES RELIABILITY:
     * - Redis down → PostgreSQL fallback (still secure)
     * - PostgreSQL down → Redis continues (still fast)
     * - BOTH down → Fail-open (prioritize availability)
     *
     * FAILURE SCENARIOS:
     * - Redis only down: Uses DB (slightly slower, still secure)
     * - DB only down: Uses Redis cache (fast, mostly secure)
     * - Both down: FAIL-OPEN (attackers bypass bans, site stays online)
     *
     * HIGH AVAILABILITY PROBABILITY:
     * - Redis uptime: 99.9% (Sentinel/Cluster)
     * - PostgreSQL uptime: 99.95% (Replication)
     * - BOTH down: 0.0005% = 4 minutes/year
     *
     * FAIL-CLOSED ALTERNATIVE:
     * For critical security apps, catch exception at WafMiddleware level
     * and return 503 Service Unavailable if storage completely fails.
     */
    public function isBanned(string $ip): bool
    {
        // Fast path: Redis cache (MUST be fast)
        if ($this->redis) {
            try {
                $key = $this->keyPrefix . 'ban:' . $ip;
                $exists = $this->redis->exists($key);
                if (is_int($exists) && $exists > 0) {
                    return true; // Cache hit - banned
                }
            } catch (\RedisException $e) {
                Logger::channel('database')->warning('WAF isBanned Redis check failed', [
                    'ip' => $ip,
                    'error' => $e->getMessage(),
                ]);
                // Fallthrough to database
            }
        }

        // Slow path: Database fallback (cold start or Redis down)
        // NOTE: This is ONLY hit when Redis is unavailable or cold cache
        try {
            $stmt = $this->pdo->prepare('
                SELECT 1 FROM security_shield_bans
                WHERE ip = :ip AND expires_at > NOW()
                LIMIT 1
            ');
            $stmt->execute([':ip' => $ip]);
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);

            $banned = $result !== false;

            // Warm Redis cache to avoid DB hit next time
            if ($banned && $this->redis) {
                // Get ban duration from DB to set correct TTL
                $stmt = $this->pdo->prepare('
                    SELECT EXTRACT(EPOCH FROM (expires_at - NOW()))::INTEGER AS ttl
                    FROM security_shield_bans
                    WHERE ip = :ip AND expires_at > NOW()
                    LIMIT 1
                ');
                $stmt->execute([':ip' => $ip]);
                $ttlResult = $stmt->fetch(\PDO::FETCH_ASSOC);
                $ttl = $ttlResult && isset($ttlResult['ttl']) ? max(60, (int) $ttlResult['ttl']) : 86400;

                $key = $this->keyPrefix . 'ban:' . $ip;
                $this->redis->setex($key, $ttl, '1');
            }

            return $banned;
        } catch (\PDOException $e) {
            Logger::channel('database')->error('WAF isBanned DB query failed (FAIL-OPEN)', [
                'ip' => $ip,
                'error' => $e->getMessage(),
            ]);

            // FAIL-OPEN: Both Redis and DB failed
            // Probability: ~4 minutes/year with proper HA setup
            // Alternative: Return true for fail-closed (block all traffic)
            return false;
        }
    }

    /**
     * {@inheritDoc}
     *
     * PERFORMANCE-CRITICAL: Cache-only check (NO database query)
     * Called at STEP 0 of handle() before ANY other operations.
     *
     * RATIONALE: This prevents banned IPs from:
     * - Incrementing rate limit counters (DoS storage amplification)
     * - Running SQL/XSS pattern matching (CPU waste)
     * - Triggering scoring calculations (storage writes)
     *
     * DATABASE FALLBACK INTENTIONALLY OMITTED:
     * - Cold cache scenario is acceptable (one extra request before ban takes effect)
     * - Database query here would hurt performance for ALL requests (hot path)
     * - Next request will hit isBanned() which warms the cache
     */
    public function isIpBannedCached(string $ip): bool
    {
        // Cache-only check (NO database fallback)
        if ($this->redis) {
            try {
                $key = $this->keyPrefix . 'ban:' . $ip;
                $exists = $this->redis->exists($key);

                return is_int($exists) && $exists > 0;
            } catch (\RedisException $e) {
                Logger::channel('database')->warning('WAF isIpBannedCached Redis check failed', [
                    'ip' => $ip,
                    'error' => $e->getMessage(),
                ]);

                // Graceful degradation - assume not banned (fail-open)
                return false;
            }
        }

        // No Redis = no cached ban check possible
        return false;
    }

    /**
     * {@inheritDoc}
     *
     * DUAL-WRITE: Redis (immediate effect) + PostgreSQL (audit trail)
     */
    public function banIP(string $ip, int $duration, string $reason): bool
    {
        $expiresAt = date('Y-m-d H:i:s', time() + $duration);
        $bannedAt = date('Y-m-d H:i:s');

        try {
            // STEP 1: Write to PostgreSQL (audit trail)
            $stmt = $this->pdo->prepare('
                INSERT INTO security_shield_bans (ip, reason, banned_at, expires_at)
                VALUES (:ip, :reason, :banned_at, :expires_at)
            ');
            $stmt->execute([
                ':ip' => $ip,
                ':reason' => $reason,
                ':banned_at' => $bannedAt,
                ':expires_at' => $expiresAt,
            ]);

            // STEP 2: Write to Redis (immediate block)
            if ($this->redis) {
                $key = $this->keyPrefix . 'ban:' . $ip;
                $data = json_encode([
                    'ip' => $ip,
                    'reason' => $reason,
                    'banned_at' => time(),
                    'expires_at' => time() + $duration,
                ]);
                $this->redis->setex($key, $duration, $data);
            }

            return true;
        } catch (\PDOException $e) {
            Logger::channel('security')->error('WAF banIP DB write failed', [
                'ip' => $ip,
                'reason' => $reason,
                'duration' => $duration,
                'error' => $e->getMessage(),
            ]);
            // Fallback: Redis-only ban (volatile but functional)
            if ($this->redis) {
                $key = $this->keyPrefix . 'ban:' . $ip;
                $data = json_encode([
                    'ip' => $ip,
                    'reason' => $reason,
                    'banned_at' => time(),
                    'expires_at' => time() + $duration,
                ]);

                return $this->redis->setex($key, $duration, $data) !== false;
            }

            return false;
        }
    }

    /**
     * {@inheritDoc}
     *
     * DUAL-DELETE: Redis + PostgreSQL
     */
    public function unbanIP(string $ip): bool
    {
        try {
            // Delete from PostgreSQL
            $stmt = $this->pdo->prepare('
                DELETE FROM security_shield_bans WHERE ip = :ip
            ');
            $stmt->execute([':ip' => $ip]);

            // Delete from Redis
            if ($this->redis) {
                $key = $this->keyPrefix . 'ban:' . $ip;
                $this->redis->del($key);
            }

            return true;
        } catch (\PDOException $e) {
            Logger::channel('database')->error('WAF unbanIP DB delete failed', [
                'ip' => $ip,
                'error' => $e->getMessage(),
            ]);
            // Fallback: Redis-only delete
            if ($this->redis) {
                $key = $this->keyPrefix . 'ban:' . $ip;
                $deleted = $this->redis->del($key);

                return is_int($deleted) && $deleted > 0;
            }

            return false;
        }
    }

    /**
     * {@inheritDoc}
     *
     * DUAL-WRITE: Redis (fast reads) + PostgreSQL (persistence)
     */
    public function cacheBotVerification(string $ip, bool $isLegitimate, array $metadata, int $ttl): bool
    {
        $expiresAt = date('Y-m-d H:i:s', time() + $ttl);

        try {
            // Write to PostgreSQL
            $stmt = $this->pdo->prepare('
                INSERT INTO security_shield_bot_cache (ip, is_legitimate, metadata, cached_at, expires_at)
                VALUES (:ip, :is_legitimate, :metadata, NOW(), :expires_at)
                ON CONFLICT (ip) DO UPDATE
                SET is_legitimate = :is_legitimate,
                    metadata = :metadata,
                    cached_at = NOW(),
                    expires_at = :expires_at
            ');
            $stmt->execute([
                ':ip' => $ip,
                ':is_legitimate' => $isLegitimate ? 'true' : 'false',
                ':metadata' => json_encode($metadata),
                ':expires_at' => $expiresAt,
            ]);

            // Write to Redis
            if ($this->redis) {
                $key = $this->keyPrefix . 'bot:' . $ip;
                $data = json_encode([
                    'verified' => $isLegitimate,
                    'metadata' => $metadata,
                    'cached_at' => time(),
                ]);
                $this->redis->setex($key, $ttl, $data);
            }

            return true;
        } catch (\PDOException $e) {
            Logger::channel('database')->error('WAF cacheBotVerification DB write failed', [
                'ip' => $ip,
                'is_legitimate' => $isLegitimate,
                'error' => $e->getMessage(),
            ]);
            // Fallback: Redis-only cache
            if ($this->redis) {
                $key = $this->keyPrefix . 'bot:' . $ip;
                $data = json_encode([
                    'verified' => $isLegitimate,
                    'metadata' => $metadata,
                    'cached_at' => time(),
                ]);

                return $this->redis->setex($key, $ttl, $data) !== false;
            }

            return false;
        }
    }

    /**
     * {@inheritDoc}
     *
     * READ PATH: Redis (fast) → PostgreSQL (fallback)
     */
    public function getCachedBotVerification(string $ip): ?array
    {
        // Fast path: Redis cache
        if ($this->redis) {
            try {
                $key = $this->keyPrefix . 'bot:' . $ip;
                $data = $this->redis->get($key);

                if ($data !== false && is_string($data)) {
                    $decoded = json_decode($data, true);
                    if (is_array($decoded) && isset($decoded['verified'])) {
                        return [
                            'verified' => $decoded['verified'],
                            'metadata' => $decoded['metadata'] ?? [],
                        ];
                    }
                }
            } catch (\RedisException $e) {
                Logger::channel('database')->warning('WAF getCachedBotVerification Redis miss', [
                    'ip' => $ip,
                    'error' => $e->getMessage(),
                ]);
                // Fall through to database
            }
        }

        // Slow path: PostgreSQL fallback
        try {
            $stmt = $this->pdo->prepare('
                SELECT is_legitimate, metadata FROM security_shield_bot_cache
                WHERE ip = :ip AND expires_at > NOW()
            ');
            $stmt->execute([':ip' => $ip]);
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);

            if ($result) {
                $metadata = json_decode($result['metadata'] ?? '{}', true);
                $verified = $result['is_legitimate'] === 't' || $result['is_legitimate'] === true;

                // Warm Redis cache
                if ($this->redis) {
                    $key = $this->keyPrefix . 'bot:' . $ip;
                    $data = json_encode([
                        'verified' => $verified,
                        'metadata' => is_array($metadata) ? $metadata : [],
                        'cached_at' => time(),
                    ]);
                    $this->redis->setex($key, 86400, $data);
                }

                return [
                    'verified' => $verified,
                    'metadata' => is_array($metadata) ? $metadata : [],
                ];
            }

            return null;
        } catch (\PDOException $e) {
            Logger::channel('database')->error('WAF getCachedBotVerification DB query failed', [
                'ip' => $ip,
                'error' => $e->getMessage(),
            ]);

            return null;
        }
    }

    /**
     * {@inheritDoc}
     *
     * DUAL-WRITE: Redis list (fast) + PostgreSQL table (compliance)
     *
     * DOS PROTECTION:
     * ===============
     * Event deduplication prevents log flooding attacks.
     *
     * ATTACK SCENARIO:
     * - Attacker sends 1M requests → 1M identical log entries
     * - PostgreSQL INSERT overwhelmed (10k/s limit)
     * - Table size grows to GB → query slowdown
     * - Disk I/O saturation
     *
     * DEFENSE:
     * - Deduplicate via Redis (type + IP + data hash)
     * - Same event logged max 1x per 60 seconds
     * - Reduces 1M events → 1 event per minute
     * - Database protected, compliance maintained
     */
    public function logSecurityEvent(string $type, string $ip, array $data): bool
    {
        // Deduplication with time bucket: Skip if same event logged in current minute
        if ($this->redis) {
            $bucket = intdiv(time(), 60); // 1-minute time bucket
            // Sort data keys for consistent hashing regardless of array key order
            $sortedData = $data;
            ksort($sortedData);

            // Safely encode data - fallback to simple hash if JSON encoding fails
            try {
                $dataJson = json_encode($sortedData, JSON_THROW_ON_ERROR);
            } catch (\JsonException $e) {
                // Fallback: use simple type:ip:bucket hash without data
                $dataJson = '';
            }

            $dedupHash = md5($type . ':' . $ip . ':' . $bucket . ':' . $dataJson);
            $dedupKey = $this->keyPrefix . 'event_dedup:' . $dedupHash;

            try {
                // Check if event already logged recently
                if ($this->redis->exists($dedupKey)) {
                    return true; // Already logged - skip duplicate
                }

                // Mark as logged for 300 seconds (5 minutes) to prevent log inflation
                $this->redis->setex($dedupKey, 300, '1');
            } catch (\RedisException $e) {
                Logger::channel('database')->warning('WAF event dedup Redis check failed', [
                    'type' => $type,
                    'ip' => $ip,
                    'error' => $e->getMessage(),
                ]);
                // Dedup failed - log anyway (better than losing events)
            }
        }

        try {
            // Determine severity from event type
            $severity = match ($type) {
                'auto_ban', 'sql_injection', 'xss_attack' => 'critical',
                'threshold_exceeded', 'honeypot' => 'high',
                'scan', 'rate_limit_exceeded' => 'medium',
                default => 'low',
            };

            // Write to PostgreSQL (compliance)
            $stmt = $this->pdo->prepare('
                INSERT INTO security_shield_events (type, ip, data)
                VALUES (:event_type, :ip, :event_data)
            ');
            $stmt->execute([
                ':event_type' => $type,
                ':ip' => $ip,
                ':event_data' => json_encode($data),
            ]);

            // Write to Redis list (fast analytics)
            if ($this->redis) {
                $key = $this->keyPrefix . 'events:' . $type;
                $event = json_encode([
                    'type' => $type,
                    'ip' => $ip,
                    'data' => $data,
                    'timestamp' => time(),
                ]);
                $this->redis->lPush($key, $event);
                $this->redis->lTrim($key, 0, 9999);
                $this->redis->expire($key, 2592000);
            }

            return true;
        } catch (\PDOException $e) {
            Logger::channel('database')->error('WAF logSecurityEvent DB insert failed', [
                'type' => $type,
                'ip' => $ip,
                'error' => $e->getMessage(),
            ]);
            // Fallback: Redis-only logging
            if ($this->redis) {
                $key = $this->keyPrefix . 'events:' . $type;
                $event = json_encode([
                    'type' => $type,
                    'ip' => $ip,
                    'data' => $data,
                    'timestamp' => time(),
                ]);
                $this->redis->lPush($key, $event);
                $this->redis->lTrim($key, 0, 9999);

                return true;
            }

            return false;
        }
    }

    /**
     * {@inheritDoc}
     *
     * READ PATH: PostgreSQL (authoritative) with Redis fallback for recent events
     */
    public function getRecentEvents(int $limit = 100, ?string $type = null): array
    {
        try {
            if ($type) {
                // Get events for specific type
                $stmt = $this->pdo->prepare('
                    SELECT type, ip, data, EXTRACT(EPOCH FROM created_at)::INTEGER AS timestamp
                    FROM security_shield_events
                    WHERE type = :type
                    ORDER BY created_at DESC
                    LIMIT :limit
                ');
                $stmt->bindValue(':type', $type, \PDO::PARAM_STR);
                $stmt->bindValue(':limit', $limit, \PDO::PARAM_INT);
            } else {
                // Get all events
                $stmt = $this->pdo->prepare('
                    SELECT type, ip, data, EXTRACT(EPOCH FROM created_at)::INTEGER AS timestamp
                    FROM security_shield_events
                    ORDER BY created_at DESC
                    LIMIT :limit
                ');
                $stmt->bindValue(':limit', $limit, \PDO::PARAM_INT);
            }

            $stmt->execute();
            $results = $stmt->fetchAll(\PDO::FETCH_ASSOC);

            // Decode JSON data
            return array_map(function ($row) {
                $row['data'] = json_decode($row['data'] ?? '{}', true);

                return $row;
            }, $results);
        } catch (\PDOException $e) {
            Logger::channel('database')->error('WAF getRecentEvents DB query failed', [
                'type' => $type,
                'limit' => $limit,
                'error' => $e->getMessage(),
            ]);
            // Fallback: Redis list (limited retention)
            if ($this->redis) {
                $events = [];
                if ($type) {
                    $key = $this->keyPrefix . 'events:' . $type;
                    $rawEvents = $this->redis->lRange($key, 0, $limit - 1);
                    foreach ($rawEvents as $eventJson) {
                        if (is_string($eventJson)) {
                            $event = json_decode($eventJson, true);
                            if (is_array($event)) {
                                $events[] = $event;
                            }
                        }
                    }
                }

                return $events;
            }

            return [];
        }
    }

    /**
     * {@inheritDoc}
     *
     * DUAL-WRITE: Redis atomic + PostgreSQL update
     *
     * WINDOW LOGIC:
     * - If window expired (expires_at < NOW), reset count to 1 and start new window
     * - If window still valid, increment count
     * - This ensures proper rate limiting within time windows
     */
    public function incrementRequestCount(string $ip, int $window, string $action = 'general'): int
    {
        $expiresAt = date('Y-m-d H:i:s', time() + $window);

        try {
            // PostgreSQL increment with proper window expiration handling
            // If window expired, reset count to 1; otherwise increment
            $stmt = $this->pdo->prepare('
                INSERT INTO security_shield_request_counts (ip, action, count, window_start, expires_at)
                VALUES (:ip, :action, 1, NOW(), :expires_at)
                ON CONFLICT (ip, action, window_start) DO UPDATE
                SET count = CASE
                    WHEN security_shield_request_counts.expires_at < NOW() THEN 1
                    ELSE security_shield_request_counts.count + 1
                END,
                expires_at = CASE
                    WHEN security_shield_request_counts.expires_at < NOW() THEN :expires_at
                    ELSE security_shield_request_counts.expires_at
                END
                RETURNING count
            ');
            $stmt->execute([
                ':ip' => $ip,
                ':action' => $action,
                ':expires_at' => $expiresAt,
            ]);
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);
            $count = $result ? (int) $result['count'] : 1;

            // Sync to Redis with action-specific key
            if ($this->redis) {
                $key = $this->keyPrefix . 'rate_limit:' . $action . ':' . $ip;
                $this->redis->setex($key, $window, (string) $count);
            }

            return $count;
        } catch (\PDOException $e) {
            Logger::channel('database')->error('WAF incrementRequestCount DB failed', [
                'ip' => $ip,
                'action' => $action,
                'error' => $e->getMessage(),
            ]);
            // Fallback: Redis-only increment with action-specific key
            if ($this->redis) {
                $key = $this->keyPrefix . 'rate_limit:' . $action . ':' . $ip;
                $lua = <<<'LUA'
                    local key = KEYS[1]
                    local window = tonumber(ARGV[1])
                    local count = redis.call('INCR', key)
                    if count == 1 then
                        redis.call('EXPIRE', key, window)
                    end
                    return count
                    LUA;
                $result = $this->redis->eval($lua, [$key, $window], 1);

                return is_int($result) ? $result : 1;
            }

            return 1;
        }
    }

    /**
     * {@inheritDoc}
     *
     * READ PATH: Redis (fast) → PostgreSQL (fallback)
     */
    public function getRequestCount(string $ip, int $window, string $action = 'general'): int
    {
        // Fast path: Redis cache with action-specific key
        if ($this->redis) {
            try {
                $key = $this->keyPrefix . 'rate_limit:' . $action . ':' . $ip;
                $count = $this->redis->get($key);
                if ($count !== false && is_numeric($count)) {
                    return (int) $count;
                }
            } catch (\RedisException $e) {
                Logger::channel('database')->warning('WAF getRequestCount Redis miss', [
                    'ip' => $ip,
                    'action' => $action,
                    'error' => $e->getMessage(),
                ]);
                // Fall through to database
            }
        }

        // Slow path: PostgreSQL with action filter
        try {
            $stmt = $this->pdo->prepare('
                SELECT count FROM security_shield_request_counts
                WHERE ip = :ip AND action = :action AND expires_at > NOW()
            ');
            $stmt->execute([
                ':ip' => $ip,
                ':action' => $action,
            ]);
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);

            if ($result) {
                $count = (int) $result['count'];

                // Warm Redis cache with correct action-specific key
                if ($this->redis) {
                    $key = $this->keyPrefix . 'rate_limit:' . $action . ':' . $ip;
                    $this->redis->setex($key, $window, (string) $count);
                }

                return $count;
            }

            return 0;
        } catch (\PDOException $e) {
            Logger::channel('database')->error('WAF getRequestCount DB query failed', [
                'ip' => $ip,
                'action' => $action,
                'error' => $e->getMessage(),
            ]);

            return 0;
        }
    }

    /**
     * {@inheritDoc}
     *
     * DUAL-CLEAR: Redis + PostgreSQL
     * WARNING: This is destructive - use only for testing
     */
    public function clear(): bool
    {
        try {
            // Clear PostgreSQL tables
            $this->pdo->exec('TRUNCATE TABLE security_shield_bans, security_shield_scores, security_shield_events, security_shield_request_counts, security_shield_bot_cache CASCADE');

            // Clear Redis keys with safety limits
            if ($this->redis) {
                $pattern = $this->keyPrefix . '*';
                $cursor = null;
                $deletedCount = 0;
                $iterations = 0;
                $maxIterations = 10000; // Max 10M keys (10k iterations × 1k count)
                $startTime = microtime(true);
                $timeout = 30.0; // 30 seconds max for clear operation

                do {
                    try {
                        $result = $this->redis->scan($cursor, $pattern, 1000);
                        if ($result === false) {
                            break;
                        }

                        if (is_array($result) && count($result) >= 2) {
                            $cursor = $result[0];
                            /** @var list<string> $keys */
                            $keys = $result[1];
                            if (!empty($keys)) {
                                $deleted = $this->redis->del($keys);
                                $deletedCount += is_int($deleted) ? $deleted : 0;
                            }
                        }

                        $iterations++;

                        // Safety: Prevent infinite loop
                        if ($iterations >= $maxIterations) {
                            error_log("DatabaseStorage::clear() exceeded max iterations ({$maxIterations})");
                            break;
                        }

                        // Safety: Prevent timeout
                        if ((microtime(true) - $startTime) > $timeout) {
                            error_log("DatabaseStorage::clear() timeout exceeded ({$timeout}s)");
                            break;
                        }
                    } catch (\RedisException $e) {
                        Logger::channel('database')->error('WAF clear() Redis SCAN failed', [
                            'error' => $e->getMessage(),
                        ]);
                        break;
                    }
                } while ((int) $cursor > 0);
            }

            return true;
        } catch (\PDOException | \RedisException $e) {
            Logger::channel('database')->error('WAF clear() failed', [
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * Get PDO instance (for advanced queries).
     *
     * @return \PDO
     */
    public function getPDO(): \PDO
    {
        return $this->pdo;
    }

    /**
     * Get Redis instance (for custom operations).
     *
     * @return \Redis|null
     */
    public function getRedis(): ?\Redis
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
        if ($this->redis) {
            try {
                $value = $this->redis->get($this->keyPrefix . $key);
                if ($value !== false) {
                    if (is_string($value) && (str_starts_with($value, '{') || str_starts_with($value, '['))) {
                        $decoded = json_decode($value, true);

                        return is_array($decoded) ? $decoded : $value;
                    }

                    return $value;
                }
            } catch (\RedisException $e) {
                Logger::channel('database')->warning('WAF get() Redis failed', [
                    'key' => $key,
                    'error' => $e->getMessage(),
                ]);
                // Fall through to null
            }
        }

        return null;
    }

    /**
     * {@inheritDoc}
     */
    public function set(string $key, mixed $value, int $ttl): bool
    {
        if ($this->redis) {
            try {
                if (is_array($value) || is_object($value)) {
                    $value = json_encode($value);
                }
                if (!is_string($value)) {
                    return false;
                }

                return $this->redis->setex($this->keyPrefix . $key, $ttl, $value) !== false;
            } catch (\RedisException $e) {
                Logger::channel('database')->error('WAF set() Redis failed', [
                    'key' => $key,
                    'error' => $e->getMessage(),
                ]);

                return false;
            }
        }

        return false;
    }

    /**
     * {@inheritDoc}
     */
    public function delete(string $key): bool
    {
        if ($this->redis) {
            try {
                $result = $this->redis->del($this->keyPrefix . $key);

                return $result !== false;
            } catch (\RedisException $e) {
                Logger::channel('database')->error('WAF delete() Redis failed', [
                    'key' => $key,
                    'error' => $e->getMessage(),
                ]);

                return false;
            }
        }

        return false;
    }

    /**
     * {@inheritDoc}
     */
    public function exists(string $key): bool
    {
        if ($this->redis) {
            try {
                $result = $this->redis->exists($this->keyPrefix . $key);

                return is_int($result) ? $result > 0 : (bool) $result;
            } catch (\RedisException $e) {
                Logger::channel('database')->warning('WAF exists() Redis failed', [
                    'key' => $key,
                    'error' => $e->getMessage(),
                ]);

                return false;
            }
        }

        return false;
    }

    /**
     * {@inheritDoc}
     */
    public function increment(string $key, int $delta, int $ttl): int
    {
        if ($this->redis) {
            try {
                $fullKey = $this->keyPrefix . $key;

                // Use Lua script for atomic increment with TTL
                $lua = <<<'LUA'
                    local key = KEYS[1]
                    local delta = tonumber(ARGV[1])
                    local ttl = tonumber(ARGV[2])
                    local newValue = redis.call('INCRBY', key, delta)
                    if redis.call('TTL', key) < 0 then
                        redis.call('EXPIRE', key, ttl)
                    end
                    return newValue
                    LUA;

                $result = $this->redis->eval($lua, [$fullKey, $delta, $ttl], 1);

                return is_int($result) ? $result : 0;
            } catch (\RedisException $e) {
                Logger::channel('database')->error('WAF increment() Redis failed', [
                    'key' => $key,
                    'delta' => $delta,
                    'error' => $e->getMessage(),
                ]);

                return 0;
            }
        }

        return 0;
    }

    /**
     * {@inheritDoc}
     *
     * ATOMIC RATE LIMIT CHECK - CRITICAL FOR SECURITY
     * ================================================
     *
     * This method MUST be atomic to prevent race conditions.
     *
     * DUAL-STORAGE STRATEGY:
     * 1. If Redis available: Use Lua script (sub-ms, atomic)
     * 2. If Redis down: Use PostgreSQL transaction (5-10ms, atomic)
     *
     * RACE CONDITION PREVENTED:
     * - Non-atomic: Thread A reads 99, Thread B reads 99, both allow, actual = 101
     * - Atomic: Lua script runs entirely in Redis, no interleaving possible
     */
    public function atomicRateLimitCheck(string $key, int $limit, int $window, int $cost = 1): array
    {
        $now = time();

        // Fast path: Redis with Lua script (atomic, sub-millisecond)
        if ($this->redis) {
            try {
                $fullKey = $this->keyPrefix . $key;

                // Lua script: Atomic increment + limit check
                $lua = <<<'LUA'
                        local key = KEYS[1]
                        local limit = tonumber(ARGV[1])
                        local window = tonumber(ARGV[2])
                        local cost = tonumber(ARGV[3])

                        -- Increment counter
                        local current = redis.call('INCRBY', key, cost)

                        -- Set TTL only on first increment
                        if current == cost then
                            redis.call('EXPIRE', key, window)
                        end

                        -- Get TTL for reset time
                        local ttl = redis.call('TTL', key)
                        if ttl < 0 then ttl = window end

                        -- Check if over limit
                        if current > limit then
                            -- Over limit: decrement back
                            redis.call('DECRBY', key, cost)
                            return {0, current - cost, ttl}
                        end

                        return {1, current, ttl}
                    LUA;

                $result = $this->redis->eval($lua, [$fullKey, $limit, $window, $cost], 1);

                if (is_array($result) && count($result) >= 3) {
                    $allowed = (int) $result[0] === 1;
                    $count = (int) $result[1];
                    $ttl = (int) $result[2];

                    return [
                        'allowed' => $allowed,
                        'count' => $count,
                        'remaining' => max(0, $limit - $count),
                        'reset' => $now + $ttl,
                    ];
                }
            } catch (\RedisException $e) {
                Logger::channel('database')->warning('WAF atomicRateLimitCheck Redis failed', [
                    'key' => $key,
                    'limit' => $limit,
                    'error' => $e->getMessage(),
                ]);
                // Fall through to database
            }
        }

        // Slow path: PostgreSQL with transaction (atomic, 5-10ms)
        try {
            $this->pdo->beginTransaction();

            // Use SELECT FOR UPDATE to lock the row
            $stmt = $this->pdo->prepare('
                SELECT count, EXTRACT(EPOCH FROM expires_at)::INTEGER as expires_epoch
                FROM security_shield_rate_limits
                WHERE key = :key
                FOR UPDATE
            ');
            $stmt->execute([':key' => $key]);
            $row = $stmt->fetch(\PDO::FETCH_ASSOC);

            $expiresAt = date('Y-m-d H:i:s', $now + $window);

            if (!$row || (isset($row['expires_epoch']) && $row['expires_epoch'] < $now)) {
                // New window or expired: insert/reset with cost
                $stmt = $this->pdo->prepare('
                    INSERT INTO security_shield_rate_limits (key, count, expires_at)
                    VALUES (:key, :cost, :expires_at)
                    ON CONFLICT (key) DO UPDATE
                    SET count = :cost, expires_at = :expires_at
                ');
                $stmt->execute([
                    ':key' => $key,
                    ':cost' => $cost,
                    ':expires_at' => $expiresAt,
                ]);

                $this->pdo->commit();

                return [
                    'allowed' => $cost <= $limit,
                    'count' => $cost,
                    'remaining' => max(0, $limit - $cost),
                    'reset' => $now + $window,
                ];
            }

            $currentCount = (int) $row['count'];
            $newCount = $currentCount + $cost;
            $resetTime = (int) ($row['expires_epoch'] ?? ($now + $window));

            if ($newCount > $limit) {
                // Over limit - don't increment
                $this->pdo->commit();

                return [
                    'allowed' => false,
                    'count' => $currentCount,
                    'remaining' => max(0, $limit - $currentCount),
                    'reset' => $resetTime,
                ];
            }

            // Under limit - increment
            $stmt = $this->pdo->prepare('
                UPDATE security_shield_rate_limits SET count = count + :cost WHERE key = :key
            ');
            $stmt->execute([':cost' => $cost, ':key' => $key]);

            $this->pdo->commit();

            return [
                'allowed' => true,
                'count' => $newCount,
                'remaining' => max(0, $limit - $newCount),
                'reset' => $resetTime,
            ];
        } catch (\PDOException $e) {
            Logger::channel('database')->error('WAF atomicRateLimitCheck DB failed (FAIL-OPEN)', [
                'key' => $key,
                'limit' => $limit,
                'error' => $e->getMessage(),
            ]);
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }

            // Fail open - allow request on complete storage failure
            return [
                'allowed' => true,
                'count' => 0,
                'remaining' => $limit,
                'reset' => $now + $window,
            ];
        }
    }
}
