<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Storage;

use AdosLabs\EnterpriseSecurityShield\Contracts\StorageInterface;

/**
 * Redis Sentinel Storage - Enterprise High Availability
 *
 * Production-grade Redis storage with automatic failover support.
 * Uses Redis Sentinel for master discovery and automatic failover.
 *
 * FEATURES:
 * - Automatic master discovery via Sentinel
 * - Automatic failover (typically <1s)
 * - Connection pooling support
 * - Health monitoring
 * - Configurable timeouts
 * - Fail-open/fail-closed modes
 *
 * ARCHITECTURE:
 * - Sentinel instances monitor Redis master/slaves
 * - On master failure, Sentinel promotes a slave
 * - Client queries Sentinel to discover current master
 * - Client reconnects automatically after failover
 *
 * REQUIREMENTS:
 * - ext-redis PHP extension with Sentinel support
 * - 3+ Sentinel instances for quorum
 * - Redis 5.0+ with Sentinel 3.0+
 *
 * @version 1.0.0
 */
final class RedisSentinelStorage implements StorageInterface
{
    /**
     * Sentinel configuration
     *
     * @var array{
     *     sentinels: array<array{host: string, port: int}>,
     *     master_name: string,
     *     password?: string,
     *     database: int,
     *     timeout: float,
     *     read_timeout: float,
     *     retry_interval: int,
     *     persistent: bool
     * }
     */
    private array $config;

    private string $keyPrefix;
    private ?\Redis $redis = null;
    private bool $failClosed;

    /**
     * Current master info
     *
     * @var array{host: string, port: int}|null
     */
    private ?array $currentMaster = null;

    /**
     * Last time master was discovered
     */
    private int $masterDiscoveredAt = 0;

    /**
     * Master discovery cache TTL (seconds)
     */
    private int $masterCacheTtl = 30;

    /**
     * Number of connection retries
     */
    private int $maxRetries = 3;

    /**
     * @param array{
     *     sentinels: array<array{host: string, port: int}>,
     *     master_name?: string,
     *     password?: string,
     *     database?: int,
     *     timeout?: float,
     *     read_timeout?: float,
     *     retry_interval?: int,
     *     persistent?: bool
     * } $config Sentinel configuration
     * @param string $keyPrefix Key prefix for namespacing
     * @param bool $failClosed If true, errors block requests (high security); if false, errors allow requests (high availability)
     */
    public function __construct(
        array $config,
        string $keyPrefix = 'security_shield:',
        bool $failClosed = false
    ) {
        $this->config = array_merge([
            'sentinels' => [],
            'master_name' => 'mymaster',
            'password' => null,
            'database' => 0,
            'timeout' => 2.0,
            'read_timeout' => 2.0,
            'retry_interval' => 100,
            'persistent' => true,
        ], $config);

        if (empty($this->config['sentinels'])) {
            throw new \InvalidArgumentException('At least one Sentinel must be configured');
        }

        $this->keyPrefix = $keyPrefix;
        $this->failClosed = $failClosed;
    }

    /**
     * Discover master via Sentinel
     *
     * @return array{host: string, port: int}
     * @throws \RuntimeException If master cannot be discovered
     */
    private function discoverMaster(): array
    {
        // Check cache
        if ($this->currentMaster !== null && (time() - $this->masterDiscoveredAt) < $this->masterCacheTtl) {
            return $this->currentMaster;
        }

        $errors = [];

        foreach ($this->config['sentinels'] as $sentinel) {
            try {
                $sentinelConn = new \Redis();
                $connected = @$sentinelConn->connect(
                    $sentinel['host'],
                    $sentinel['port'],
                    $this->config['timeout']
                );

                if (!$connected) {
                    $errors[] = "Failed to connect to Sentinel {$sentinel['host']}:{$sentinel['port']}";
                    continue;
                }

                // Query Sentinel for master address
                $masterInfo = $sentinelConn->rawCommand(
                    'SENTINEL',
                    'get-master-addr-by-name',
                    $this->config['master_name']
                );

                $sentinelConn->close();

                if (is_array($masterInfo) && count($masterInfo) >= 2) {
                    $this->currentMaster = [
                        'host' => (string) $masterInfo[0],
                        'port' => (int) $masterInfo[1],
                    ];
                    $this->masterDiscoveredAt = time();

                    return $this->currentMaster;
                }

                $errors[] = "Sentinel {$sentinel['host']}:{$sentinel['port']} returned invalid master info";
            } catch (\RedisException $e) {
                $errors[] = "Sentinel {$sentinel['host']}:{$sentinel['port']} error: " . $e->getMessage();
            }
        }

        throw new \RuntimeException(
            "Failed to discover Redis master from all Sentinels. Errors: " . implode('; ', $errors)
        );
    }

    /**
     * Get Redis connection (with automatic reconnection)
     *
     * @throws \RuntimeException If connection fails
     */
    private function getConnection(): \Redis
    {
        // Return existing connection if still valid
        if ($this->redis !== null) {
            try {
                $pong = @$this->redis->ping();
                if ($pong === true || $pong === '+PONG') {
                    return $this->redis;
                }
            } catch (\RedisException $e) {
                // Connection lost, will reconnect
            }
        }

        // Discover master and connect
        $master = $this->discoverMaster();

        for ($attempt = 1; $attempt <= $this->maxRetries; $attempt++) {
            try {
                $redis = new \Redis();

                if ($this->config['persistent']) {
                    $connected = @$redis->pconnect(
                        $master['host'],
                        $master['port'],
                        $this->config['timeout'],
                        'sentinel_' . $this->config['master_name']
                    );
                } else {
                    $connected = @$redis->connect(
                        $master['host'],
                        $master['port'],
                        $this->config['timeout']
                    );
                }

                if (!$connected) {
                    // Master may have changed, invalidate cache and retry
                    $this->currentMaster = null;
                    $master = $this->discoverMaster();
                    continue;
                }

                // Authenticate if password set
                if (!empty($this->config['password'])) {
                    if (!$redis->auth($this->config['password'])) {
                        throw new \RuntimeException('Redis authentication failed');
                    }
                }

                // Select database
                if ($this->config['database'] > 0) {
                    $redis->select($this->config['database']);
                }

                // Set read timeout
                $redis->setOption(\Redis::OPT_READ_TIMEOUT, $this->config['read_timeout']);

                $this->redis = $redis;

                return $this->redis;
            } catch (\RedisException $e) {
                if ($attempt === $this->maxRetries) {
                    throw new \RuntimeException(
                        "Failed to connect to Redis master after {$this->maxRetries} attempts: " . $e->getMessage()
                    );
                }

                // Invalidate master cache and retry
                $this->currentMaster = null;
                usleep($this->config['retry_interval'] * 1000);
            }
        }

        throw new \RuntimeException('Failed to establish Redis connection');
    }

    /**
     * Execute Redis command with automatic failover
     *
     * @param callable $operation The Redis operation to execute
     * @param mixed $failOpenValue Value to return on failure in fail-open mode
     * @return mixed
     */
    private function execute(callable $operation, mixed $failOpenValue = null): mixed
    {
        for ($attempt = 1; $attempt <= $this->maxRetries; $attempt++) {
            try {
                $redis = $this->getConnection();

                return $operation($redis);
            } catch (\RedisException $e) {
                // Connection failed, try to reconnect
                $this->redis = null;
                $this->currentMaster = null;

                if ($attempt === $this->maxRetries) {
                    if ($this->failClosed) {
                        throw new \RuntimeException('Redis operation failed: ' . $e->getMessage());
                    }

                    return $failOpenValue;
                }

                usleep($this->config['retry_interval'] * 1000);
            } catch (\RuntimeException $e) {
                if ($this->failClosed) {
                    throw $e;
                }

                return $failOpenValue;
            }
        }

        return $failOpenValue;
    }

    // =========================================================================
    // StorageInterface Implementation
    // =========================================================================

    public function setScore(string $ip, int $score, int $ttl): bool
    {
        return $this->execute(
            fn(\Redis $redis) => $redis->setex($this->keyPrefix . 'score:' . $ip, $ttl, (string) $score) !== false,
            false
        );
    }

    public function getScore(string $ip): ?int
    {
        return $this->execute(function (\Redis $redis) use ($ip) {
            $score = $redis->get($this->keyPrefix . 'score:' . $ip);

            if ($score === false || $score === null) {
                return null;
            }

            return is_numeric($score) ? (int) $score : null;
        }, null);
    }

    public function incrementScore(string $ip, int $points, int $ttl): int
    {
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

        $failValue = $this->failClosed ? 100 : 0; // If fail-closed, assume max score

        return $this->execute(function (\Redis $redis) use ($ip, $points, $ttl, $lua) {
            $key = $this->keyPrefix . 'score:' . $ip;
            $result = $redis->eval($lua, [$key, $points, $ttl], 1);

            return is_int($result) ? $result : 0;
        }, $failValue);
    }

    public function isBanned(string $ip): bool
    {
        $failValue = $this->failClosed; // If fail-closed, assume banned

        return $this->execute(function (\Redis $redis) use ($ip) {
            $exists = $redis->exists($this->keyPrefix . 'ban:' . $ip);

            return is_int($exists) && $exists > 0;
        }, $failValue);
    }

    public function isIpBannedCached(string $ip): bool
    {
        return $this->isBanned($ip);
    }

    public function banIP(string $ip, int $duration, string $reason): bool
    {
        return $this->execute(function (\Redis $redis) use ($ip, $duration, $reason) {
            $key = $this->keyPrefix . 'ban:' . $ip;
            $data = json_encode([
                'ip' => $ip,
                'reason' => $reason,
                'banned_at' => time(),
                'expires_at' => time() + $duration,
            ]);

            return $redis->setex($key, $duration, $data) !== false;
        }, false);
    }

    public function unbanIP(string $ip): bool
    {
        return $this->execute(function (\Redis $redis) use ($ip) {
            $deleted = $redis->del($this->keyPrefix . 'ban:' . $ip);

            return is_int($deleted) && $deleted > 0;
        }, false);
    }

    public function cacheBotVerification(string $ip, bool $isLegitimate, array $metadata, int $ttl): bool
    {
        return $this->execute(function (\Redis $redis) use ($ip, $isLegitimate, $metadata, $ttl) {
            $key = $this->keyPrefix . 'bot:' . $ip;
            $data = json_encode([
                'verified' => $isLegitimate,
                'metadata' => $metadata,
                'cached_at' => time(),
            ]);

            return $redis->setex($key, $ttl, $data) !== false;
        }, false);
    }

    public function getCachedBotVerification(string $ip): ?array
    {
        return $this->execute(function (\Redis $redis) use ($ip) {
            $key = $this->keyPrefix . 'bot:' . $ip;
            $data = $redis->get($key);

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
        }, null);
    }

    public function logSecurityEvent(string $type, string $ip, array $data): bool
    {
        return $this->execute(function (\Redis $redis) use ($type, $ip, $data) {
            // Deduplication
            $bucket = intdiv(time(), 60);
            $dedupHash = md5($type . ':' . $ip . ':' . $bucket . ':' . json_encode($data));
            $dedupKey = $this->keyPrefix . 'event_dedup:' . $dedupHash;

            if ($redis->exists($dedupKey)) {
                return true;
            }

            $redis->setex($dedupKey, 60, '1');

            $key = $this->keyPrefix . 'events:' . $type;
            $event = json_encode([
                'type' => $type,
                'ip' => $ip,
                'data' => $data,
                'timestamp' => time(),
            ]);

            $redis->lPush($key, $event);
            $redis->lTrim($key, 0, 9999);
            $redis->expire($key, 2592000);

            return true;
        }, false);
    }

    public function getRecentEvents(int $limit = 100, ?string $type = null): array
    {
        return $this->execute(function (\Redis $redis) use ($limit, $type) {
            $events = [];

            if ($type) {
                $key = $this->keyPrefix . 'events:' . $type;
                $rawEvents = $redis->lRange($key, 0, $limit - 1);

                foreach ($rawEvents as $eventJson) {
                    if (is_string($eventJson)) {
                        $event = json_decode($eventJson, true);
                        if (is_array($event)) {
                            $events[] = $event;
                        }
                    }
                }
            } else {
                $pattern = $this->keyPrefix . 'events:*';
                $it = null;

                do {
                    $keys = $redis->scan($it, $pattern, 1000);
                    if ($keys === false) {
                        break;
                    }

                    foreach ($keys as $key) {
                        $rawEvents = $redis->lRange($key, 0, $limit - 1);
                        foreach ($rawEvents as $eventJson) {
                            if (is_string($eventJson)) {
                                $event = json_decode($eventJson, true);
                                if (is_array($event)) {
                                    $events[] = $event;
                                }
                            }
                        }
                    }
                } while ($it > 0);

                usort($events, fn($a, $b) => ($b['timestamp'] ?? 0) <=> ($a['timestamp'] ?? 0));
                $events = array_slice($events, 0, $limit);
            }

            return $events;
        }, []);
    }

    public function incrementRequestCount(string $ip, int $window, string $action = 'general'): int
    {
        $lua = <<<'LUA'
            local key = KEYS[1]
            local window = tonumber(ARGV[1])
            local count = redis.call('INCR', key)
            if count == 1 then
                redis.call('EXPIRE', key, window)
            end
            return count
            LUA;

        $failValue = $this->failClosed ? PHP_INT_MAX : 1;

        return $this->execute(function (\Redis $redis) use ($ip, $window, $action, $lua) {
            $key = $this->keyPrefix . 'rate_limit:' . $action . ':' . $ip;
            $result = $redis->eval($lua, [$key, $window], 1);

            return is_int($result) ? $result : 1;
        }, $failValue);
    }

    public function getRequestCount(string $ip, int $window, string $action = 'general'): int
    {
        return $this->execute(function (\Redis $redis) use ($ip, $action) {
            $key = $this->keyPrefix . 'rate_limit:' . $action . ':' . $ip;
            $count = $redis->get($key);

            if ($count === false || !is_numeric($count)) {
                return 0;
            }

            return (int) $count;
        }, 0);
    }

    public function clear(): bool
    {
        return $this->execute(function (\Redis $redis) {
            $pattern = $this->keyPrefix . '*';
            $it = null;
            $totalDeleted = 0;

            do {
                $keys = $redis->scan($it, $pattern, 1000);
                if ($keys === false || empty($keys)) {
                    break;
                }

                $deleted = $redis->del($keys);
                $totalDeleted += is_int($deleted) ? $deleted : 0;
            } while ($it > 0);

            return $totalDeleted > 0;
        }, false);
    }

    public function get(string $key): mixed
    {
        return $this->execute(function (\Redis $redis) use ($key) {
            $value = $redis->get($this->keyPrefix . $key);

            if ($value === false) {
                return null;
            }

            if (is_string($value) && (str_starts_with($value, '{') || str_starts_with($value, '['))) {
                $decoded = json_decode($value, true);

                return is_array($decoded) ? $decoded : $value;
            }

            return $value;
        }, null);
    }

    public function set(string $key, mixed $value, int $ttl): bool
    {
        return $this->execute(function (\Redis $redis) use ($key, $value, $ttl) {
            if (is_array($value) || is_object($value)) {
                $value = json_encode($value);
            }

            if (!is_string($value)) {
                return false;
            }

            return $redis->setex($this->keyPrefix . $key, $ttl, $value) !== false;
        }, false);
    }

    public function delete(string $key): bool
    {
        return $this->execute(function (\Redis $redis) use ($key) {
            $deleted = $redis->del($this->keyPrefix . $key);

            return $deleted !== false;
        }, false);
    }

    public function exists(string $key): bool
    {
        return $this->execute(function (\Redis $redis) use ($key) {
            $exists = $redis->exists($this->keyPrefix . $key);

            return is_int($exists) && $exists > 0;
        }, $this->failClosed);
    }

    public function increment(string $key, int $delta, int $ttl): int
    {
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

        return $this->execute(function (\Redis $redis) use ($key, $delta, $ttl, $lua) {
            $fullKey = $this->keyPrefix . $key;
            $result = $redis->eval($lua, [$fullKey, $delta, $ttl], 1);

            return is_int($result) ? $result : 0;
        }, 0);
    }

    // =========================================================================
    // Sentinel-Specific Methods
    // =========================================================================

    /**
     * Get current master info
     *
     * @return array{host: string, port: int}|null
     */
    public function getCurrentMaster(): ?array
    {
        try {
            return $this->discoverMaster();
        } catch (\RuntimeException $e) {
            return null;
        }
    }

    /**
     * Get all slaves from Sentinel
     *
     * @return array<array{host: string, port: int, flags: string}>
     */
    public function getSlaves(): array
    {
        $slaves = [];

        foreach ($this->config['sentinels'] as $sentinel) {
            try {
                $sentinelConn = new \Redis();
                $connected = @$sentinelConn->connect(
                    $sentinel['host'],
                    $sentinel['port'],
                    $this->config['timeout']
                );

                if (!$connected) {
                    continue;
                }

                $rawSlaves = $sentinelConn->rawCommand(
                    'SENTINEL',
                    'slaves',
                    $this->config['master_name']
                );

                $sentinelConn->close();

                if (is_array($rawSlaves)) {
                    foreach ($rawSlaves as $slave) {
                        if (!is_array($slave)) {
                            continue;
                        }

                        // Parse slave info (comes as flat array)
                        $slaveInfo = [];
                        for ($i = 0; $i < count($slave) - 1; $i += 2) {
                            $slaveInfo[$slave[$i]] = $slave[$i + 1];
                        }

                        if (isset($slaveInfo['ip'], $slaveInfo['port'])) {
                            $slaves[] = [
                                'host' => $slaveInfo['ip'],
                                'port' => (int) $slaveInfo['port'],
                                'flags' => $slaveInfo['flags'] ?? '',
                            ];
                        }
                    }
                }

                break; // Got info from one Sentinel, no need to query others
            } catch (\RedisException $e) {
                // Try next Sentinel
            }
        }

        return $slaves;
    }

    /**
     * Force failover (for testing/maintenance)
     *
     * @return bool
     */
    public function forceFailover(): bool
    {
        foreach ($this->config['sentinels'] as $sentinel) {
            try {
                $sentinelConn = new \Redis();
                $connected = @$sentinelConn->connect(
                    $sentinel['host'],
                    $sentinel['port'],
                    $this->config['timeout']
                );

                if (!$connected) {
                    continue;
                }

                $result = $sentinelConn->rawCommand(
                    'SENTINEL',
                    'failover',
                    $this->config['master_name']
                );

                $sentinelConn->close();

                // Invalidate cached master
                $this->currentMaster = null;
                $this->redis = null;

                return $result !== false;
            } catch (\RedisException $e) {
                // Try next Sentinel
            }
        }

        return false;
    }

    /**
     * Get Sentinel health status
     *
     * @return array{
     *     healthy: bool,
     *     sentinels_up: int,
     *     sentinels_total: int,
     *     master: array{host: string, port: int}|null,
     *     slaves_count: int,
     *     quorum_met: bool
     * }
     */
    public function getHealth(): array
    {
        $sentinelsUp = 0;
        $sentinelsTotal = count($this->config['sentinels']);
        $master = null;
        $slavesCount = 0;

        foreach ($this->config['sentinels'] as $sentinel) {
            try {
                $sentinelConn = new \Redis();
                $connected = @$sentinelConn->connect(
                    $sentinel['host'],
                    $sentinel['port'],
                    $this->config['timeout']
                );

                if ($connected) {
                    $pong = $sentinelConn->ping();
                    if ($pong === true || $pong === '+PONG') {
                        $sentinelsUp++;
                    }
                    $sentinelConn->close();
                }
            } catch (\RedisException $e) {
                // Sentinel down
            }
        }

        try {
            $master = $this->discoverMaster();
            $slavesCount = count($this->getSlaves());
        } catch (\RuntimeException $e) {
            // Could not discover master
        }

        // Quorum requires majority of Sentinels
        $quorumRequired = (int) floor($sentinelsTotal / 2) + 1;
        $quorumMet = $sentinelsUp >= $quorumRequired;

        return [
            'healthy' => $quorumMet && $master !== null,
            'sentinels_up' => $sentinelsUp,
            'sentinels_total' => $sentinelsTotal,
            'master' => $master,
            'slaves_count' => $slavesCount,
            'quorum_met' => $quorumMet,
        ];
    }

    /**
     * Check if failover is in progress
     *
     * @return bool
     */
    public function isFailoverInProgress(): bool
    {
        foreach ($this->config['sentinels'] as $sentinel) {
            try {
                $sentinelConn = new \Redis();
                $connected = @$sentinelConn->connect(
                    $sentinel['host'],
                    $sentinel['port'],
                    $this->config['timeout']
                );

                if (!$connected) {
                    continue;
                }

                $masterInfo = $sentinelConn->rawCommand(
                    'SENTINEL',
                    'master',
                    $this->config['master_name']
                );

                $sentinelConn->close();

                if (is_array($masterInfo)) {
                    // Parse flat array
                    $info = [];
                    for ($i = 0; $i < count($masterInfo) - 1; $i += 2) {
                        $info[$masterInfo[$i]] = $masterInfo[$i + 1];
                    }

                    // Check for failover flags
                    $flags = $info['flags'] ?? '';
                    if (str_contains($flags, 'o_down') || str_contains($flags, 's_down') || str_contains($flags, 'failover')) {
                        return true;
                    }
                }

                return false;
            } catch (\RedisException $e) {
                // Try next Sentinel
            }
        }

        return false;
    }

    /**
     * Set fail mode (open or closed)
     *
     * @param bool $failClosed True for fail-closed (security), false for fail-open (availability)
     */
    public function setFailMode(bool $failClosed): self
    {
        $this->failClosed = $failClosed;

        return $this;
    }

    /**
     * Set master cache TTL
     *
     * @param int $ttl TTL in seconds
     */
    public function setMasterCacheTtl(int $ttl): self
    {
        $this->masterCacheTtl = max(1, $ttl);

        return $this;
    }

    /**
     * Set max retries
     *
     * @param int $retries Number of retries
     */
    public function setMaxRetries(int $retries): self
    {
        $this->maxRetries = max(1, $retries);

        return $this;
    }

    /**
     * Get Redis connection (for advanced use)
     *
     * @return \Redis
     * @throws \RuntimeException
     */
    public function getRedis(): \Redis
    {
        return $this->getConnection();
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

    /**
     * Close connections
     */
    public function close(): void
    {
        if ($this->redis !== null) {
            try {
                $this->redis->close();
            } catch (\RedisException $e) {
                // Ignore close errors
            }
            $this->redis = null;
        }
    }

    /**
     * Destructor - close connections
     */
    public function __destruct()
    {
        $this->close();
    }
}
