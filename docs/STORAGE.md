# Storage Architecture

How data persistence works in Enterprise Security Shield.

---

## Storage Interface

All storage backends implement `StorageInterface`:

```php
interface StorageInterface
{
    public function get(string $key): ?string;
    public function set(string $key, string $value, ?int $ttl = null): bool;
    public function delete(string $key): bool;
    public function exists(string $key): bool;
    public function increment(string $key, int $value = 1, ?int $ttl = null): int;
    public function decrement(string $key, int $value = 1, ?int $ttl = null): int;

    // IP-specific methods
    public function setScore(string $ip, int $score, int $ttl): bool;
    public function getScore(string $ip): ?int;
    public function incrementScore(string $ip, int $points, int $ttl): int;
    public function isBanned(string $ip): bool;
    public function ban(string $ip, int $ttl, string $reason): bool;
    public function unban(string $ip): bool;
    public function isWhitelisted(string $ip): bool;
    public function addToWhitelist(string $ip, string $label): bool;
    public function removeFromWhitelist(string $ip): bool;
    public function logEvent(array $event): bool;
    // ... more methods
}
```

---

## Implementations

### 1. RedisStorage

**File**: `src/Storage/RedisStorage.php`

Recommended for production.

**Requirements**:
- ext-redis PHP extension
- Redis 5.0+ (6.0+ recommended)

**Features**:
- Sub-millisecond reads
- Atomic operations via Lua scripts
- Automatic key expiration
- High concurrency support

**Usage**:

```php
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
$redis->auth('password'); // If auth required

$storage = new RedisStorage($redis, 'security_shield:');
```

**Key Prefix**: All keys prefixed with `security_shield:` by default.

**Key Structure**:
```
security_shield:score:{ip}        - Threat score
security_shield:ban:{ip}          - Ban record
security_shield:whitelist:{ip}    - Whitelist entry
security_shield:rate:{ip}         - Rate limit counter
security_shield:event:{id}        - Security event
```

**Fail Behavior**: FAIL-OPEN by default. On Redis failure:
- `isBanned()` returns `false` (allow traffic)
- `incrementScore()` returns `0`
- Site stays online

For high-security: Configure fail-closed mode in SecurityConfig.

---

### 2. RedisSentinelStorage

**File**: `src/Storage/RedisSentinelStorage.php`

High-availability Redis with automatic failover.

**Requirements**:
- Redis Sentinel cluster
- Multiple Redis instances

**Usage**:

```php
$storage = new RedisSentinelStorage([
    'sentinels' => [
        ['host' => 'sentinel1.example.com', 'port' => 26379],
        ['host' => 'sentinel2.example.com', 'port' => 26379],
        ['host' => 'sentinel3.example.com', 'port' => 26379],
    ],
    'master' => 'mymaster',
    'password' => 'redis_password',
]);
```

Automatically:
- Discovers current master
- Reconnects on failover
- Retries on connection loss

---

### 3. DatabaseStorage

**File**: `src/Storage/DatabaseStorage.php`

Dual-write architecture: Redis (cache) + PostgreSQL/MySQL (persistence).

**Architecture**:

```
Write Path:
Request → DatabaseStorage → Redis (cache) + PostgreSQL (persist)

Read Path:
Request → DatabaseStorage → Redis (hit?) → Return
                              ↓ (miss)
                         PostgreSQL → Warm Redis → Return
```

**Requirements**:
- PDO extension
- PostgreSQL 9.5+ or MySQL 5.7+
- Optional: Redis for caching

**Usage**:

```php
$pdo = new PDO('pgsql:host=localhost;dbname=myapp', 'user', 'pass');
$redis = new Redis();
$redis->connect('127.0.0.1');

$storage = new DatabaseStorage($pdo, $redis, 'security_shield:');
```

**Without Redis** (slower, but works):

```php
$storage = new DatabaseStorage($pdo, null);
```

**Performance**:

| Operation | With Redis | Without Redis |
|-----------|-----------|---------------|
| Ban check | <1ms | ~5ms |
| Score read | <1ms | ~3ms |
| Score write | ~2ms | ~2ms |
| Event log | ~1ms | ~1ms |

---

### 4. NullStorage

**File**: `src/Storage/NullStorage.php`

In-memory storage for testing. Data lost on process end.

**Warning**: NOT for production.

```php
$storage = new NullStorage();
```

---

## Database Schema

Tables in `database/migrations/`:

### banned_ips

```sql
CREATE TABLE banned_ips (
    id SERIAL PRIMARY KEY,
    ip VARCHAR(45) NOT NULL UNIQUE,
    reason TEXT,
    banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    created_by VARCHAR(255)
);
CREATE INDEX idx_banned_ips_expires ON banned_ips(expires_at);
```

### whitelisted_ips

```sql
CREATE TABLE whitelisted_ips (
    id SERIAL PRIMARY KEY,
    ip VARCHAR(45) NOT NULL UNIQUE,
    label VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255)
);
```

### threat_scores

```sql
CREATE TABLE threat_scores (
    id SERIAL PRIMARY KEY,
    ip VARCHAR(45) NOT NULL UNIQUE,
    score INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMP,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    request_count INTEGER DEFAULT 1
);
CREATE INDEX idx_threat_scores_expires ON threat_scores(expires_at);
```

### security_events

```sql
CREATE TABLE security_events (
    id SERIAL PRIMARY KEY,
    ip VARCHAR(45) NOT NULL,
    type VARCHAR(100) NOT NULL,
    score INTEGER DEFAULT 0,
    path TEXT,
    user_agent TEXT,
    action VARCHAR(50),
    details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_security_events_ip ON security_events(ip);
CREATE INDEX idx_security_events_type ON security_events(type);
CREATE INDEX idx_security_events_created ON security_events(created_at DESC);
```

### ml_models

```sql
CREATE TABLE ml_models (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    weights JSONB NOT NULL,
    priors JSONB NOT NULL,
    training_count INTEGER DEFAULT 0,
    last_trained TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### ml_training_data

```sql
CREATE TABLE ml_training_data (
    id SERIAL PRIMARY KEY,
    features JSONB NOT NULL,
    label VARCHAR(50) NOT NULL,
    source VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### security_config

```sql
CREATE TABLE security_config (
    key VARCHAR(100) PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## Data Retention

### Redis TTLs

| Data Type | Default TTL | Configurable |
|-----------|-------------|--------------|
| Threat scores | 24h | Yes |
| Rate limit counters | Window + 60s | Yes |
| Ban records | Ban duration | Yes |
| Bot verification cache | 24h | No |
| ML model cache | 1h | Yes |

### Database Cleanup

Events auto-expire based on `created_at`. Run cleanup:

```php
// Via Admin Panel: /security/events/clear
// Or programmatically:
$storage->clearOldEvents(days: 30);
```

Expired bans cleared via:

```php
// Via Admin Panel: /security/ips -> Clear Expired
$storage->clearExpiredBans();
```

---

## Memory Estimates

### Redis

| Data | Size per IP |
|------|-------------|
| Score entry | ~50 bytes |
| Ban entry | ~200 bytes |
| Whitelist entry | ~100 bytes |
| Rate limit | ~100 bytes |

For 10,000 tracked IPs: ~4.5MB Redis memory

### Database

| Table | Size per row |
|-------|-------------|
| security_events | ~500 bytes |
| threat_scores | ~100 bytes |
| banned_ips | ~300 bytes |

---

## Backup & Recovery

### Redis

```bash
# RDB snapshot
redis-cli BGSAVE

# AOF persistence (recommended for WAF data)
# In redis.conf:
appendonly yes
appendfsync everysec
```

### PostgreSQL

```bash
pg_dump -t banned_ips -t whitelisted_ips -t security_events mydb > waf_backup.sql
```

### Recovery Priority

1. `banned_ips` - Critical for security
2. `whitelisted_ips` - Business operations
3. `ml_models` - Can be retrained
4. `security_events` - Audit trail

---

## Switching Storage

To migrate from one storage to another:

```php
// Export from old
$bannedIps = $oldStorage->getBannedIps();
$whitelist = $oldStorage->getWhitelistedIps();

// Import to new
foreach ($bannedIps as $ban) {
    $newStorage->ban($ban['ip'], $ban['ttl'], $ban['reason']);
}

foreach ($whitelist as $entry) {
    $newStorage->addToWhitelist($entry['ip'], $entry['label']);
}
```

Events and scores typically not migrated (fresh start).

---

## Monitoring

### Redis

Monitor with `INFO` command:
- `used_memory` - Total memory
- `connected_clients` - Connection count
- `keyspace_hits/misses` - Cache efficiency

### PostgreSQL

Check table sizes:

```sql
SELECT relname, pg_size_pretty(pg_total_relation_size(relid))
FROM pg_catalog.pg_statio_user_tables
WHERE relname LIKE '%security%';
```

Check index usage:

```sql
SELECT indexrelname, idx_scan, idx_tup_read
FROM pg_stat_user_indexes
WHERE indexrelname LIKE '%security%';
```
