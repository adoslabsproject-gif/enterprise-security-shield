# Enterprise Security Shield

[![PHP Version](https://img.shields.io/badge/PHP-%5E8.1-blue)](https://www.php.net/)
[![PHPStan Level](https://img.shields.io/badge/PHPStan-Level%208-brightgreen)](https://phpstan.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Enterprise-Grade Web Application Firewall (WAF) for PHP 8.1+**

A complete security solution with ML-based threat detection, bot verification, anomaly detection, and resilience patterns trained on real attack data.

---

## Features

### Core Security

| Feature | Description |
|---------|-------------|
| **Online Learning ML** | TRUE Machine Learning that learns continuously from security events |
| **ML Threat Classifier** | Naive Bayes classifier pre-trained on 662 real security events |
| **XSS Detection** | Multi-layer detection with HTML entity decode loop |
| **SQL Injection Detection** | Pattern + behavioral analysis |
| **Anomaly Detection** | Z-Score + IQR statistical analysis |
| **Bot Verification** | DNS + IP range verification for 30+ bots |
| **Honeypot System** | 69 trap endpoints to catch scanners |
| **GeoIP Blocking** | Country-level restrictions via MaxMind |
| **Rate Limiting** | 4 algorithms: sliding window, token bucket, leaky bucket, fixed |

### Enterprise Security (NEW)

| Feature | Description |
|---------|-------------|
| **Request Smuggling Detection** | CL.TE, TE.CL, TE.TE attack detection |
| **WebSocket Protection** | CSWSH detection, origin validation, connection limits |
| **JWT Security Validation** | alg:none attacks, algorithm confusion, header injection |
| **GraphQL Protection** | Query depth/complexity limits, batching abuse, introspection control |
| **DDoS Layer 7** | Slowloris, RUDY, HTTP flood detection |
| **HTTP/2 Protection** | CONTINUATION flood, Rapid Reset (CVE-2023-44487) |
| **API Rate Limiting** | Per-endpoint, per-API-key, tier-based limits |
| **Threat Intelligence** | Auto-updating feeds (FireHOL, Emerging Threats, Abuse.ch) |

### Resilience Patterns

| Pattern | Description |
|---------|-------------|
| **Circuit Breaker** | Fail fast when dependency is down |
| **Retry Policy** | Exponential backoff with jitter |
| **Fallback Chain** | Try providers in order until success |
| **Bulkhead** | Limit concurrent executions |

### Observability

| Component | Format |
|-----------|--------|
| **Tracing** | OpenTelemetry-compatible, W3C traceparent |
| **Metrics** | Prometheus text format |
| **Health Checks** | JSON + HTTP status for Kubernetes |

---

## Installation

```bash
composer require ados-labs/enterprise-security-shield
```

### Requirements

- PHP 8.1+ (uses enums, readonly properties, named arguments)
- ext-json (required)

### Optional Extensions

| Extension | Required For |
|-----------|--------------|
| ext-redis | RedisStorage (recommended for production) |
| ext-pdo | DatabaseStorage |
| ext-curl | Notifications, GeoIP |

### Optional Dependencies

| Package | Required For |
|---------|--------------|
| geoip2/geoip2 | GeoIP blocking (MaxMind) |

---

## Quick Start

### Minimal Setup (No Redis Required)

```php
<?php
use AdosLabs\EnterpriseSecurityShield\Core\SecurityShield;
use AdosLabs\EnterpriseSecurityShield\Storage\NullStorage;

// In-memory storage - for testing only
$shield = new SecurityShield(new NullStorage());

$result = $shield->analyze([
    'ip' => $_SERVER['REMOTE_ADDR'],
    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
    'path' => $_SERVER['REQUEST_URI'] ?? '/',
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
]);

if ($result['blocked']) {
    http_response_code(403);
    exit('Access Denied: ' . $result['reason']);
}
```

### Production Setup (Redis)

```php
<?php
use AdosLabs\EnterpriseSecurityShield\Core\SecurityShield;
use AdosLabs\EnterpriseSecurityShield\Storage\RedisStorage;

$redis = new Redis();
$redis->connect('127.0.0.1', 6379);

$shield = new SecurityShield(new RedisStorage($redis));

// Configure thresholds
$shield->setThresholds(
    monitor: 15,
    challenge: 35,
    rateLimit: 50,
    block: 70,
    ban: 90
);

$result = $shield->analyze([
    'ip' => $_SERVER['REMOTE_ADDR'],
    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
    'path' => $_SERVER['REQUEST_URI'] ?? '/',
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
    'request_count' => $requestCount,  // From your rate limiter
    'error_count' => $errorCount,      // 404s for this IP
]);

match ($result['decision']) {
    'ALLOW' => null,  // Continue
    'MONITOR' => $logger->info('Suspicious activity', $result),
    'CHALLENGE' => showCaptcha(),
    'RATE_LIMIT' => respondWith429($result['retry_after']),
    'BLOCK' => respondWith403($result['reason']),
    'BAN' => respondWith403AndBan($result['ip']),
};
```

### SecurityMiddleware with ML

The SecurityMiddleware automatically integrates ML-based threat detection alongside pattern-based scoring.

```php
<?php
use AdosLabs\EnterpriseSecurityShield\Config\SecurityConfig;
use AdosLabs\EnterpriseSecurityShield\Middleware\SecurityMiddleware;
use AdosLabs\EnterpriseSecurityShield\Storage\RedisStorage;

// Configure the WAF
$config = new SecurityConfig();
$config->setStorage(new RedisStorage($redis))
       ->setLogger($logger)
       ->setScoreThreshold(50)
       ->setBanDuration(86400);

// Create middleware - ML is enabled by default
$middleware = new SecurityMiddleware($config);

// Optionally disable ML (pattern-based only)
// $middleware->setMLEnabled(false);

// In your request handler
if (!$middleware->handle($_SERVER, $_GET, $_POST)) {
    http_response_code(403);
    exit('Access Denied');
}
```

**How ML Scoring Works:**
1. Pattern-based scoring (ThreatPatterns) runs first
2. ML analyzer classifies the request
3. ML score is weighted at 40% and added to pattern score
4. If ML confidence >= 85% with BAN decision → immediate block
5. Total score checked against threshold for auto-ban

---

## TRUE Machine Learning (Online Learning)

The WAF includes a **true online learning system** that continuously improves from security events.

### How It Works

1. **Initial Knowledge**: Pre-trained on 662 real security events (starting weights)
2. **Continuous Learning**: Every security event (ban, honeypot hit, SQLi block) trains the model
3. **Concept Drift**: Decay factor (0.995) ensures older patterns lose relevance over time
4. **Persistence**: Learned weights stored in Redis, survives restarts

### Learning Status

| Status | Samples | Behavior |
|--------|---------|----------|
| `warming_up` | < 50 | Uses initial weights only |
| `learning` | 50-500 | Blends initial + learned weights |
| `mature` | > 500 | Primarily uses learned weights |

### Usage (Online Learning Classifier)

```php
use AdosLabs\EnterpriseSecurityShield\ML\OnlineLearningClassifier;

$classifier = new OnlineLearningClassifier($storage);

// Classify a request
$result = $classifier->classify([
    'user_agent' => 'curl/8.7.1',
    'path' => '/admin/phpinfo.php',
    'request_count' => 50,
    'rate_limited' => true,
]);

// Result structure
[
    'classification' => 'SCANNER',
    'confidence' => 0.87,
    'is_threat' => true,
    'learning_status' => 'mature',
    'total_samples_learned' => 1247,
    'features_used' => ['ua:curl', 'path:phpinfo', 'behavior:rapid_requests'],
    'probabilities' => [...],
]

// Manual learning (for confirmed threats)
$classifier->learn(
    features: ['user_agent' => 'malicious-bot', 'path' => '/exploit'],
    trueClass: OnlineLearningClassifier::CLASS_SCANNER,
    weight: 1.0  // Confidence in label
);

// Train from historical events
$learned = $classifier->autoLearnFromEvents(limit: 1000);

// Get model statistics
$stats = $classifier->getStats();
// ['total_samples' => 1247, 'learning_status' => 'mature', ...]

// Export/Import for backup
$backup = $classifier->exportModel();
$classifier->importModel($backup);
```

### Auto-Learning Integration

The SecurityMiddleware automatically learns from every security event:

```php
// In SecurityMiddleware, when an IP is banned:
$this->learnFromSecurityEvent('auto_ban', $ip, [
    'user_agent' => $userAgent,
    'path' => $path,
    'reasons' => ['critical_path', 'scanner_ua'],
]);
// The model updates incrementally - no manual training needed
```

---

## Static ML Threat Classifier

For deterministic classification (useful alongside online learning):

### Training Data

- **662 security events** from production logs
- **188 confirmed attack patterns**
- Categories: SCANNER, IOT_EXPLOIT, CREDENTIAL_THEFT, CMS_PROBE, BRUTE_FORCE, LEGITIMATE

### Features Detected

```php
// User-Agent signatures
'curl/', 'wget/', 'python-requests/', 'CensysInspect/', 'Nmap Scripting Engine'

// Path patterns
'/wp-admin/', '/.env', '/.git/', '/phpmyadmin/', '/GponForm/'

// Behavioral signals
'high_404_rate', 'rapid_requests', 'login_failure_burst', 'path_scanning'
```

### Usage

```php
use AdosLabs\EnterpriseSecurityShield\ML\ThreatClassifier;

$classifier = new ThreatClassifier();

$result = $classifier->classify(
    ip: '185.177.72.51',
    userAgent: 'curl/8.7.1',
    path: '/admin/phpinfo.php'
);

// Result structure
[
    'classification' => 'SCANNER',       // SCANNER, IOT_EXPLOIT, CREDENTIAL_THEFT, etc.
    'confidence' => 0.87,                // 0.0 to 1.0
    'is_threat' => true,
    'reasoning' => 'Known scanner UA (curl) + sensitive path',
    'features_detected' => ['ua_curl', 'path_phpinfo'],
    'probabilities' => [
        'SCANNER' => 0.87,
        'LEGITIMATE' => 0.13,
    ],
]
```

---

## Bot Verification

Verifies legitimate bots (Googlebot, Bingbot, etc.) via DNS reverse lookup and IP range verification.

### Supported Bots

| Category | Bots |
|----------|------|
| **Search Engines** | Googlebot, Bingbot, YandexBot, Baiduspider, DuckDuckBot |
| **Social Media** | FacebookBot, Twitterbot, LinkedInBot, Pinterest |
| **AI Crawlers** | GPTBot, ClaudeBot, CCBot, PerplexityBot |
| **SEO Tools** | AhrefsBot, SemrushBot, MJ12bot |
| **Monitoring** | UptimeRobot, Pingdom, DatadogBot |
| **Messaging** | Slackbot, TelegramBot, DiscordBot |

### Usage

```php
use AdosLabs\EnterpriseSecurityShield\Bot\BotVerificationService;

$verifier = new BotVerificationService();

$result = $verifier->verify(
    ip: '66.249.66.1',
    userAgent: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
);

// Result structure
[
    'is_bot' => true,
    'is_verified' => true,              // DNS verification passed
    'bot_id' => 'googlebot',
    'bot_name' => 'Googlebot',
    'category' => 'search_engine',
    'verification_method' => 'dns',     // 'dns', 'ip_range', 'ua_only'
    'respect_robots' => true,           // Does this bot respect robots.txt?
    'confidence' => 0.99,
]
```

### DNS Verification

For search engine bots, the service performs reverse DNS lookup:

1. `gethostbyaddr('66.249.66.1')` → `crawl-66-249-66-1.googlebot.com`
2. Verify domain ends with `.googlebot.com` or `.google.com`
3. Forward lookup confirms IP matches

---

## Anomaly Detection

Statistical anomaly detection using Z-Score and IQR (Interquartile Range) analysis.

### Metrics Analyzed

| Metric | Baseline | Detection Method |
|--------|----------|------------------|
| Requests/minute | 15.2 | Z-Score > 3σ |
| 404 errors/session | 2.1 | IQR outlier |
| Unique paths/session | 8.7 | Z-Score |
| Path depth | 3.2 | IQR outlier |
| Session duration | 180s | Anomaly if < 10s |

### Usage

```php
use AdosLabs\EnterpriseSecurityShield\ML\AnomalyDetector;

$detector = new AnomalyDetector();

$result = $detector->analyze(
    ip: '192.168.1.1',
    path: '/a/b/c/d/e/f/g/h',  // Deep path
    requestCount: 500,
    errorCount404: 80
);

// Result structure
[
    'is_anomaly' => true,
    'anomaly_score' => 67,
    'anomalies' => [
        ['metric' => 'path_depth', 'value' => 8, 'threshold' => 5],
        ['metric' => 'requests_per_minute', 'value' => 500, 'zscore' => 4.2],
    ],
    'risk_factors' => ['high_request_rate', 'deep_path'],
    'recommendation' => 'Rate limit this IP',
]
```

---

## XSS Detection

Multi-layer XSS detection with recursive HTML entity decoding.

### Detection Patterns

- `<script>` tags and event handlers
- `javascript:` URLs
- SVG/XML payloads
- Encoded attacks (HTML entities, URL encoding, Unicode)

### Usage

```php
use AdosLabs\EnterpriseSecurityShield\Detection\XSSDetector;

$detector = new XSSDetector();

$result = $detector->detect('<script>alert(1)</script>');

// Result structure
[
    'is_xss' => true,
    'confidence' => 0.95,
    'patterns_matched' => ['script_tag', 'alert_function'],
    'sanitized' => '&lt;script&gt;alert(1)&lt;/script&gt;',
]
```

---

## SQL Injection Detection

Pattern-based SQLi detection with behavioral analysis.

### Detection Patterns

- UNION-based injection
- Boolean-based blind injection
- Time-based blind injection
- Error-based injection
- Stacked queries

### Usage

```php
use AdosLabs\EnterpriseSecurityShield\Detection\SQLiDetector;

$detector = new SQLiDetector();

$result = $detector->detect("1' OR '1'='1");

// Result structure
[
    'is_sqli' => true,
    'confidence' => 0.92,
    'patterns_matched' => ['boolean_injection', 'quote_escape'],
    'risk_level' => 'high',
]
```

---

## Rate Limiting

Four algorithms for different use cases.

### Algorithms

| Algorithm | Best For | How It Works |
|-----------|----------|--------------|
| **Sliding Window** | API rate limits | Counts requests in moving time window |
| **Token Bucket** | Burst-tolerant limits | Tokens refill over time, bursts allowed |
| **Leaky Bucket** | Smooth rate limiting | Requests "leak" at constant rate |
| **Fixed Window** | Simple limits | Counts per calendar minute/hour |

### Usage

```php
use AdosLabs\EnterpriseSecurityShield\RateLimiting\RateLimiter;

// Token bucket: 100 tokens, refills 10/second
$limiter = RateLimiter::tokenBucket($storage, capacity: 100, refillRate: 10);

$result = $limiter->attempt('user:123');

if (!$result->allowed) {
    header('Retry-After: ' . $result->retryAfter);
    http_response_code(429);
    exit('Too Many Requests');
}
```

---

## Honeypot System

69 trap endpoints to catch scanners.

### Trap Endpoints

```
/.env, /.git/config, /.aws/credentials, /wp-admin/, /wp-login.php,
/phpmyadmin/, /phpinfo.php, /admin/, /administrator/, /GponForm/,
/HNAP1/, /cgi-bin/, /actuator/health, /api/v1/users, etc.
```

### Usage

```php
use AdosLabs\EnterpriseSecurityShield\Middleware\HoneypotMiddleware;

$honeypot = new HoneypotMiddleware($storage);

if ($honeypot->isHoneypot($_SERVER['REQUEST_URI'])) {
    // Log attacker IP, ban immediately
    $storage->banIP($_SERVER['REMOTE_ADDR'], 86400, 'Honeypot access');
    http_response_code(404);
    exit;
}
```

---

## Resilience Patterns

### Circuit Breaker

```php
use AdosLabs\EnterpriseSecurityShield\Resilience\CircuitBreaker;

$breaker = new CircuitBreaker('redis', $storage, [
    'failure_threshold' => 5,    // Open after 5 failures
    'recovery_timeout' => 30,    // Try again after 30s
    'half_open_max_calls' => 3,  // Allow 3 test calls
]);

$result = $breaker->call(
    fn() => $redis->get('key'),           // Primary
    fn() => $localCache->get('key')       // Fallback
);
```

### Retry Policy

```php
use AdosLabs\EnterpriseSecurityShield\Resilience\RetryPolicy;

$policy = RetryPolicy::exponentialBackoffWithJitter(
    maxAttempts: 5,
    baseDelay: 1.0,
    maxDelay: 30.0
);

// Delays: ~1s, ~2s, ~4s, ~8s (with jitter)
$result = $policy->execute(fn() => $api->call());
```

---

## Storage Backends

| Backend | Use Case | Performance | Persistence |
|---------|----------|-------------|-------------|
| **NullStorage** | Testing | ~0.001ms | No |
| **DatabaseStorage** | Production (no Redis) | ~1-5ms | Yes |
| **RedisStorage** | Production (recommended) | ~0.05ms | Yes |

### Security: Fail-Open vs Fail-Closed

By default, RedisStorage uses **fail-open** behavior:

- On Redis failure, returns "not banned" / score = 0
- Prioritizes availability over security
- Site stays online during outage

For high-security applications (banking, government), implement **fail-closed**:

```php
class FailClosedRedisStorage extends RedisStorage
{
    public function isBanned(string $ip): bool
    {
        try {
            return parent::isBanned($ip);
        } catch (\RedisException $e) {
            error_log("Redis down - fail-closed active");
            return true;  // Block all traffic on failure
        }
    }
}
```

---

## Notifications

```php
use AdosLabs\EnterpriseSecurityShield\Notifications\NotificationManager;
use AdosLabs\EnterpriseSecurityShield\Notifications\TelegramNotifier;
use AdosLabs\EnterpriseSecurityShield\Notifications\SlackNotifier;

$manager = new NotificationManager();
$manager->addChannel(new TelegramNotifier($botToken, $chatId));
$manager->addChannel(new SlackNotifier($webhookUrl));

$manager->broadcast('Security Alert', 'IP banned: 1.2.3.4', [
    'reason' => 'Honeypot access',
    'path' => '/.env',
]);
```

---

## Health Checks

```php
use AdosLabs\EnterpriseSecurityShield\Health\HealthCheck;
use AdosLabs\EnterpriseSecurityShield\Health\Checks\RedisHealthCheck;

$health = new HealthCheck();
$health->addCheck('redis', new RedisHealthCheck($redis));

// Kubernetes liveness/readiness
header('Content-Type: application/json');
$result = $health->readiness();
http_response_code($result->getHttpStatusCode());
echo $result->toJson();
```

---

## Admin Panel Integration

The package includes admin panel views for WordPress-style integration.

### Views Included

- `dashboard.php` - Security overview with charts
- `events.php` - Security events log with filters
- `ips.php` - IP ban/whitelist management
- `config.php` - WAF configuration presets

### CSS/JS Assets (CSP A+ Compliant)

All assets use external files (no inline CSS/JS):

```
assets/
├── css/
│   ├── ess-dashboard.css    # Dashboard styles (BEM naming)
│   └── ess-components.css   # Filters, modals, tabs
└── js/
    ├── ess-dashboard.js     # Chart initialization
    └── ess-components.js    # UI interactions
```

---

## Testing

```bash
composer install
composer test          # PHPUnit tests (75 tests, 256 assertions)
composer stan          # PHPStan level 8
composer cs-check      # PHP-CS-Fixer
```

---

## File Structure

```
src/
├── AdminIntegration/  # Admin panel module (7 tabs)
├── Anomaly/           # Statistical anomaly detectors
├── Bot/               # Bot verification service
├── Config/            # Configuration management
├── Contracts/         # Interfaces
├── Core/              # SecurityShield main class
├── CSRF/              # CSRF token management
├── Detection/         # XSS, SQLi, Request Smuggling, DDoS, GraphQL, HTTP/2, WebSocket
├── FileUpload/        # Secure file upload validation
├── GeoIP/             # GeoIP blocking service
├── Health/            # Health check system
├── Honeypot/          # Trap endpoints
├── Integrations/      # WooCommerce, WordPress
├── Middleware/        # PSR-15 middleware
├── ML/                # Machine learning (ThreatClassifier, OnlineLearning, AnomalyDetector)
├── Notifications/     # Telegram, Slack, Email
├── RateLimiting/      # 5 rate limit algorithms (+ API-specific)
├── Resilience/        # Circuit breaker, retry, bulkhead
├── Security/          # JWT validation
├── Storage/           # Redis, Database, Null
├── Telemetry/         # Tracing, metrics
├── ThreatIntel/       # Threat feed client & matcher
└── Utils/             # IP utilities
```

---

## Enterprise Security Features

### Request Smuggling Detection

Detects HTTP Request Smuggling attacks that exploit discrepancies between front-end and back-end servers.

```php
use AdosLabs\EnterpriseSecurityShield\Detection\RequestSmugglingDetector;

$detector = new RequestSmugglingDetector();

// Check request headers
$result = $detector->detect($headers, $rawRequest);

if ($result['detected']) {
    // Attack type: CL_TE_CONFLICT, DUPLICATE_CL, TE_OBFUSCATION, etc.
    error_log("Smuggling detected: " . $result['attack_type']);
    http_response_code(400);
    exit('Bad Request');
}

// Sanitize headers (removes dangerous combinations)
$safeHeaders = $detector->sanitize($headers);
```

**Detected Attack Types:**
- CL.TE (Front-end uses Content-Length, back-end uses Transfer-Encoding)
- TE.CL (Front-end uses Transfer-Encoding, back-end uses Content-Length)
- TE.TE (Both use Transfer-Encoding but parse obfuscation differently)

---

### WebSocket Protection

Validates WebSocket upgrade requests and detects Cross-Site WebSocket Hijacking (CSWSH).

```php
use AdosLabs\EnterpriseSecurityShield\Detection\WebSocketProtector;

$protector = new WebSocketProtector([
    'allowed_origins' => ['example.com', '*.example.com'],
    'max_connections_per_ip' => 10,
]);

// Validate upgrade request
$result = $protector->validateUpgrade($headers, $origin, $clientIp, $connectionCount);

if (!$result['valid']) {
    // Reject WebSocket connection
    http_response_code(403);
    exit(json_encode(['errors' => $result['errors']]));
}

// Generate accept key for handshake
$acceptKey = $protector->generateAcceptKey($headers['sec-websocket-key']);

// Check for CSWSH attack
$cswsh = $protector->detectCSWSH($origin, $referer, $host);
if ($cswsh['detected']) {
    error_log("CSWSH attack: " . $cswsh['reason']);
}
```

---

### JWT Security Validation

Validates JWT tokens for common attack patterns. **Does NOT verify signatures** - use with a JWT library.

```php
use AdosLabs\EnterpriseSecurityShield\Security\JWTValidator;

$validator = new JWTValidator([
    'allowed_algorithms' => ['RS256', 'ES256'],  // Whitelist only!
    'required_claims' => ['exp', 'iat', 'sub'],
    'max_token_age' => 86400,
]);

$result = $validator->validate($token);

if (!$result['valid']) {
    // Check for attacks
    if (in_array('ALG_NONE_ATTACK', $result['attacks_detected'])) {
        error_log("CRITICAL: alg:none attack attempted!");
    }
    if (in_array('ALG_CONFUSION', $result['attacks_detected'])) {
        error_log("WARNING: Possible RS256->HS256 confusion attack");
    }

    http_response_code(401);
    exit('Invalid token');
}

// Token structure is safe, now verify signature with your JWT library
$payload = $result['payload'];
```

**Detected Attacks:**
- `ALG_NONE_ATTACK` - Algorithm set to "none" (bypass signature)
- `ALG_CONFUSION` - RS256→HS256 confusion (use public key as HMAC secret)
- `HEADER_INJECTION` - Malicious jku/x5u/jwk headers
- `SUSPICIOUS_CLAIMS` - Admin role escalation attempts

---

### GraphQL Protection

Protects against GraphQL-specific DoS and abuse patterns.

```php
use AdosLabs\EnterpriseSecurityShield\Detection\GraphQLProtector;

$protector = new GraphQLProtector([
    'max_depth' => 10,           // Prevent deeply nested queries
    'max_complexity' => 1000,    // Prevent expensive queries
    'max_batch_size' => 10,      // Prevent batching abuse
    'allow_introspection' => false,  // Disable in production!
]);

// Analyze single query
$result = $protector->analyze($query, $variables);

// Analyze batch (array of operations)
$result = $protector->analyze($batchOperations);

if (!$result['allowed']) {
    http_response_code(400);
    exit(json_encode([
        'errors' => $result['errors'],
        'attacks' => $result['attacks_detected'],
    ]));
}

// Query is safe to execute
$metrics = $result['metrics'];  // depth, complexity, aliases, operations
```

**Detected Attacks:**
- `DEPTH_ATTACK` - Query depth exceeds limit
- `COMPLEXITY_ATTACK` - Query too expensive
- `BATCH_ABUSE` - Too many operations in batch
- `INTROSPECTION_BLOCKED` - Schema discovery attempt
- `ALIAS_ABUSE` - Excessive aliases (amplification)

---

### DDoS Layer 7 Protection

Detects application-layer DDoS attacks. Works best with server metrics.

```php
use AdosLabs\EnterpriseSecurityShield\Detection\DDoSProtector;

$protector = new DDoSProtector($storage, [
    'max_requests_per_window' => 1000,
    'window_size' => 60,
    'max_concurrent_connections' => 50,
    'expensive_endpoints' => [
        '/api/search' => 5,     // Costs 5 requests
        '/api/export' => 20,    // Costs 20 requests
    ],
]);

// Basic check (flood detection)
$result = $protector->analyze($clientIp, $path, $method);

// Advanced check with server metrics
$result = $protector->analyze($clientIp, $path, $method, [
    'header_receive_time' => 5.2,      // Slowloris detection
    'header_count' => 10,
    'body_receive_time' => 30.0,       // RUDY detection
    'content_length' => 1000,
    'concurrent_connections' => 45,
]);

if (!$result['allowed']) {
    // $result['attack_type']: HTTP_FLOOD, SLOWLORIS, RUDY, etc.
    http_response_code(429);
    exit('Too Many Requests');
}
```

**Detected Attacks:**
- `HTTP_FLOOD` - Excessive request rate
- `SLOWLORIS` - Slow HTTP headers
- `RUDY` - Slow POST body (R-U-Dead-Yet)
- `CONNECTION_FLOOD` - Too many concurrent connections
- `RESOURCE_EXHAUSTION` - Expensive endpoint abuse

---

### HTTP/2 Protection

Detects HTTP/2 protocol-specific attacks. Requires server metrics for full detection.

```php
use AdosLabs\EnterpriseSecurityShield\Detection\HTTP2Protector;

$protector = new HTTP2Protector([
    'max_header_list_size' => 16384,
    'max_concurrent_streams' => 100,
    'max_resets_per_minute' => 100,
]);

// Analyze request (requires HTTP/2 metrics from web server)
$result = $protector->analyze($headers, [
    'protocol' => 'h2',
    'continuation_frames' => 3,
    'rst_stream_count' => 50,
    'settings_frames' => 2,
]);

if (!$result['allowed']) {
    foreach ($result['recommendations'] as $rec) {
        error_log("HTTP/2 Security: " . $rec);
    }
}

// Get recommended nginx/apache config
echo $protector->getNginxConfig();
echo $protector->getApacheConfig();
```

**Detected Attacks:**
- `CONTINUATION_FLOOD` - CVE-2024-27983
- `RAPID_RESET` - CVE-2023-44487
- `HPACK_BOMB` - Header compression abuse
- `SETTINGS_FLOOD` - Excessive SETTINGS frames

---

### API Rate Limiting

Advanced rate limiting with per-endpoint, per-API-key, and tier-based limits.

```php
use AdosLabs\EnterpriseSecurityShield\RateLimiting\APIRateLimiter;

$limiter = new APIRateLimiter($storage, [
    'default_limit' => 60,
    'default_window' => 60,
    'algorithm' => 'token_bucket',  // or 'sliding_window', 'fixed_window'
]);

// Define tiers
$limiter->defineTier('free', ['limit' => 60, 'burst' => 10]);
$limiter->defineTier('pro', ['limit' => 1000, 'burst' => 200]);
$limiter->defineTier('enterprise', ['limit' => 10000, 'burst' => 2000]);

// Set endpoint-specific limits
$limiter->setEndpointLimit('/api/search', ['limit' => 10, 'cost' => 5]);
$limiter->setEndpointLimit('/api/export/*', ['limit' => 5, 'cost' => 20]);

// Register API keys
$limiter->registerApiKey('sk_live_xxx', 'pro');

// Check rate limit
$result = $limiter->check(
    identifier: $clientIp,
    endpoint: '/api/users',
    apiKey: $request->header('X-API-Key'),
    cost: 1
);

if (!$result['allowed']) {
    header('X-RateLimit-Limit: ' . $result['limit']);
    header('X-RateLimit-Remaining: ' . $result['remaining']);
    header('X-RateLimit-Reset: ' . $result['reset']);
    header('Retry-After: ' . $result['retry_after']);
    http_response_code(429);
    exit('Rate limit exceeded');
}
```

---

### Threat Intelligence Feeds

Auto-updating threat intelligence from public feeds.

```php
use AdosLabs\EnterpriseSecurityShield\ThreatIntel\ThreatFeedClient;
use AdosLabs\EnterpriseSecurityShield\ThreatIntel\ThreatMatcher;

// Initialize feed client
$feedClient = new ThreatFeedClient($storage, [
    'cache_ttl' => 21600,  // 6 hours
]);

// Update feeds (call via cron every 6 hours)
$result = $feedClient->fetchAllFeeds();
echo "Updated: " . implode(', ', $result['success']);
echo "Failed: " . implode(', ', array_keys($result['failed']));
echo "Total entries: " . $result['total_entries'];

// Check IP against feeds
$matcher = new ThreatMatcher($storage);
$matcher->loadFromStorage();

$result = $matcher->matchIp('1.2.3.4');
if ($result['match']) {
    echo "Blocked by feed: " . $result['feed'];
    // $result['type']: 'exact_ip', 'cidr', etc.
}

// Batch check
$results = $matcher->matchIpBatch(['1.2.3.4', '5.6.7.8', '9.10.11.12']);
```

**Included Feeds:**
- FireHOL Level 1 (high confidence malicious IPs)
- Emerging Threats Compromised IPs
- Abuse.ch Feodo Tracker (botnet C&C)
- Spamhaus DROP (Do Not Route Or Peer)
- Tor Exit Nodes (disabled by default)

---

### SecurityShield Integration

All enterprise features are integrated into the main SecurityShield class:

```php
use AdosLabs\EnterpriseSecurityShield\Core\SecurityShield;

$shield = new SecurityShield($storage, $config, $logger);

// Request smuggling
$result = $shield->analyzeRequestSmuggling($headers, $rawRequest);

// WebSocket validation
$result = $shield->validateWebSocketUpgrade($headers, $origin, $clientIp);

// JWT validation
$result = $shield->validateJWT($token);

// GraphQL protection
$result = $shield->analyzeGraphQL($query, $variables);

// DDoS detection
$result = $shield->analyzeDDoS($clientIp, $path, $method, $serverMetrics);

// API rate limiting
$result = $shield->checkAPIRateLimit($identifier, $endpoint, $apiKey);

// Threat intelligence
$result = $shield->checkThreatIntel($ip);

// Update threat feeds (cron job)
$result = $shield->updateThreatFeeds();

// HTTP/2 protection
$result = $shield->analyzeHTTP2($headers, $serverMetrics);
```

---

## What This WAF Actually Does

### Attack Detection & Blocking

| Attack Type | Detection Method | Real-Time Blocking |
|-------------|------------------|-------------------|
| **SQL Injection** | Tokenizer-based analysis (not just regex), detects UNION, boolean, stacked queries | Yes |
| **XSS Attacks** | Multi-pass HTML entity decoding, DOM analysis, event handler detection | Yes |
| **Request Smuggling** | CL.TE, TE.CL, TE.TE header analysis | Yes |
| **Path Traversal** | Pattern + normalization bypass detection | Yes |
| **Command Injection** | Shell metacharacter and command pattern detection | Yes |
| **GraphQL Abuse** | Query depth, complexity, batching limits | Yes |
| **JWT Attacks** | alg:none, algorithm confusion, header injection | Yes |

### Machine Learning (Real, Not Marketing)

| Component | Implementation | Verification |
|-----------|---------------|--------------|
| **Naive Bayes Classifier** | `src/ML/ThreatClassifier.php` - 800+ lines | Probabilistic classification with feature extraction |
| **Online Learning** | `src/ML/OnlineLearningClassifier.php` | Incremental training, concept drift handling |
| **Anomaly Detection** | `src/ML/AnomalyDetector.php` | Z-Score + IQR statistical analysis |
| **Training Data** | 662 real security events, 188 attack patterns | Pre-trained weights included |

### DDoS Protection (Layer 7)

| Attack | Detection | How It Works |
|--------|-----------|--------------|
| **HTTP Flood** | Request rate analysis | Atomic rate limiting with Redis Lua scripts |
| **Slowloris** | Header receive timing | Detects slow header transmission |
| **RUDY** | Body receive timing | Detects slow POST body attacks |
| **HTTP/2 Rapid Reset** | RST_STREAM counting | CVE-2023-44487 detection |

### Rate Limiting (4 Algorithms)

All use **atomic operations** (Lua scripts) to prevent race conditions:
- Sliding Window (most accurate)
- Token Bucket (burst-tolerant)
- Leaky Bucket (smooth enforcement)
- Fixed Window (simple)

---

## Architecture: Where This WAF Fits

```
Internet
    │
    ▼
┌─────────────────────────────┐
│   Edge WAF (Cloudflare)     │  ◄── Volumetric DDoS (L3/L4), CDN
│   - Network-level attacks   │
│   - Bandwidth attacks       │
└─────────────────────────────┘
    │
    ▼
┌─────────────────────────────┐
│   This WAF (PHP)            │  ◄── Application attacks (L7)
│   - SQLi, XSS, RCE          │
│   - Business logic abuse    │
│   - Bot detection           │
│   - ML threat scoring       │
└─────────────────────────────┘
    │
    ▼
┌─────────────────────────────┐
│   Your Application          │
└─────────────────────────────┘
```

**Use BOTH layers for complete protection.**

---

## Known Limitations

1. **Fail-Open Default** - Allows traffic during Redis outage (configurable to fail-closed)
2. **DNS Timeout** - Bot verification can block up to 30s on slow DNS (timeout configurable)
3. **No L3/L4 Protection** - Cannot stop volumetric network floods (use edge WAF)
4. **No Third-Party Audit** - Not penetration tested by external security firm
5. **ML Warm-Up** - Online learning needs ~50 samples before improving

---

## Transparency

This project is honest about what it does and doesn't do:

- **No penetration test** - We haven't paid for a third-party security audit
- **Defense in depth** - Use alongside Cloudflare/AWS WAF, not instead of
- **Open source** - All code is inspectable, no black boxes
- **Security audit included** - See `docs/SECURITY-AUDIT.md` for known vulnerabilities we've documented ourselves

---

## License

MIT License - see [LICENSE](LICENSE)

---

## Credits

- Initial ML model trained on security events from real production environments
- Online Learning Classifier uses Naive Bayes with Laplace smoothing
- Concept drift handling via exponential decay (0.995 factor)
- Feature extraction from 40+ attack patterns across 11 threat categories
