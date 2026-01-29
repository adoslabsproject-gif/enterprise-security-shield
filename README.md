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
| **ML Threat Classifier** | Naive Bayes classifier trained on 662 real security events |
| **XSS Detection** | Multi-layer detection with HTML entity decode loop |
| **SQL Injection Detection** | Pattern + behavioral analysis |
| **Anomaly Detection** | Z-Score + IQR statistical analysis |
| **Bot Verification** | DNS + IP range verification for 30+ bots |
| **Honeypot System** | 69 trap endpoints to catch scanners |
| **GeoIP Blocking** | Country-level restrictions via MaxMind |
| **Rate Limiting** | 4 algorithms: sliding window, token bucket, leaky bucket, fixed |

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

## ML Threat Classification

The threat classifier uses a Naive Bayes algorithm trained on real attack data from production servers.

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
├── Anomaly/           # Statistical anomaly detectors
├── Bot/               # Bot verification service
├── Config/            # Configuration management
├── Contracts/         # Interfaces
├── Core/              # SecurityShield main class
├── Detection/         # XSS/SQLi detectors
├── GeoIP/             # GeoIP blocking service
├── Health/            # Health check system
├── Honeypot/          # Trap endpoints
├── Integrations/      # WooCommerce, WordPress
├── Middleware/        # PSR-15 middleware
├── ML/                # Machine learning (ThreatClassifier, AnomalyDetector)
├── Notifications/     # Telegram, Slack, Email
├── RateLimiting/      # 4 rate limit algorithms
├── Resilience/        # Circuit breaker, retry, bulkhead
├── Storage/           # Redis, Database, Null
├── Telemetry/         # Tracing, metrics
└── Utils/             # IP utilities
```

---

## Known Limitations

1. **Fail-Open Default** - RedisStorage allows traffic during Redis outage (configurable)
2. **Static ML Weights** - Classifier trained on 662 events; no online learning (weights updated manually)
3. **DNS Timeout Risk** - Bot verification can block for up to 30s on slow DNS
4. **GeoIP Provider Required** - GeoIP blocking requires provider configuration (IPApiProvider included free)
5. **Clock Skew** - Rate limiting assumes synchronized server clocks

---

## Security Considerations

### This Package IS

- A layer of defense for PHP applications
- ML-based threat classification
- Bot verification and honeypot system
- Rate limiting and IP scoring

### This Package IS NOT

- A replacement for edge WAF (Cloudflare, AWS WAF) for volumetric attacks
- Network-level DDoS protection (use Cloudflare/AWS Shield for L3/L4 attacks)
- Penetration tested by third party
- A guarantee of security

**Note:** This WAF DOES provide application-level DDoS protection via rate limiting (4 algorithms), IP scoring, and auto-ban. For volumetric network attacks (L3/L4), use edge protection in addition.

**Always use defense in depth. Deploy alongside edge protection for maximum security.**

---

## License

MIT License - see [LICENSE](LICENSE)

---

## Credits

Trained on security events from real production environments.
ML model based on Naive Bayes classification with feature extraction from attack patterns.
