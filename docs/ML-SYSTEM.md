# Machine Learning System - Technical Documentation

How the ML threat detection actually works.

---

## Overview

The ML system consists of three components:

1. **ThreatClassifier** - Pre-trained Naive Bayes classifier
2. **OnlineLearningClassifier** - Continuous learning from events
3. **RequestAnalyzer** - Combines ML with pattern-based scoring

---

## 1. ThreatClassifier

**File**: `src/ML/ThreatClassifier.php`

### Algorithm

**Naive Bayes** with log-probability calculation:

```
P(class|features) ∝ P(class) × Π P(feature|class)
```

Using log-space to prevent underflow:

```php
$logProb = log($prior);
foreach ($features as $feature) {
    $logProb += log($featureWeight[$feature][$class] + 0.001);
}
```

Softmax normalization produces probability distribution across classes.

### Training Data

Pre-trained on 662 real security events:
- Source: Aggregated production logs and security research datasets
- 188 confirmed attack patterns extracted

**This is real data, not synthetic.**

### Feature Categories

#### User-Agent Features (38 signatures)

| Feature | Weight for SCANNER | Weight for LEGITIMATE |
|---------|-------------------|----------------------|
| `ua_curl` | 0.85 | 0.02 |
| `ua_python` | 0.78 | 0.05 |
| `ua_censys` | 0.98 | 0.0 |
| `ua_zgrab` | 0.97 | 0.0 |
| `ua_masscan` | 0.99 | 0.0 |
| `ua_sqlmap` | 0.99 | 0.0 |
| `ua_hello_world` (GPON) | 0.95 (IOT_EXPLOIT) | 0.001 |

#### Path Features (40+ patterns)

| Feature | Primary Class |
|---------|--------------|
| `path_wp_admin` | CMS_PROBE |
| `path_phpmyadmin` | CONFIG_HUNT |
| `path_env` | CREDENTIAL_THEFT |
| `path_git` | CREDENTIAL_THEFT |
| `path_gponform` | IOT_EXPLOIT |
| `path_traversal` | PATH_TRAVERSAL |

#### Behavioral Features

| Feature | Description | Detection |
|---------|-------------|-----------|
| `high_404_rate` | >5 404s | SCANNER |
| `rapid_requests` | >30 req/min | SCANNER, BRUTE_FORCE |
| `login_failure_burst` | >=3 failures | BRUTE_FORCE |
| `rate_limit_exceeded` | Hit rate limit | SCANNER |

### Classification Categories

| Category | Prior | Description |
|----------|-------|-------------|
| SCANNER | 0.12 | Automated vulnerability scanners |
| BOT_SPOOF | 0.05 | Fake search engine bots |
| CMS_PROBE | 0.08 | WordPress/Joomla/Drupal attacks |
| CONFIG_HUNT | 0.04 | .env, config.php access |
| PATH_TRAVERSAL | 0.02 | Directory traversal |
| CREDENTIAL_THEFT | 0.01 | AWS keys, .git exposure |
| IOT_EXPLOIT | 0.03 | GPON, router exploits |
| BRUTE_FORCE | 0.03 | Login attacks |
| LEGITIMATE | 0.62 | Normal users |

### Usage

```php
$classifier = new ThreatClassifier();
$classifier->setConfidenceThreshold(0.65);
$classifier->enableBotVerification(true);

$result = $classifier->classify(
    ip: '192.168.1.100',
    userAgent: 'curl/7.68.0',
    path: '/wp-admin/',
    method: 'GET',
    headers: ['accept' => 'text/html'],
    behaviorMetrics: ['404_count' => 10]
);

// Result:
// [
//     'classification' => 'SCANNER',
//     'confidence' => 0.89,
//     'is_threat' => true,
//     'features_detected' => ['ua_curl', 'path_wp_admin', 'high_404_rate'],
//     'probabilities' => ['SCANNER' => 0.89, 'CMS_PROBE' => 0.08, ...],
//     'reasoning' => 'SCANNER (HIGH confidence: 89%). Evidence: curl UA; WP admin access'
// ]
```

### Bot Verification

When User-Agent claims to be a search bot (Googlebot, Bingbot, etc.):

1. Reverse DNS lookup: IP -> hostname
2. Check hostname ends with expected domain
3. Forward DNS lookup: hostname -> IP
4. Verify IP matches

If verification fails: `BOT_SPOOF` classification.

---

## 2. OnlineLearningClassifier

**File**: `src/ML/OnlineLearningClassifier.php`

### How It Works

Every security event updates the model:

```php
$classifier->learn($event);
```

Weight update formula:

```
new_weight = old_weight × decay + learning_rate × observation
```

### Concept Drift

Decay factor (0.995) ensures:
- Recent patterns weighted higher
- Old patterns gradually fade
- Model adapts to new attack vectors

### Persistence

Model state saved to Redis/Database:
- Feature weights
- Class priors
- Training sample count
- Last update timestamp

### Integration

```php
$classifier = new OnlineLearningClassifier($storage);

// Load existing model
$classifier->load();

// Security event occurs
$classifier->learn([
    'type' => 'SCANNER',
    'features' => ['ua_curl', 'path_wp_admin'],
    'confidence' => 0.85
]);

// Model updates immediately
$classifier->save();
```

---

## 3. RequestAnalyzer

**File**: `src/ML/RequestAnalyzer.php`

### Combined Scoring

1. Pattern-based scoring runs first (ThreatPatterns)
2. ML classifier analyzes request
3. ML score weighted at 40% added to pattern score
4. High-confidence ML (>=85%) triggers immediate action

### Score Calculation

```php
$patternScore = $threatPatterns->score($request);  // 0-100
$mlResult = $classifier->classify($request);       // 0-1 confidence

$mlScore = $mlResult['confidence'] * 100 * 0.4;    // 40% weight
$totalScore = min(100, $patternScore + $mlScore);
```

### Decision Thresholds

| ML Confidence | Action |
|---------------|--------|
| >= 95% | Immediate block (if threat) |
| >= 85% | High-priority block |
| >= 65% | Add to total score |
| < 65% | Ignore ML result |

---

## Limitations

### What Naive Bayes Cannot Do

1. **Context understanding** - Treats features independently
2. **Sequence analysis** - No memory of request order
3. **Semantic understanding** - Pattern matching only
4. **Zero-day detection** - Only known patterns

### False Positive Risks

| Scenario | Risk |
|----------|------|
| Legitimate curl usage | May flag as SCANNER |
| WordPress admins | May flag as CMS_PROBE |
| High traffic APIs | May flag as BRUTE_FORCE |

**Mitigation**: Whitelist known IPs, tune thresholds, review flagged events.

### Training Data Bias

Training data from single production site. May not generalize to:
- Different CMS (trained mostly on WordPress attacks)
- Different industries
- Different attack patterns

---

## Model Statistics

```php
$classifier->getModelStats();

// Returns:
// [
//     'feature_count' => 38,
//     'class_count' => 9,
//     'attack_patterns' => 40,
//     'scanner_signatures' => 30,
//     'verifiable_bots' => 13,
//     'trained_on' => 'Aggregated production logs and security research datasets',
//     'training_events' => 662,
//     'confirmed_attacks' => 188
// ]
```

---

## Retraining

### Manual Retrain

```php
$classifier = new OnlineLearningClassifier($storage);

// Load training data
$trainingData = json_decode(file_get_contents('training-data.json'), true);

foreach ($trainingData as $event) {
    $classifier->learn($event);
}

$classifier->save();
```

### Automated Retrain

Via Admin Panel: `/security/ml` -> "Retrain Model" button

This:
1. Loads recent security events from database
2. Feeds them through OnlineLearningClassifier
3. Saves updated model

---

## Performance

| Operation | Latency |
|-----------|---------|
| Feature extraction | ~1ms |
| Probability calculation | ~1ms |
| Bot verification (cached) | ~0ms |
| Bot verification (DNS) | ~50-200ms |
| Total classification | ~3ms (no DNS) |

Bot verification cached for 24 hours.

---

## Tuning

### Confidence Threshold

```php
$classifier->setConfidenceThreshold(0.65);  // Default
```

- Lower (0.5): More sensitive, more false positives
- Higher (0.8): Less sensitive, may miss attacks

### ML Weight in Total Score

```php
$analyzer->setMLWeight(0.4);  // Default 40%
```

- Higher: Trust ML more
- Lower: Trust patterns more

### Disable ML

```php
$middleware->setMLEnabled(false);  // Pattern-based only
```

---

## Debugging

### Log Classification Reasoning

```php
$result = $classifier->classify(...);

$logger->info('ML Classification', [
    'ip' => $ip,
    'classification' => $result['classification'],
    'confidence' => $result['confidence'],
    'features' => $result['features_detected'],
    'reasoning' => $result['reasoning']
]);
```

### Check Feature Extraction

```php
// Internal method - use for debugging
$features = $classifier->extractFeatures($ip, $ua, $path, $method, $headers, $metrics);
```

### Verify Bot Detection

```php
$spoofResult = $classifier->isSpoofedBot($ip, $userAgent);

if ($spoofResult !== null) {
    // Bot claims to be $spoofResult['bot_name']
    // DNS verification failed
    // Expected domain: $spoofResult['expected_domain']
}
```
