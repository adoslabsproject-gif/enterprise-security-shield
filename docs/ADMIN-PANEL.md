# Admin Panel Integration Guide

Technical documentation for integrating Security Shield with Enterprise Admin Panel.

---

## Module Registration

The Security Shield provides `SecurityShieldAdminModule` that implements `AdminModuleInterface`.

### Automatic Registration

If using ModuleRegistry auto-discovery:

```php
// ModuleRegistry calls: new SecurityShieldAdminModule($db, $logger)
$registry->register(SecurityShieldAdminModule::class);
```

### Manual Registration

```php
use AdosLabs\EnterpriseSecurityShield\AdminIntegration\SecurityShieldAdminModule;
use AdosLabs\EnterpriseSecurityShield\Storage\RedisStorage;
use AdosLabs\EnterpriseSecurityShield\Config\SecurityConfig;

$redis = new Redis();
$redis->connect('127.0.0.1', 6379);

$storage = new RedisStorage($redis);
$config = new SecurityConfig();

$module = new SecurityShieldAdminModule();
$module->setStorage($storage)
       ->setConfig($config)
       ->setDatabasePool($db);

$adminPanel->registerModule($module);
```

---

## Routes Provided

| Method | Path | Handler | Description |
|--------|------|---------|-------------|
| GET | `/security` | `dashboard` | Main dashboard |
| GET | `/security/ips` | `ipManagement` | IP management list |
| POST | `/security/ips/ban` | `banIp` | Ban an IP |
| POST | `/security/ips/unban` | `unbanIp` | Unban an IP |
| POST | `/security/ips/whitelist` | `addToWhitelist` | Add to whitelist |
| POST | `/security/ips/remove-whitelist` | `removeFromWhitelist` | Remove from whitelist |
| POST | `/security/ips/clear-expired` | `clearExpiredBans` | Clear expired bans |
| GET | `/security/ips/lookup` | `ipLookup` | IP details (query: `?ip=x.x.x.x`) |
| GET | `/security/events` | `events` | Security event log |
| POST | `/security/events/clear` | `clearEvents` | Clear old events |
| GET | `/security/events/export` | `exportEvents` | Export as CSV |
| GET | `/security/config` | `config` | Configuration page |
| POST | `/security/config/save` | `saveConfig` | Save configuration |
| POST | `/security/config/preset` | `applyPreset` | Apply preset (low/medium/high) |
| GET | `/security/waf` | `wafRules` | WAF rules page |
| POST | `/security/waf/toggle` | `toggleWafRule` | Enable/disable rule |
| GET | `/security/ml` | `mlThreats` | ML threats page |
| POST | `/security/ml/retrain` | `retrainModel` | Retrain ML model |
| GET | `/security/ratelimit` | `rateLimiting` | Rate limit settings |
| POST | `/security/ratelimit/save` | `saveRateLimits` | Save rate limits |

### API Endpoints (JSON)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/security/api/stats` | Get statistics |
| GET | `/security/api/recent-threats` | Recent threat events |
| GET | `/security/api/ip-score` | Get IP score (query: `?ip=x.x.x.x`) |

---

## Sidebar Tabs

The module registers these sidebar entries:

| Label | URL | Icon | Priority |
|-------|-----|------|----------|
| WAF Dashboard | `/security` | shield | 15 |
| WAF Rules | `/security/waf` | shield | 16 |
| ML Threats | `/security/ml` | activity | 17 |
| Rate Limiting | `/security/ratelimit` | activity | 18 |
| IP Management | `/security/ips` | shield | 19 |
| Security Events | `/security/events` | file-text | 20 |
| WAF Config | `/security/config` | database | 21 |

Note: IP Lookup is not in sidebar. Access via `/security/ips/lookup?ip=x.x.x.x` or link from IP Management page.

---

## Views

All views use Matrix theme with `eap-*` BEM CSS classes.

### View Variables

Each view receives:

| Variable | Type | Description |
|----------|------|-------------|
| `$page_title` | string | Page title |
| `$admin_base_path` | string | Admin URL prefix |
| `$csrf_input` | string | CSRF hidden input HTML |

### Dashboard View Variables

| Variable | Type |
|----------|------|
| `$stats` | array (threats_24h, blocked_24h, banned_ips, etc.) |
| `$recentThreats` | array |
| `$topThreatenedIps` | array |

### IP Management View Variables

| Variable | Type |
|----------|------|
| `$bannedIps` | array |
| `$whitelistedIps` | array |
| `$pagination` | array |

### IP Lookup View Variables

| Variable | Type |
|----------|------|
| `$ipInfo` | array (ip, is_banned, is_whitelisted, score, ban, events) |

### Events View Variables

| Variable | Type |
|----------|------|
| `$events` | array |
| `$pagination` | array |
| `$filters` | array |

### Config View Variables

| Variable | Type |
|----------|------|
| `$config` | array |
| `$presets` | array |

---

## Database Installation

The module runs migrations on `install()`:

```php
$module->install();
```

Migrations are in `database/migrations/{driver}/`:
- `postgresql/` - PostgreSQL migrations
- `mysql/` - MySQL migrations

Tables created:
- `banned_ips`
- `whitelisted_ips`
- `threat_scores`
- `security_events`
- `ml_models`
- `ml_training_data`
- `security_config`

---

## Configuration Schema

The module provides these configurable options:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `score_threshold` | number | 50 | Auto-ban threshold |
| `ban_duration` | number | 86400 | Ban duration (seconds) |
| `rate_limit_max` | number | 100 | Max requests per window |
| `rate_limit_window` | number | 60 | Rate limit window (seconds) |
| `honeypot_enabled` | boolean | true | Enable honeypot traps |
| `bot_verification_enabled` | boolean | true | Verify bots via DNS |
| `fail_closed` | boolean | false | Block all if storage down |

---

## Security Presets

### Low (Monitoring)

```php
[
    'rate_limit_max' => 200,
    'ml_threshold' => 80,
    'auto_ban_enabled' => false,
    'mode' => 'monitor'
]
```

### Medium (Production)

```php
[
    'rate_limit_max' => 100,
    'ml_threshold' => 60,
    'auto_ban_enabled' => true,
    'ban_duration' => 86400,
    'mode' => 'protect'
]
```

### High (Paranoid)

```php
[
    'rate_limit_max' => 30,
    'ml_threshold' => 40,
    'auto_ban_enabled' => true,
    'ban_duration' => 0, // Permanent
    'mode' => 'paranoid'
]
```

---

## Permissions

The module defines these permissions:

| Permission | Description |
|------------|-------------|
| `security.view` | View dashboard and stats |
| `security.manage_ips` | Ban/unban/whitelist IPs |
| `security.view_events` | View security event log |
| `security.configure` | Modify configuration |

---

## CSS Requirements

Views use Enterprise Admin Panel CSS classes:

```css
/* Required classes */
.eap-page-header, .eap-page-header__content, .eap-page-header__actions
.eap-page-title, .eap-page-subtitle
.eap-card, .eap-card__header, .eap-card__body, .eap-card__title
.eap-stat-card, .eap-stat-card--danger, .eap-stat-card--success, etc.
.eap-grid, .eap-grid--2, .eap-grid--3, .eap-grid--4
.eap-table, .eap-table__cell--*, .eap-table--compact
.eap-badge, .eap-badge--danger, .eap-badge--success, etc.
.eap-btn, .eap-btn--primary, .eap-btn--danger, etc.
.eap-form, .eap-form-group, .eap-form-label, .eap-input
.eap-empty-state
.eap-kv-list, .eap-kv-list__item, .eap-kv-list__key, .eap-kv-list__value
.eap-code, .eap-code-block
.eap-flex, .eap-flex--gap-4
```

Ensure these are defined in your admin panel CSS.

---

## CSRF Protection

All POST forms include CSRF token:

```php
<form method="POST" action="...">
    <?= $csrf_input ?? '' ?>
    <!-- form fields -->
</form>
```

The `$csrf_input` variable contains the hidden input field.

---

## Assets

The module provides optional assets at `assets/`:

- `css/security-shield.css` - Additional styles
- `js/security-dashboard.js` - Dashboard interactions

Load via:

```php
$assetsPath = $module->getAssetsPath(); // Returns: /path/to/assets
```

---

## Error Handling

Controller methods return JSON on AJAX requests:

```php
// Success
return $this->json(['success' => true, 'message' => 'IP banned']);

// Error
return $this->json(['success' => false, 'error' => 'IP not found'], 404);
```

For regular requests, they redirect with flash messages.

---

## Extending

### Custom Storage

```php
$module->setStorage(new MyCustomStorage());
```

Storage must implement `StorageInterface`.

### Custom Views

Override views path:

```php
// In your AdminModuleInterface implementation
public function getViewsPath(): ?string
{
    return '/my/custom/views/security';
}
```

### Adding Routes

Extend `SecurityController` or create wrapper:

```php
class MySecurityController extends SecurityController
{
    public function customAction(): Response
    {
        // Custom logic
    }
}
```
