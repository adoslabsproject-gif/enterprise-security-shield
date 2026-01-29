<?php
/**
 * Rate Limiting View - Matrix Theme
 *
 * @var array $config
 * @var array $endpoints
 * @var array $stats
 * @var string $page_title
 * @var string $admin_base_path
 */
?>

<!-- Page Header -->
<div class="eap-page-header">
    <div class="eap-page-header__content">
        <h1 class="eap-page-title"><?= htmlspecialchars($page_title) ?></h1>
        <p class="eap-page-subtitle">Configure request rate limits and throttling</p>
    </div>
    <div class="eap-page-header__actions">
        <span class="eap-badge eap-badge--warning">
            <span class="eap-badge__dot"></span>
            <?= number_format($stats['rate_limit_hits_24h'] ?? 0) ?> rate limits triggered (24h)
        </span>
    </div>
</div>

<!-- Global Settings Card -->
<div class="eap-card">
    <div class="eap-card__header">
        <h2 class="eap-card__title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                <circle cx="12" cy="12" r="3"/>
                <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>
            </svg>
            Global Rate Limit Settings
        </h2>
    </div>
    <div class="eap-card__body">
        <form method="POST" action="<?= htmlspecialchars($admin_base_path . '/security/ratelimit/save') ?>" class="eap-form">
            <div class="eap-grid eap-grid--4">
                <div class="eap-form-group">
                    <label class="eap-form-label">Max Requests (Global)</label>
                    <input type="number" name="rate_limit_max" class="eap-input"
                           value="<?= (int) ($config['rate_limit_max'] ?? 100) ?>"
                           min="1" max="10000">
                    <span class="eap-form-hint">Per IP per window</span>
                </div>
                <div class="eap-form-group">
                    <label class="eap-form-label">Window (seconds)</label>
                    <input type="number" name="rate_limit_window" class="eap-input"
                           value="<?= (int) ($config['rate_limit_window'] ?? 60) ?>"
                           min="10" max="3600">
                    <span class="eap-form-hint">Time window for counting</span>
                </div>
                <div class="eap-form-group">
                    <label class="eap-form-label">Login Attempts</label>
                    <input type="number" name="rate_limit_login" class="eap-input"
                           value="<?= (int) ($config['rate_limit_login'] ?? 5) ?>"
                           min="1" max="100">
                    <span class="eap-form-hint">Per minute per IP</span>
                </div>
                <div class="eap-form-group">
                    <label class="eap-form-label">API Requests</label>
                    <input type="number" name="rate_limit_api" class="eap-input"
                           value="<?= (int) ($config['rate_limit_api'] ?? 1000) ?>"
                           min="1" max="10000">
                    <span class="eap-form-hint">Per minute per key</span>
                </div>
            </div>
            <div class="eap-form-actions">
                <button type="submit" class="eap-btn eap-btn--primary">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/>
                        <polyline points="17 21 17 13 7 13 7 21"/>
                        <polyline points="7 3 7 8 15 8"/>
                    </svg>
                    Save Settings
                </button>
            </div>
        </form>
    </div>
</div>

<!-- Per-Endpoint Rate Limits -->
<div class="eap-card">
    <div class="eap-card__header">
        <h2 class="eap-card__title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                <circle cx="12" cy="12" r="10"/>
                <polyline points="12 6 12 12 16 14"/>
            </svg>
            Per-Endpoint Rate Limits
        </h2>
        <span class="eap-badge eap-badge--secondary"><?= count($endpoints) ?> endpoints</span>
    </div>
    <div class="eap-card__body eap-card__body--no-padding">
        <table class="eap-table">
            <thead>
                <tr>
                    <th>Endpoint</th>
                    <th>Method</th>
                    <th class="eap-table__cell--right">Limit</th>
                    <th class="eap-table__cell--right">Window</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($endpoints as $endpoint): ?>
                <tr>
                    <td><code class="eap-code"><?= htmlspecialchars($endpoint['path']) ?></code></td>
                    <td>
                        <span class="eap-badge eap-badge--<?= $endpoint['method'] === 'POST' ? 'warning' : 'info' ?>">
                            <?= htmlspecialchars($endpoint['method']) ?>
                        </span>
                    </td>
                    <td class="eap-table__cell--right">
                        <strong><?= number_format($endpoint['limit']) ?></strong> req
                    </td>
                    <td class="eap-table__cell--right eap-table__cell--mono">
                        <?= number_format($endpoint['window']) ?>s
                    </td>
                    <td class="eap-table__cell--muted">
                        <?php
                        $desc = match($endpoint['path']) {
                            '/login' => 'Prevents brute force attacks',
                            '/api/*' => 'API rate limiting for authenticated users',
                            '/register' => 'Prevents registration abuse',
                            '/password/reset' => 'Prevents password reset abuse',
                            '/contact' => 'Prevents contact form spam',
                            default => 'Custom endpoint protection',
                        };
                        echo htmlspecialchars($desc);
                        ?>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<!-- Algorithms & Tiers -->
<div class="eap-grid eap-grid--2">
    <div class="eap-card">
        <div class="eap-card__header">
            <h3 class="eap-card__title">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                </svg>
                Algorithms Available
            </h3>
        </div>
        <div class="eap-card__body">
            <div class="eap-algorithm-list">
                <div class="eap-algorithm-item">
                    <span class="eap-badge eap-badge--primary">Sliding Window</span>
                    <span class="eap-badge eap-badge--success eap-badge--sm">Default</span>
                    <p class="eap-algorithm-item__desc">Most accurate, prevents bursts at window boundaries.</p>
                </div>
                <div class="eap-algorithm-item">
                    <span class="eap-badge eap-badge--secondary">Token Bucket</span>
                    <p class="eap-algorithm-item__desc">Allows controlled bursts up to bucket size.</p>
                </div>
                <div class="eap-algorithm-item">
                    <span class="eap-badge eap-badge--info">Leaky Bucket</span>
                    <p class="eap-algorithm-item__desc">Strict rate enforcement, no bursts allowed.</p>
                </div>
                <div class="eap-algorithm-item">
                    <span class="eap-badge eap-badge--warning">Fixed Window</span>
                    <p class="eap-algorithm-item__desc">Simplest but can allow 2x burst at boundaries.</p>
                </div>
            </div>
        </div>
    </div>

    <div class="eap-card">
        <div class="eap-card__header">
            <h3 class="eap-card__title">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                    <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
                    <circle cx="9" cy="7" r="4"/>
                    <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
                    <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
                </svg>
                Tier Multipliers
            </h3>
        </div>
        <div class="eap-card__body eap-card__body--no-padding">
            <table class="eap-table eap-table--compact">
                <thead>
                    <tr>
                        <th>Tier</th>
                        <th class="eap-table__cell--center">Multiplier</th>
                        <th class="eap-table__cell--right">Effective Limit</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><span class="eap-badge eap-badge--secondary">Free</span></td>
                        <td class="eap-table__cell--center">1x</td>
                        <td class="eap-table__cell--right eap-table__cell--mono"><?= number_format($config['rate_limit_max'] ?? 100) ?> req/min</td>
                    </tr>
                    <tr>
                        <td><span class="eap-badge eap-badge--info">Basic</span></td>
                        <td class="eap-table__cell--center">2x</td>
                        <td class="eap-table__cell--right eap-table__cell--mono"><?= number_format(($config['rate_limit_max'] ?? 100) * 2) ?> req/min</td>
                    </tr>
                    <tr>
                        <td><span class="eap-badge eap-badge--warning">Premium</span></td>
                        <td class="eap-table__cell--center">5x</td>
                        <td class="eap-table__cell--right eap-table__cell--mono"><?= number_format(($config['rate_limit_max'] ?? 100) * 5) ?> req/min</td>
                    </tr>
                    <tr>
                        <td><span class="eap-badge eap-badge--success">Enterprise</span></td>
                        <td class="eap-table__cell--center">10x</td>
                        <td class="eap-table__cell--right eap-table__cell--mono"><?= number_format(($config['rate_limit_max'] ?? 100) * 10) ?> req/min</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</div>

<!-- Response Headers -->
<div class="eap-card">
    <div class="eap-card__header">
        <h3 class="eap-card__title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                <polyline points="16 18 22 12 16 6"/>
                <polyline points="8 6 2 12 8 18"/>
            </svg>
            Rate Limit Response Headers
        </h3>
    </div>
    <div class="eap-card__body">
        <p class="eap-text--muted">The following headers are included in responses:</p>
        <pre class="eap-code-block"><code>X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1706536800
Retry-After: 30 <span class="eap-code-comment">// only when rate limited</span></code></pre>
    </div>
</div>
