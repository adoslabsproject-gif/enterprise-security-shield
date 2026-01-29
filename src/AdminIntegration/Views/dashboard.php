<?php
/**
 * Security Shield Dashboard View.
 *
 * @var array $stats Security statistics
 * @var array $recent_threats Recent threat events
 * @var array $banned_ips Banned IPs
 * @var array $honeypot_stats Honeypot statistics
 * @var string $csrf_token CSRF token (from BaseController)
 */

// Helper functions for badge classes (wrapped to prevent redefinition)
if (!function_exists('essThreatBadgeClass')) {
    function essThreatBadgeClass(string $type): string
    {
        return match (strtolower($type)) {
            'auto_ban', 'ban' => 'danger',
            'honeypot', 'honeypot_access' => 'warning',
            'rate_limit', 'rate_limit_exceeded' => 'info',
            'sqli', 'sqli_detected' => 'danger',
            'xss', 'xss_detected' => 'danger',
            'scanner', 'scanner_detected' => 'warning',
            default => 'secondary',
        };
    }
}

if (!function_exists('essScoreClass')) {
    function essScoreClass(int $score): string
    {
        if ($score >= 80) {
            return 'danger';
        }
        if ($score >= 50) {
            return 'warning';
        }
        if ($score >= 20) {
            return 'info';
        }

        return 'success';
    }
}

// Normalize variable names (controller uses snake_case)
$recentThreats = $recent_threats ?? [];
$bannedIps = $banned_ips ?? [];
$csrfToken = $csrf_token ?? '';

// Pass data to JavaScript via data attributes
$chartData = [
    'hourlyLabels' => $stats['hourly_labels'] ?? [],
    'hourlyThreats' => $stats['hourly_threats'] ?? [],
    'hourlyRequests' => $stats['hourly_requests'] ?? [],
    'attackTypes' => $stats['attack_types'] ?? [],
];
?>
<div class="ess-dashboard" data-chart-config="<?= htmlspecialchars(json_encode($chartData), ENT_QUOTES) ?>">
    <h1 class="ess-dashboard__title">Security Dashboard</h1>

    <!-- Stats Cards -->
    <div class="ess-stats-grid">
        <div class="ess-stats-grid__card ess-stats-grid__card--primary">
            <div class="ess-stats-grid__icon">
                <svg class="ess-stats-grid__icon-svg" viewBox="0 0 24 24" width="24" height="24" stroke="currentColor" fill="none">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
                </svg>
            </div>
            <div class="ess-stats-grid__content">
                <div class="ess-stats-grid__value"><?= number_format($stats['requests_today'] ?? 0) ?></div>
                <div class="ess-stats-grid__label">Requests Today</div>
            </div>
        </div>

        <div class="ess-stats-grid__card ess-stats-grid__card--danger">
            <div class="ess-stats-grid__icon">
                <svg class="ess-stats-grid__icon-svg" viewBox="0 0 24 24" width="24" height="24" stroke="currentColor" fill="none">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                </svg>
            </div>
            <div class="ess-stats-grid__content">
                <div class="ess-stats-grid__value"><?= number_format($stats['threats_blocked'] ?? 0) ?></div>
                <div class="ess-stats-grid__label">Threats Blocked</div>
            </div>
        </div>

        <div class="ess-stats-grid__card ess-stats-grid__card--warning">
            <div class="ess-stats-grid__icon">
                <svg class="ess-stats-grid__icon-svg" viewBox="0 0 24 24" width="24" height="24" stroke="currentColor" fill="none">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 5.636a9 9 0 010 12.728m-3.536-3.536a4 4 0 010-5.656m-5.656 0a4 4 0 000 5.656m-3.536 3.536a9 9 0 010-12.728"/>
                </svg>
            </div>
            <div class="ess-stats-grid__content">
                <div class="ess-stats-grid__value"><?= number_format($stats['banned_ips'] ?? 0) ?></div>
                <div class="ess-stats-grid__label">Banned IPs</div>
            </div>
        </div>

        <div class="ess-stats-grid__card ess-stats-grid__card--success">
            <div class="ess-stats-grid__icon">
                <svg class="ess-stats-grid__icon-svg" viewBox="0 0 24 24" width="24" height="24" stroke="currentColor" fill="none">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
            </div>
            <div class="ess-stats-grid__content">
                <div class="ess-stats-grid__value"><?= number_format($stats['bots_verified'] ?? 0) ?></div>
                <div class="ess-stats-grid__label">Verified Bots</div>
            </div>
        </div>
    </div>

    <!-- Charts Row -->
    <div class="ess-charts-row">
        <div class="ess-chart-card">
            <h3 class="ess-chart-card__title">Threat Activity (24h)</h3>
            <canvas id="ess-threat-chart" class="ess-chart-card__canvas" height="200"></canvas>
        </div>
        <div class="ess-chart-card">
            <h3 class="ess-chart-card__title">Attack Types</h3>
            <canvas id="ess-attack-types-chart" class="ess-chart-card__canvas" height="200"></canvas>
        </div>
    </div>

    <!-- Recent Threats Table -->
    <div class="ess-table-card">
        <div class="ess-table-card__header">
            <h3 class="ess-table-card__title">Recent Threats</h3>
            <a href="/security/events" class="ess-btn ess-btn--sm ess-btn--secondary">View All</a>
        </div>
        <div class="ess-table-card__wrapper">
            <table class="ess-table">
                <thead class="ess-table__head">
                    <tr class="ess-table__row">
                        <th class="ess-table__th">Time</th>
                        <th class="ess-table__th">IP Address</th>
                        <th class="ess-table__th">Type</th>
                        <th class="ess-table__th">Path</th>
                        <th class="ess-table__th">Score</th>
                        <th class="ess-table__th">Action</th>
                    </tr>
                </thead>
                <tbody class="ess-table__body">
                    <?php foreach ($recentThreats ?? [] as $threat): ?>
                    <tr class="ess-table__row">
                        <td class="ess-table__td ess-table__td--muted"><?= htmlspecialchars($threat['time'] ?? '') ?></td>
                        <td class="ess-table__td">
                            <code class="ess-code"><?= htmlspecialchars($threat['ip'] ?? '') ?></code>
                            <?php if (!empty($threat['country'])): ?>
                            <span class="ess-badge ess-badge--secondary"><?= htmlspecialchars($threat['country']) ?></span>
                            <?php endif; ?>
                        </td>
                        <td class="ess-table__td">
                            <span class="ess-badge ess-badge--<?= htmlspecialchars(essThreatBadgeClass($threat['type'] ?? '')) ?>">
                                <?= htmlspecialchars($threat['type'] ?? 'unknown') ?>
                            </span>
                        </td>
                        <td class="ess-table__td">
                            <code class="ess-code ess-code--path"><?= htmlspecialchars(substr($threat['path'] ?? '', 0, 40)) ?></code>
                        </td>
                        <td class="ess-table__td">
                            <div class="ess-score-bar">
                                <div class="ess-score-bar__fill" data-score="<?= min(100, $threat['score'] ?? 0) ?>"></div>
                                <span class="ess-score-bar__value"><?= $threat['score'] ?? 0 ?></span>
                            </div>
                        </td>
                        <td class="ess-table__td">
                            <span class="ess-action-badge ess-action-badge--<?= strtolower($threat['action'] ?? 'allow') ?>">
                                <?= htmlspecialchars($threat['action'] ?? 'ALLOW') ?>
                            </span>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                    <?php if (empty($recentThreats)): ?>
                    <tr class="ess-table__row">
                        <td class="ess-table__td ess-table__td--empty" colspan="6">No recent threats detected</td>
                    </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- Banned IPs -->
    <div class="ess-table-card">
        <div class="ess-table-card__header">
            <h3 class="ess-table-card__title">Currently Banned IPs</h3>
            <a href="/security/ips" class="ess-btn ess-btn--sm ess-btn--secondary">Manage IPs</a>
        </div>
        <div class="ess-table-card__wrapper">
            <table class="ess-table">
                <thead class="ess-table__head">
                    <tr class="ess-table__row">
                        <th class="ess-table__th">IP Address</th>
                        <th class="ess-table__th">Reason</th>
                        <th class="ess-table__th">Banned At</th>
                        <th class="ess-table__th">Expires</th>
                        <th class="ess-table__th">Actions</th>
                    </tr>
                </thead>
                <tbody class="ess-table__body">
                    <?php foreach ($bannedIps as $ban): ?>
                    <tr class="ess-table__row">
                        <td class="ess-table__td"><code class="ess-code"><?= htmlspecialchars($ban['ip'] ?? '') ?></code></td>
                        <td class="ess-table__td"><?= htmlspecialchars(substr($ban['reason'] ?? 'Manual', 0, 50)) ?></td>
                        <td class="ess-table__td ess-table__td--muted"><?= htmlspecialchars($ban['banned_at'] ?? '') ?></td>
                        <td class="ess-table__td ess-table__td--muted"><?= htmlspecialchars($ban['expires_at'] ?? '') ?></td>
                        <td class="ess-table__td">
                            <form method="POST" action="/security/ips/unban" class="ess-form--inline">
                                <input type="hidden" name="ip" value="<?= htmlspecialchars($ban['ip'] ?? '') ?>">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                                <button type="submit" class="ess-btn ess-btn--sm ess-btn--success">Unban</button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                    <?php if (empty($bannedIps)): ?>
                    <tr class="ess-table__row">
                        <td class="ess-table__td ess-table__td--empty" colspan="5">No currently banned IPs</td>
                    </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- Honeypot Stats -->
    <?php if (!empty($honeypot_stats)): ?>
    <div class="ess-table-card">
        <div class="ess-table-card__header">
            <h3 class="ess-table-card__title">Top Honeypot Paths</h3>
        </div>
        <div class="ess-table-card__wrapper">
            <table class="ess-table">
                <thead class="ess-table__head">
                    <tr class="ess-table__row">
                        <th class="ess-table__th">Path</th>
                        <th class="ess-table__th">Hits</th>
                    </tr>
                </thead>
                <tbody class="ess-table__body">
                    <?php foreach ($honeypot_stats as $hp): ?>
                    <tr class="ess-table__row">
                        <td class="ess-table__td"><code class="ess-code"><?= htmlspecialchars($hp['path'] ?? '') ?></code></td>
                        <td class="ess-table__td"><?= number_format($hp['hits'] ?? 0) ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
    <?php endif; ?>
</div>
