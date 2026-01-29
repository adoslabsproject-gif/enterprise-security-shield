<?php
/**
 * Security Shield Dashboard View - Matrix Theme.
 *
 * @var array $stats Security statistics
 * @var array $recent_threats Recent threat events
 * @var array $banned_ips Banned IPs
 * @var array $honeypot_stats Honeypot statistics
 * @var string $csrf_input CSRF input field
 * @var string $admin_base_path Admin base path
 * @var string $page_title Page title
 */

// Normalize variable names
$recentThreats = $recent_threats ?? [];
$bannedIps = $banned_ips ?? [];
$honeypotStats = $honeypot_stats ?? [];
?>

<!-- Page Header -->
<div class="eap-page-header">
    <div class="eap-page-header__content">
        <h1 class="eap-page-title"><?= htmlspecialchars($page_title ?? 'Security Dashboard') ?></h1>
        <p class="eap-page-subtitle">Real-time security monitoring and threat analysis</p>
    </div>
    <div class="eap-page-header__actions">
        <span class="eap-badge eap-badge--success">
            <span class="eap-badge__dot"></span>
            System Protected
        </span>
    </div>
</div>

<!-- Stats Grid -->
<div class="eap-stats-grid eap-stats-grid--4">
    <div class="eap-stat-card eap-stat-card--info">
        <div class="eap-stat-card__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
            </svg>
        </div>
        <div class="eap-stat-card__content">
            <span class="eap-stat-card__value"><?= number_format($stats['requests_today'] ?? 0) ?></span>
            <span class="eap-stat-card__label">Requests Today</span>
        </div>
    </div>

    <div class="eap-stat-card eap-stat-card--danger">
        <div class="eap-stat-card__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
            </svg>
        </div>
        <div class="eap-stat-card__content">
            <span class="eap-stat-card__value"><?= number_format($stats['threats_blocked'] ?? 0) ?></span>
            <span class="eap-stat-card__label">Threats Blocked</span>
        </div>
    </div>

    <div class="eap-stat-card eap-stat-card--warning">
        <div class="eap-stat-card__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M18.364 5.636a9 9 0 010 12.728m-3.536-3.536a4 4 0 010-5.656m-5.656 0a4 4 0 000 5.656m-3.536 3.536a9 9 0 010-12.728"/>
            </svg>
        </div>
        <div class="eap-stat-card__content">
            <span class="eap-stat-card__value"><?= number_format($stats['banned_ips'] ?? 0) ?></span>
            <span class="eap-stat-card__label">Banned IPs</span>
        </div>
    </div>

    <div class="eap-stat-card eap-stat-card--success">
        <div class="eap-stat-card__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
        </div>
        <div class="eap-stat-card__content">
            <span class="eap-stat-card__value"><?= number_format($stats['bots_verified'] ?? 0) ?></span>
            <span class="eap-stat-card__label">Verified Bots</span>
        </div>
    </div>
</div>

<!-- Recent Threats Table -->
<div class="eap-card">
    <div class="eap-card__header">
        <h2 class="eap-card__title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
            </svg>
            Recent Threats
        </h2>
        <a href="<?= htmlspecialchars($admin_base_path . '/security/events') ?>" class="eap-btn eap-btn--sm eap-btn--secondary">View All</a>
    </div>
    <div class="eap-card__body eap-card__body--no-padding">
        <?php if (empty($recentThreats)): ?>
            <div class="eap-empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="48" height="48">
                    <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
                <p>No recent threats detected</p>
                <span class="eap-text--muted">Your system is running securely</span>
            </div>
        <?php else: ?>
            <table class="eap-table">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>IP Address</th>
                        <th>Type</th>
                        <th>Path</th>
                        <th class="eap-table__cell--center">Score</th>
                        <th class="eap-table__cell--center">Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($recentThreats as $threat): ?>
                    <?php
                    $type = strtolower($threat['type'] ?? '');
                        $badgeClass = match(true) {
                            str_contains($type, 'ban') => 'danger',
                            str_contains($type, 'sqli') || str_contains($type, 'xss') => 'danger',
                            str_contains($type, 'honeypot') => 'warning',
                            str_contains($type, 'rate') => 'info',
                            str_contains($type, 'scanner') => 'warning',
                            default => 'secondary',
                        };
                        $score = (int) ($threat['score'] ?? 0);
                        $scoreClass = $score >= 80 ? 'danger' : ($score >= 50 ? 'warning' : ($score >= 20 ? 'info' : 'success'));
                        ?>
                    <tr>
                        <td class="eap-table__cell--mono"><?= htmlspecialchars($threat['time'] ?? '') ?></td>
                        <td>
                            <code class="eap-code"><?= htmlspecialchars($threat['ip'] ?? '') ?></code>
                            <?php if (!empty($threat['country'])): ?>
                                <span class="eap-badge eap-badge--secondary eap-badge--sm"><?= htmlspecialchars($threat['country']) ?></span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <span class="eap-badge eap-badge--<?= $badgeClass ?>"><?= htmlspecialchars($threat['type'] ?? 'unknown') ?></span>
                        </td>
                        <td class="eap-table__cell--truncate">
                            <code class="eap-code eap-code--sm"><?= htmlspecialchars(substr($threat['path'] ?? '', 0, 40)) ?></code>
                        </td>
                        <td class="eap-table__cell--center">
                            <span class="eap-badge eap-badge--<?= $scoreClass ?>"><?= $score ?></span>
                        </td>
                        <td class="eap-table__cell--center">
                            <?php $action = strtolower($threat['action'] ?? 'allow'); ?>
                            <span class="eap-badge eap-badge--<?= $action === 'block' || $action === 'ban' ? 'danger' : ($action === 'allow' ? 'success' : 'info') ?>">
                                <?= htmlspecialchars(strtoupper($threat['action'] ?? 'ALLOW')) ?>
                            </span>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</div>

<!-- Banned IPs -->
<div class="eap-card">
    <div class="eap-card__header">
        <h2 class="eap-card__title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                <circle cx="12" cy="12" r="10"/>
                <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
            </svg>
            Currently Banned IPs
        </h2>
        <a href="<?= htmlspecialchars($admin_base_path . '/security/ips') ?>" class="eap-btn eap-btn--sm eap-btn--secondary">Manage IPs</a>
    </div>
    <div class="eap-card__body eap-card__body--no-padding">
        <?php if (empty($bannedIps)): ?>
            <div class="eap-empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="48" height="48">
                    <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
                <p>No currently banned IPs</p>
            </div>
        <?php else: ?>
            <table class="eap-table">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Reason</th>
                        <th>Banned At</th>
                        <th>Expires</th>
                        <th class="eap-table__cell--center">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($bannedIps as $ban): ?>
                    <tr>
                        <td><code class="eap-code"><?= htmlspecialchars($ban['ip'] ?? '') ?></code></td>
                        <td class="eap-table__cell--muted"><?= htmlspecialchars(substr($ban['reason'] ?? 'Manual', 0, 50)) ?></td>
                        <td class="eap-table__cell--mono"><?= htmlspecialchars($ban['banned_at'] ?? '') ?></td>
                        <td class="eap-table__cell--mono">
                            <?php if (empty($ban['expires_at'])): ?>
                                <span class="eap-badge eap-badge--danger">Permanent</span>
                            <?php else: ?>
                                <?= htmlspecialchars($ban['expires_at']) ?>
                            <?php endif; ?>
                        </td>
                        <td class="eap-table__cell--center">
                            <form method="POST" action="<?= htmlspecialchars($admin_base_path . '/security/ips/unban') ?>" class="eap-inline-form">
                                <?= $csrf_input ?? '' ?>
                                <input type="hidden" name="ip" value="<?= htmlspecialchars($ban['ip'] ?? '') ?>">
                                <button type="submit" class="eap-btn eap-btn--sm eap-btn--success">Unban</button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</div>

<!-- Honeypot Stats -->
<?php if (!empty($honeypotStats)): ?>
<div class="eap-card">
    <div class="eap-card__header">
        <h2 class="eap-card__title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                <path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/>
            </svg>
            Top Honeypot Paths
        </h2>
        <span class="eap-badge eap-badge--warning"><?= count($honeypotStats) ?> paths</span>
    </div>
    <div class="eap-card__body eap-card__body--no-padding">
        <table class="eap-table">
            <thead>
                <tr>
                    <th>Path</th>
                    <th class="eap-table__cell--right">Hits</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($honeypotStats as $hp): ?>
                <tr>
                    <td><code class="eap-code"><?= htmlspecialchars($hp['path'] ?? '') ?></code></td>
                    <td class="eap-table__cell--right">
                        <span class="eap-badge eap-badge--warning"><?= number_format($hp['hits'] ?? 0) ?></span>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>
<?php endif; ?>
