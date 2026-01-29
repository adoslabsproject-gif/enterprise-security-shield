<?php
/**
 * IP Lookup View - Matrix Theme
 *
 * @var array $ipInfo IP information
 * @var string $csrf_input CSRF input field
 * @var string $admin_base_path Admin base path
 * @var string $page_title Page title
 */
$ipInfo ??= [];
$ip = $ipInfo['ip'] ?? '';
?>

<!-- Page Header -->
<div class="eap-page-header">
    <div class="eap-page-header__content">
        <h1 class="eap-page-title"><?= htmlspecialchars($page_title ?? 'IP Lookup') ?></h1>
        <p class="eap-page-subtitle">Detailed information and history for IP address</p>
    </div>
    <div class="eap-page-header__actions">
        <a href="<?= htmlspecialchars($admin_base_path . '/security/ips') ?>" class="eap-btn eap-btn--secondary">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                <line x1="19" y1="12" x2="5" y2="12"/>
                <polyline points="12 19 5 12 12 5"/>
            </svg>
            Back to IP Management
        </a>
    </div>
</div>

<!-- IP Status Cards -->
<div class="eap-grid eap-grid--4">
    <div class="eap-stat-card <?= $ipInfo['is_banned'] ? 'eap-stat-card--danger' : 'eap-stat-card--success' ?>">
        <div class="eap-stat-card__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <?php if ($ipInfo['is_banned']): ?>
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
                <?php else: ?>
                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                    <polyline points="22 4 12 14.01 9 11.01"/>
                <?php endif; ?>
            </svg>
        </div>
        <div class="eap-stat-card__content">
            <span class="eap-stat-card__value"><?= $ipInfo['is_banned'] ? 'BANNED' : 'CLEAR' ?></span>
            <span class="eap-stat-card__label">Ban Status</span>
        </div>
    </div>

    <div class="eap-stat-card <?= $ipInfo['is_whitelisted'] ? 'eap-stat-card--success' : 'eap-stat-card--secondary' ?>">
        <div class="eap-stat-card__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
        </div>
        <div class="eap-stat-card__content">
            <span class="eap-stat-card__value"><?= $ipInfo['is_whitelisted'] ? 'YES' : 'NO' ?></span>
            <span class="eap-stat-card__label">Whitelisted</span>
        </div>
    </div>

    <div class="eap-stat-card <?= $ipInfo['score'] >= 500 ? 'eap-stat-card--danger' : ($ipInfo['score'] >= 100 ? 'eap-stat-card--warning' : 'eap-stat-card--info') ?>">
        <div class="eap-stat-card__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
            </svg>
        </div>
        <div class="eap-stat-card__content">
            <span class="eap-stat-card__value"><?= number_format($ipInfo['score']) ?></span>
            <span class="eap-stat-card__label">Threat Score</span>
        </div>
    </div>

    <div class="eap-stat-card eap-stat-card--info">
        <div class="eap-stat-card__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                <polyline points="14 2 14 8 20 8"/>
            </svg>
        </div>
        <div class="eap-stat-card__content">
            <span class="eap-stat-card__value"><?= number_format($ipInfo['event_count']) ?></span>
            <span class="eap-stat-card__label">Events Logged</span>
        </div>
    </div>
</div>

<!-- Quick Actions -->
<div class="eap-card">
    <div class="eap-card__header">
        <h2 class="eap-card__title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
            </svg>
            Quick Actions
        </h2>
    </div>
    <div class="eap-card__body">
        <div class="eap-flex eap-flex--gap-4">
            <?php if ($ipInfo['is_banned']): ?>
                <form method="POST" action="<?= htmlspecialchars($admin_base_path . '/security/ips/unban') ?>" class="eap-inline-form">
                    <?= $csrf_input ?? '' ?>
                    <input type="hidden" name="ip" value="<?= htmlspecialchars($ip) ?>">
                    <button type="submit" class="eap-btn eap-btn--success">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                            <polyline points="22 4 12 14.01 9 11.01"/>
                        </svg>
                        Unban IP
                    </button>
                </form>
            <?php else: ?>
                <form method="POST" action="<?= htmlspecialchars($admin_base_path . '/security/ips/ban') ?>" class="eap-inline-form">
                    <?= $csrf_input ?? '' ?>
                    <input type="hidden" name="ip" value="<?= htmlspecialchars($ip) ?>">
                    <input type="hidden" name="reason" value="Manual ban from lookup">
                    <button type="submit" class="eap-btn eap-btn--danger">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                            <circle cx="12" cy="12" r="10"/>
                            <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
                        </svg>
                        Ban IP
                    </button>
                </form>
            <?php endif; ?>

            <?php if ($ipInfo['is_whitelisted']): ?>
                <form method="POST" action="<?= htmlspecialchars($admin_base_path . '/security/ips/remove-whitelist') ?>" class="eap-inline-form">
                    <?= $csrf_input ?? '' ?>
                    <input type="hidden" name="ip" value="<?= htmlspecialchars($ip) ?>">
                    <button type="submit" class="eap-btn eap-btn--warning">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                            <line x1="18" y1="6" x2="6" y2="18"/>
                            <line x1="6" y1="6" x2="18" y2="18"/>
                        </svg>
                        Remove from Whitelist
                    </button>
                </form>
            <?php else: ?>
                <form method="POST" action="<?= htmlspecialchars($admin_base_path . '/security/ips/whitelist') ?>" class="eap-inline-form">
                    <?= $csrf_input ?? '' ?>
                    <input type="hidden" name="ip" value="<?= htmlspecialchars($ip) ?>">
                    <input type="hidden" name="label" value="Added from lookup">
                    <button type="submit" class="eap-btn eap-btn--success">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        </svg>
                        Add to Whitelist
                    </button>
                </form>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- Ban Details (if banned) -->
<?php if ($ipInfo['is_banned'] && $ipInfo['ban']): ?>
<div class="eap-card">
    <div class="eap-card__header">
        <h2 class="eap-card__title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                <circle cx="12" cy="12" r="10"/>
                <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
            </svg>
            Ban Details
        </h2>
        <span class="eap-badge eap-badge--danger">Active Ban</span>
    </div>
    <div class="eap-card__body">
        <div class="eap-kv-list">
            <div class="eap-kv-list__item">
                <span class="eap-kv-list__key">Banned At</span>
                <span class="eap-kv-list__value"><?= htmlspecialchars($ipInfo['ban']['created_at'] ?? $ipInfo['ban']['banned_at'] ?? 'Unknown') ?></span>
            </div>
            <div class="eap-kv-list__item">
                <span class="eap-kv-list__key">Expires</span>
                <span class="eap-kv-list__value">
                    <?php if (empty($ipInfo['ban']['expires_at'])): ?>
                        <span class="eap-badge eap-badge--danger">Permanent</span>
                    <?php else: ?>
                        <?= htmlspecialchars($ipInfo['ban']['expires_at']) ?>
                    <?php endif; ?>
                </span>
            </div>
            <div class="eap-kv-list__item">
                <span class="eap-kv-list__key">Reason</span>
                <span class="eap-kv-list__value"><?= htmlspecialchars($ipInfo['ban']['reason'] ?? 'No reason provided') ?></span>
            </div>
        </div>
    </div>
</div>
<?php endif; ?>

<!-- Recent Events -->
<div class="eap-card">
    <div class="eap-card__header">
        <h2 class="eap-card__title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                <circle cx="12" cy="12" r="10"/>
                <polyline points="12 6 12 12 16 14"/>
            </svg>
            Recent Events
        </h2>
        <span class="eap-badge eap-badge--secondary"><?= count($ipInfo['events']) ?> events</span>
    </div>
    <div class="eap-card__body eap-card__body--no-padding">
        <?php if (empty($ipInfo['events'])): ?>
            <div class="eap-empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="48" height="48">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                    <polyline points="14 2 14 8 20 8"/>
                </svg>
                <p>No events recorded for this IP</p>
            </div>
        <?php else: ?>
            <table class="eap-table">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Type</th>
                        <th>Path</th>
                        <th class="eap-table__cell--center">Score</th>
                        <th class="eap-table__cell--center">Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($ipInfo['events'] as $event): ?>
                    <?php
                    $type = strtolower($event['type'] ?? '');
                    $badgeClass = match(true) {
                        str_contains($type, 'ban') => 'danger',
                        str_contains($type, 'sqli') || str_contains($type, 'sql') => 'danger',
                        str_contains($type, 'xss') => 'danger',
                        str_contains($type, 'honeypot') => 'warning',
                        str_contains($type, 'rate') => 'info',
                        str_contains($type, 'scanner') => 'warning',
                        default => 'secondary',
                    };
                    $score = (int) ($event['score'] ?? 0);
                    $scoreClass = $score >= 80 ? 'danger' : ($score >= 50 ? 'warning' : ($score >= 20 ? 'info' : 'success'));
                    $action = strtolower($event['action'] ?? 'allow');
                    $actionClass = match($action) {
                        'block', 'ban' => 'danger',
                        'allow' => 'success',
                        'challenge' => 'warning',
                        default => 'secondary',
                    };
                    ?>
                    <tr>
                        <td class="eap-table__cell--mono"><?= htmlspecialchars($event['time'] ?? '') ?></td>
                        <td>
                            <span class="eap-badge eap-badge--<?= $badgeClass ?>"><?= htmlspecialchars($event['type'] ?? 'unknown') ?></span>
                        </td>
                        <td class="eap-table__cell--truncate">
                            <code class="eap-code eap-code--sm"><?= htmlspecialchars(substr($event['path'] ?? '', 0, 50)) ?></code>
                        </td>
                        <td class="eap-table__cell--center">
                            <span class="eap-badge eap-badge--<?= $scoreClass ?>"><?= $score ?></span>
                        </td>
                        <td class="eap-table__cell--center">
                            <span class="eap-badge eap-badge--<?= $actionClass ?>"><?= htmlspecialchars(strtoupper($event['action'] ?? 'ALLOW')) ?></span>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</div>
