<?php
/**
 * Security Shield IP Management View - Matrix Theme.
 *
 * @var array $bannedIps List of banned IPs
 * @var array $whitelistedIps List of whitelisted IPs
 * @var array $ipStats IP statistics
 * @var string $csrf_input CSRF input field
 * @var string $admin_base_path Admin base path
 * @var string $page_title Page title
 */
$bannedIps ??= [];
$whitelistedIps ??= [];
$ipStats ??= [];
?>

<!-- Page Header -->
<div class="eap-page-header">
    <div class="eap-page-header__content">
        <h1 class="eap-page-title"><?= htmlspecialchars($page_title ?? 'IP Management') ?></h1>
        <p class="eap-page-subtitle">Manage banned and whitelisted IP addresses</p>
    </div>
</div>

<!-- Stats Grid -->
<div class="eap-stats-grid eap-stats-grid--4">
    <div class="eap-stat-card eap-stat-card--danger">
        <div class="eap-stat-card__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"/>
                <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
            </svg>
        </div>
        <div class="eap-stat-card__content">
            <span class="eap-stat-card__value"><?= number_format($ipStats['total_banned'] ?? count($bannedIps)) ?></span>
            <span class="eap-stat-card__label">Banned IPs</span>
        </div>
    </div>

    <div class="eap-stat-card eap-stat-card--success">
        <div class="eap-stat-card__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                <polyline points="22 4 12 14.01 9 11.01"/>
            </svg>
        </div>
        <div class="eap-stat-card__content">
            <span class="eap-stat-card__value"><?= number_format($ipStats['total_whitelisted'] ?? count($whitelistedIps)) ?></span>
            <span class="eap-stat-card__label">Whitelisted IPs</span>
        </div>
    </div>

    <div class="eap-stat-card eap-stat-card--warning">
        <div class="eap-stat-card__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"/>
                <polyline points="12 6 12 12 16 14"/>
            </svg>
        </div>
        <div class="eap-stat-card__content">
            <span class="eap-stat-card__value"><?= number_format($ipStats['banned_today'] ?? 0) ?></span>
            <span class="eap-stat-card__label">Banned Today</span>
        </div>
    </div>

    <div class="eap-stat-card eap-stat-card--info">
        <div class="eap-stat-card__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/>
            </svg>
        </div>
        <div class="eap-stat-card__content">
            <span class="eap-stat-card__value"><?= number_format($ipStats['auto_banned'] ?? 0) ?></span>
            <span class="eap-stat-card__label">Auto-Banned</span>
        </div>
    </div>
</div>

<!-- Quick Actions -->
<div class="eap-grid eap-grid--3">
    <!-- Quick Ban -->
    <div class="eap-card">
        <div class="eap-card__header">
            <h3 class="eap-card__title">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
                </svg>
                Quick Ban
            </h3>
        </div>
        <div class="eap-card__body">
            <form method="POST" action="<?= htmlspecialchars($admin_base_path . '/security/ips/ban') ?>">
                <?= $csrf_input ?? '' ?>
                <div class="eap-form-group">
                    <label class="eap-form-label">IP Address</label>
                    <input type="text" name="ip" class="eap-input" placeholder="e.g., 192.168.1.1"
                           pattern="^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$" required>
                </div>
                <div class="eap-form-group">
                    <label class="eap-form-label">Reason (optional)</label>
                    <input type="text" name="reason" class="eap-input" placeholder="Ban reason">
                </div>
                <button type="submit" class="eap-btn eap-btn--danger">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <circle cx="12" cy="12" r="10"/>
                        <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
                    </svg>
                    Ban IP
                </button>
            </form>
        </div>
    </div>

    <!-- Quick Whitelist -->
    <div class="eap-card">
        <div class="eap-card__header">
            <h3 class="eap-card__title">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                    <polyline points="22 4 12 14.01 9 11.01"/>
                </svg>
                Quick Whitelist
            </h3>
        </div>
        <div class="eap-card__body">
            <form method="POST" action="<?= htmlspecialchars($admin_base_path . '/security/ips/whitelist') ?>">
                <?= $csrf_input ?? '' ?>
                <div class="eap-form-group">
                    <label class="eap-form-label">IP Address</label>
                    <input type="text" name="ip" class="eap-input" placeholder="e.g., 192.168.1.1"
                           pattern="^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$" required>
                </div>
                <div class="eap-form-group">
                    <label class="eap-form-label">Label (optional)</label>
                    <input type="text" name="label" class="eap-input" placeholder="e.g., Office IP">
                </div>
                <button type="submit" class="eap-btn eap-btn--success">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                        <polyline points="22 4 12 14.01 9 11.01"/>
                    </svg>
                    Whitelist IP
                </button>
            </form>
        </div>
    </div>

    <!-- IP Lookup -->
    <div class="eap-card">
        <div class="eap-card__header">
            <h3 class="eap-card__title">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                    <circle cx="11" cy="11" r="8"/>
                    <line x1="21" y1="21" x2="16.65" y2="16.65"/>
                </svg>
                IP Lookup
            </h3>
        </div>
        <div class="eap-card__body">
            <form method="GET" action="<?= htmlspecialchars($admin_base_path . '/security/ips/lookup') ?>">
                <div class="eap-form-group">
                    <label class="eap-form-label">IP Address</label>
                    <input type="text" name="ip" class="eap-input" placeholder="IP to lookup"
                           pattern="^(\d{1,3}\.){3}\d{1,3}$" required>
                </div>
                <div class="eap-form-group">
                    <span class="eap-form-hint">Check IP status and history</span>
                </div>
                <button type="submit" class="eap-btn eap-btn--primary">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <circle cx="11" cy="11" r="8"/>
                        <line x1="21" y1="21" x2="16.65" y2="16.65"/>
                    </svg>
                    Lookup
                </button>
            </form>
        </div>
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
            Banned IP Addresses
        </h2>
        <div class="eap-flex eap-flex--gap-2">
            <span class="eap-badge eap-badge--danger"><?= count($bannedIps) ?> IPs</span>
            <form method="POST" action="<?= htmlspecialchars($admin_base_path . '/security/ips/clear-expired') ?>" class="eap-inline-form">
                <?= $csrf_input ?? '' ?>
                <button type="submit" class="eap-btn eap-btn--sm eap-btn--secondary">Clear Expired</button>
            </form>
        </div>
    </div>
    <div class="eap-card__body eap-card__body--no-padding">
        <?php if (empty($bannedIps)): ?>
            <div class="eap-empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="48" height="48">
                    <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
                <p>No banned IPs</p>
                <span class="eap-text--muted">All clear!</span>
            </div>
        <?php else: ?>
            <table class="eap-table">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Country</th>
                        <th>Reason</th>
                        <th>Banned At</th>
                        <th>Expires</th>
                        <th>Source</th>
                        <th class="eap-table__cell--center">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($bannedIps as $banned): ?>
                    <tr>
                        <td>
                            <a href="<?= htmlspecialchars($admin_base_path . '/security/ips/lookup?ip=' . urlencode($banned['ip'] ?? '')) ?>" class="eap-link">
                                <code class="eap-code"><?= htmlspecialchars($banned['ip'] ?? '') ?></code>
                            </a>
                        </td>
                        <td><?= htmlspecialchars($banned['country'] ?? 'Unknown') ?></td>
                        <td class="eap-table__cell--muted eap-table__cell--truncate" title="<?= htmlspecialchars($banned['reason'] ?? '') ?>">
                            <?= htmlspecialchars(substr($banned['reason'] ?? 'No reason', 0, 30)) ?>
                        </td>
                        <td class="eap-table__cell--mono"><?= htmlspecialchars($banned['banned_at'] ?? '') ?></td>
                        <td>
                            <?php if (empty($banned['expires_at'])): ?>
                                <span class="eap-badge eap-badge--danger">Permanent</span>
                            <?php else: ?>
                                <span class="eap-table__cell--mono"><?= htmlspecialchars($banned['expires_at']) ?></span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <span class="eap-badge eap-badge--<?= ($banned['source'] ?? '') === 'auto' ? 'warning' : 'secondary' ?>">
                                <?= htmlspecialchars(ucfirst($banned['source'] ?? 'manual')) ?>
                            </span>
                        </td>
                        <td class="eap-table__cell--center">
                            <form method="POST" action="<?= htmlspecialchars($admin_base_path . '/security/ips/unban') ?>" class="eap-inline-form">
                                <?= $csrf_input ?? '' ?>
                                <input type="hidden" name="ip" value="<?= htmlspecialchars($banned['ip'] ?? '') ?>">
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

<!-- Whitelisted IPs -->
<div class="eap-card">
    <div class="eap-card__header">
        <h2 class="eap-card__title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                <polyline points="22 4 12 14.01 9 11.01"/>
            </svg>
            Whitelisted IP Addresses
        </h2>
        <span class="eap-badge eap-badge--success"><?= count($whitelistedIps) ?> IPs</span>
    </div>
    <div class="eap-card__body eap-card__body--no-padding">
        <?php if (empty($whitelistedIps)): ?>
            <div class="eap-empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="48" height="48">
                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                    <polyline points="22 4 12 14.01 9 11.01"/>
                </svg>
                <p>No whitelisted IPs</p>
                <span class="eap-text--muted">Add trusted IPs to bypass security checks</span>
            </div>
        <?php else: ?>
            <table class="eap-table">
                <thead>
                    <tr>
                        <th>IP Address / Range</th>
                        <th>Label</th>
                        <th>Added At</th>
                        <th>Added By</th>
                        <th class="eap-table__cell--center">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($whitelistedIps as $whitelisted): ?>
                    <tr>
                        <td>
                            <a href="<?= htmlspecialchars($admin_base_path . '/security/ips/lookup?ip=' . urlencode($whitelisted['ip'] ?? '')) ?>" class="eap-link">
                                <code class="eap-code"><?= htmlspecialchars($whitelisted['ip'] ?? '') ?></code>
                            </a>
                        </td>
                        <td><?= htmlspecialchars($whitelisted['label'] ?? '-') ?></td>
                        <td class="eap-table__cell--mono"><?= htmlspecialchars($whitelisted['added_at'] ?? '') ?></td>
                        <td><?= htmlspecialchars($whitelisted['added_by'] ?? 'System') ?></td>
                        <td class="eap-table__cell--center">
                            <form method="POST" action="<?= htmlspecialchars($admin_base_path . '/security/ips/remove-whitelist') ?>" class="eap-inline-form">
                                <?= $csrf_input ?? '' ?>
                                <input type="hidden" name="ip" value="<?= htmlspecialchars($whitelisted['ip'] ?? '') ?>">
                                <button type="submit" class="eap-btn eap-btn--sm eap-btn--danger">Remove</button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</div>
