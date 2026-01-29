<?php
/**
 * Security Shield Events View - Matrix Theme.
 *
 * @var array $events Security events list
 * @var array $filters Current filters
 * @var int $total Total events count
 * @var int $page Current page
 * @var int $per_page Items per page
 * @var int $pages Total pages
 * @var string $csrf_input CSRF input field
 * @var string $admin_base_path Admin base path
 * @var string $page_title Page title
 */

// Calculate pagination
$pagination = [
    'current_page' => $page ?? 1,
    'total_pages' => $pages ?? 1,
    'total' => $total ?? 0,
    'from' => (($page ?? 1) - 1) * ($per_page ?? 100) + 1,
    'to' => min(($page ?? 1) * ($per_page ?? 100), $total ?? 0),
];
?>

<!-- Page Header -->
<div class="eap-page-header">
    <div class="eap-page-header__content">
        <h1 class="eap-page-title"><?= htmlspecialchars($page_title ?? 'Security Events') ?></h1>
        <p class="eap-page-subtitle">Browse and filter security events and threat detections</p>
    </div>
    <div class="eap-page-header__actions">
        <a href="<?= htmlspecialchars($admin_base_path . '/security/events/export?' . http_build_query($filters ?? [])) ?>" class="eap-btn eap-btn--secondary">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                <polyline points="7 10 12 15 17 10"/>
                <line x1="12" y1="15" x2="12" y2="3"/>
            </svg>
            Export CSV
        </a>
    </div>
</div>

<!-- Filters -->
<div class="eap-card">
    <div class="eap-card__header">
        <h2 class="eap-card__title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/>
            </svg>
            Filters
        </h2>
    </div>
    <div class="eap-card__body">
        <form method="GET" action="<?= htmlspecialchars($admin_base_path . '/security/events') ?>">
            <div class="eap-grid eap-grid--4">
                <div class="eap-form-group">
                    <label class="eap-form-label">Event Type</label>
                    <select name="type" class="eap-input">
                        <option value="">All Types</option>
                        <option value="SCANNER" <?= ($filters['type'] ?? '') === 'SCANNER' ? 'selected' : '' ?>>Scanner</option>
                        <option value="BOT_SPOOF" <?= ($filters['type'] ?? '') === 'BOT_SPOOF' ? 'selected' : '' ?>>Bot Spoofing</option>
                        <option value="CMS_PROBE" <?= ($filters['type'] ?? '') === 'CMS_PROBE' ? 'selected' : '' ?>>CMS Probe</option>
                        <option value="SQL_INJECTION" <?= ($filters['type'] ?? '') === 'SQL_INJECTION' ? 'selected' : '' ?>>SQL Injection</option>
                        <option value="XSS" <?= ($filters['type'] ?? '') === 'XSS' ? 'selected' : '' ?>>XSS</option>
                        <option value="PATH_TRAVERSAL" <?= ($filters['type'] ?? '') === 'PATH_TRAVERSAL' ? 'selected' : '' ?>>Path Traversal</option>
                        <option value="CONFIG_HUNT" <?= ($filters['type'] ?? '') === 'CONFIG_HUNT' ? 'selected' : '' ?>>Config Hunting</option>
                        <option value="RATE_LIMIT" <?= ($filters['type'] ?? '') === 'RATE_LIMIT' ? 'selected' : '' ?>>Rate Limit</option>
                    </select>
                </div>
                <div class="eap-form-group">
                    <label class="eap-form-label">Action</label>
                    <select name="action" class="eap-input">
                        <option value="">All Actions</option>
                        <option value="ALLOW" <?= ($filters['action'] ?? '') === 'ALLOW' ? 'selected' : '' ?>>Allow</option>
                        <option value="MONITOR" <?= ($filters['action'] ?? '') === 'MONITOR' ? 'selected' : '' ?>>Monitor</option>
                        <option value="CHALLENGE" <?= ($filters['action'] ?? '') === 'CHALLENGE' ? 'selected' : '' ?>>Challenge</option>
                        <option value="RATE_LIMIT" <?= ($filters['action'] ?? '') === 'RATE_LIMIT' ? 'selected' : '' ?>>Rate Limit</option>
                        <option value="BLOCK" <?= ($filters['action'] ?? '') === 'BLOCK' ? 'selected' : '' ?>>Block</option>
                        <option value="BAN" <?= ($filters['action'] ?? '') === 'BAN' ? 'selected' : '' ?>>Ban</option>
                    </select>
                </div>
                <div class="eap-form-group">
                    <label class="eap-form-label">IP Address</label>
                    <input type="text" name="ip" class="eap-input" placeholder="e.g., 192.168.1.1"
                           value="<?= htmlspecialchars($filters['ip'] ?? '') ?>">
                </div>
                <div class="eap-form-group">
                    <label class="eap-form-label">Date From</label>
                    <input type="date" name="date_from" class="eap-input"
                           value="<?= htmlspecialchars($filters['date_from'] ?? '') ?>">
                </div>
            </div>
            <div class="eap-form-actions">
                <button type="submit" class="eap-btn eap-btn--primary">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <circle cx="11" cy="11" r="8"/>
                        <line x1="21" y1="21" x2="16.65" y2="16.65"/>
                    </svg>
                    Filter
                </button>
                <a href="<?= htmlspecialchars($admin_base_path . '/security/events') ?>" class="eap-btn eap-btn--secondary">Reset</a>
            </div>
        </form>
    </div>
</div>

<!-- Events Table -->
<div class="eap-card">
    <div class="eap-card__header">
        <h2 class="eap-card__title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                <polyline points="14 2 14 8 20 8"/>
                <line x1="16" y1="13" x2="8" y2="13"/>
                <line x1="16" y1="17" x2="8" y2="17"/>
                <polyline points="10 9 9 9 8 9"/>
            </svg>
            Security Events
        </h2>
        <span class="eap-badge eap-badge--secondary"><?= number_format($pagination['total']) ?> total</span>
    </div>
    <div class="eap-card__body eap-card__body--no-padding">
        <?php if (empty($events)): ?>
            <div class="eap-empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="48" height="48">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                    <polyline points="14 2 14 8 20 8"/>
                </svg>
                <p>No events found matching your filters</p>
                <span class="eap-text--muted">Try adjusting your filter criteria</span>
            </div>
        <?php else: ?>
            <table class="eap-table">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>IP Address</th>
                        <th>Type</th>
                        <th>Path</th>
                        <th>User Agent</th>
                        <th class="eap-table__cell--center">Score</th>
                        <th class="eap-table__cell--center">Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($events as $event): ?>
                    <?php
                    $type = strtolower($event['type'] ?? '');
                        $badgeClass = match(true) {
                            str_contains($type, 'ban') => 'danger',
                            str_contains($type, 'sqli') || str_contains($type, 'sql') => 'danger',
                            str_contains($type, 'xss') => 'danger',
                            str_contains($type, 'honeypot') => 'warning',
                            str_contains($type, 'rate') => 'info',
                            str_contains($type, 'scanner') => 'warning',
                            str_contains($type, 'cms') => 'info',
                            str_contains($type, 'path') => 'purple',
                            str_contains($type, 'config') => 'secondary',
                            default => 'secondary',
                        };
                        $score = (int) ($event['score'] ?? 0);
                        $scoreClass = $score >= 80 ? 'danger' : ($score >= 50 ? 'warning' : ($score >= 20 ? 'info' : 'success'));
                        $action = strtolower($event['action'] ?? 'allow');
                        $actionClass = match($action) {
                            'block', 'ban' => 'danger',
                            'allow' => 'success',
                            'challenge' => 'warning',
                            'rate_limit' => 'info',
                            default => 'secondary',
                        };
                        ?>
                    <tr>
                        <td class="eap-table__cell--mono"><?= htmlspecialchars($event['time'] ?? '') ?></td>
                        <td>
                            <code class="eap-code"><?= htmlspecialchars($event['ip'] ?? '') ?></code>
                            <?php if (!empty($event['country'])): ?>
                                <span class="eap-badge eap-badge--secondary eap-badge--sm"><?= htmlspecialchars($event['country']) ?></span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <span class="eap-badge eap-badge--<?= $badgeClass ?>"><?= htmlspecialchars($event['type'] ?? 'unknown') ?></span>
                        </td>
                        <td class="eap-table__cell--truncate" title="<?= htmlspecialchars($event['path'] ?? '') ?>">
                            <code class="eap-code eap-code--sm"><?= htmlspecialchars(substr($event['path'] ?? '', 0, 40)) ?></code>
                        </td>
                        <td class="eap-table__cell--truncate eap-table__cell--muted" title="<?= htmlspecialchars($event['user_agent'] ?? '') ?>">
                            <?= htmlspecialchars(substr($event['user_agent'] ?? '', 0, 30)) ?>
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

    <!-- Pagination -->
    <?php if ($pagination['total_pages'] > 1): ?>
    <div class="eap-card__footer">
        <div class="eap-flex eap-flex--between eap-flex--center">
            <span class="eap-text--muted eap-text--sm">
                Showing <?= $pagination['from'] ?> - <?= $pagination['to'] ?> of <?= number_format($pagination['total']) ?> events
            </span>
            <div class="eap-pagination">
                <?php if ($pagination['current_page'] > 1): ?>
                    <a href="?<?= http_build_query(array_merge($filters ?? [], ['page' => $pagination['current_page'] - 1])) ?>" class="eap-btn eap-btn--sm eap-btn--secondary">Previous</a>
                <?php endif; ?>

                <?php for ($i = max(1, $pagination['current_page'] - 2); $i <= min($pagination['total_pages'], $pagination['current_page'] + 2); $i++): ?>
                    <a href="?<?= http_build_query(array_merge($filters ?? [], ['page' => $i])) ?>"
                       class="eap-btn eap-btn--sm <?= $i === $pagination['current_page'] ? 'eap-btn--primary' : 'eap-btn--secondary' ?>">
                        <?= $i ?>
                    </a>
                <?php endfor; ?>

                <?php if ($pagination['current_page'] < $pagination['total_pages']): ?>
                    <a href="?<?= http_build_query(array_merge($filters ?? [], ['page' => $pagination['current_page'] + 1])) ?>" class="eap-btn eap-btn--sm eap-btn--secondary">Next</a>
                <?php endif; ?>
            </div>
        </div>
    </div>
    <?php endif; ?>
</div>
