<?php
/**
 * Security Shield Events View.
 *
 * @var array $events Security events list
 * @var array $filters Current filters
 * @var int $total Total events count
 * @var int $page Current page
 * @var int $per_page Items per page
 * @var int $pages Total pages
 * @var array $event_types Available event types
 * @var string $csrf_token CSRF token
 */

// Helper functions for badge classes
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

// Normalize variable names
$csrfToken = $csrf_token ?? '';
$pagination = [
    'current_page' => $page ?? 1,
    'total_pages' => $pages ?? 1,
    'total' => $total ?? 0,
    'from' => (($page ?? 1) - 1) * ($per_page ?? 100) + 1,
    'to' => min(($page ?? 1) * ($per_page ?? 100), $total ?? 0),
];
?>
<div class="ess-events">
    <div class="ess-events__header">
        <h1 class="ess-events__title">Security Events</h1>
        <div class="ess-events__actions">
            <a href="/security/events/export?<?= http_build_query($filters ?? []) ?>" class="ess-btn ess-btn--secondary">
                <svg class="ess-btn__icon" viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" fill="none">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                </svg>
                Export CSV
            </a>
        </div>
    </div>

    <!-- Filters -->
    <div class="ess-filters">
        <form method="GET" action="/security/events" class="ess-filters__form">
            <div class="ess-filters__group">
                <label class="ess-filters__label" for="ess-filter-type">Type</label>
                <select name="type" id="ess-filter-type" class="ess-filters__select">
                    <option value="">All Types</option>
                    <option value="SCANNER" <?= ($filters['type'] ?? '') === 'SCANNER' ? 'selected' : '' ?>>Scanner</option>
                    <option value="BOT_SPOOF" <?= ($filters['type'] ?? '') === 'BOT_SPOOF' ? 'selected' : '' ?>>Bot Spoofing</option>
                    <option value="CMS_PROBE" <?= ($filters['type'] ?? '') === 'CMS_PROBE' ? 'selected' : '' ?>>CMS Probe</option>
                    <option value="SQL_INJECTION" <?= ($filters['type'] ?? '') === 'SQL_INJECTION' ? 'selected' : '' ?>>SQL Injection</option>
                    <option value="XSS" <?= ($filters['type'] ?? '') === 'XSS' ? 'selected' : '' ?>>XSS</option>
                    <option value="PATH_TRAVERSAL" <?= ($filters['type'] ?? '') === 'PATH_TRAVERSAL' ? 'selected' : '' ?>>Path Traversal</option>
                    <option value="CONFIG_HUNT" <?= ($filters['type'] ?? '') === 'CONFIG_HUNT' ? 'selected' : '' ?>>Config Hunting</option>
                    <option value="IOT_EXPLOIT" <?= ($filters['type'] ?? '') === 'IOT_EXPLOIT' ? 'selected' : '' ?>>IoT Exploit</option>
                    <option value="RATE_LIMIT" <?= ($filters['type'] ?? '') === 'RATE_LIMIT' ? 'selected' : '' ?>>Rate Limit</option>
                </select>
            </div>

            <div class="ess-filters__group">
                <label class="ess-filters__label" for="ess-filter-action">Action</label>
                <select name="action" id="ess-filter-action" class="ess-filters__select">
                    <option value="">All Actions</option>
                    <option value="ALLOW" <?= ($filters['action'] ?? '') === 'ALLOW' ? 'selected' : '' ?>>Allow</option>
                    <option value="MONITOR" <?= ($filters['action'] ?? '') === 'MONITOR' ? 'selected' : '' ?>>Monitor</option>
                    <option value="CHALLENGE" <?= ($filters['action'] ?? '') === 'CHALLENGE' ? 'selected' : '' ?>>Challenge</option>
                    <option value="RATE_LIMIT" <?= ($filters['action'] ?? '') === 'RATE_LIMIT' ? 'selected' : '' ?>>Rate Limit</option>
                    <option value="BLOCK" <?= ($filters['action'] ?? '') === 'BLOCK' ? 'selected' : '' ?>>Block</option>
                    <option value="BAN" <?= ($filters['action'] ?? '') === 'BAN' ? 'selected' : '' ?>>Ban</option>
                </select>
            </div>

            <div class="ess-filters__group">
                <label class="ess-filters__label" for="ess-filter-ip">IP Address</label>
                <input type="text" name="ip" id="ess-filter-ip" class="ess-filters__input"
                       value="<?= htmlspecialchars($filters['ip'] ?? '') ?>" placeholder="e.g., 192.168.1.1">
            </div>

            <div class="ess-filters__group">
                <label class="ess-filters__label" for="ess-filter-date-from">Date From</label>
                <input type="date" name="date_from" id="ess-filter-date-from" class="ess-filters__input"
                       value="<?= htmlspecialchars($filters['date_from'] ?? '') ?>">
            </div>

            <div class="ess-filters__group">
                <label class="ess-filters__label" for="ess-filter-date-to">Date To</label>
                <input type="date" name="date_to" id="ess-filter-date-to" class="ess-filters__input"
                       value="<?= htmlspecialchars($filters['date_to'] ?? '') ?>">
            </div>

            <div class="ess-filters__group ess-filters__group--actions">
                <button type="submit" class="ess-btn ess-btn--primary">Filter</button>
                <a href="/security/events" class="ess-btn ess-btn--secondary">Reset</a>
            </div>
        </form>
    </div>

    <!-- Events Table -->
    <div class="ess-table-card">
        <div class="ess-table-card__wrapper">
            <table class="ess-table">
                <thead class="ess-table__head">
                    <tr class="ess-table__row">
                        <th class="ess-table__th">Time</th>
                        <th class="ess-table__th">IP Address</th>
                        <th class="ess-table__th">Type</th>
                        <th class="ess-table__th">Path</th>
                        <th class="ess-table__th">User Agent</th>
                        <th class="ess-table__th">Score</th>
                        <th class="ess-table__th">Action</th>
                        <th class="ess-table__th">Details</th>
                    </tr>
                </thead>
                <tbody class="ess-table__body">
                    <?php foreach ($events ?? [] as $event): ?>
                    <tr class="ess-table__row">
                        <td class="ess-table__td ess-table__td--muted">
                            <span class="ess-datetime" data-timestamp="<?= htmlspecialchars($event['timestamp'] ?? '') ?>">
                                <?= htmlspecialchars($event['time'] ?? '') ?>
                            </span>
                        </td>
                        <td class="ess-table__td">
                            <code class="ess-code"><?= htmlspecialchars($event['ip'] ?? '') ?></code>
                            <?php if (!empty($event['country'])): ?>
                            <span class="ess-badge ess-badge--secondary"><?= htmlspecialchars($event['country']) ?></span>
                            <?php endif; ?>
                        </td>
                        <td class="ess-table__td">
                            <span class="ess-badge ess-badge--<?= htmlspecialchars(essThreatBadgeClass($event['type'] ?? '')) ?>">
                                <?= htmlspecialchars($event['type'] ?? 'unknown') ?>
                            </span>
                        </td>
                        <td class="ess-table__td">
                            <code class="ess-code ess-code--path" title="<?= htmlspecialchars($event['path'] ?? '') ?>">
                                <?= htmlspecialchars(substr($event['path'] ?? '', 0, 50)) ?>
                            </code>
                        </td>
                        <td class="ess-table__td">
                            <span class="ess-truncate" title="<?= htmlspecialchars($event['user_agent'] ?? '') ?>">
                                <?= htmlspecialchars(substr($event['user_agent'] ?? '', 0, 40)) ?>
                            </span>
                        </td>
                        <td class="ess-table__td">
                            <div class="ess-score-bar">
                                <div class="ess-score-bar__fill ess-score-bar__fill--<?= essScoreClass((int) ($event['score'] ?? 0)) ?>"
                                     data-score="<?= min(100, $event['score'] ?? 0) ?>"></div>
                                <span class="ess-score-bar__value"><?= $event['score'] ?? 0 ?></span>
                            </div>
                        </td>
                        <td class="ess-table__td">
                            <span class="ess-action-badge ess-action-badge--<?= strtolower($event['action'] ?? 'allow') ?>">
                                <?= htmlspecialchars($event['action'] ?? 'ALLOW') ?>
                            </span>
                        </td>
                        <td class="ess-table__td">
                            <button type="button" class="ess-btn ess-btn--sm ess-btn--secondary"
                                    data-ess-modal="event-<?= htmlspecialchars($event['id'] ?? '') ?>">
                                View
                            </button>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                    <?php if (empty($events)): ?>
                    <tr class="ess-table__row">
                        <td class="ess-table__td ess-table__td--empty" colspan="8">No events found matching your filters</td>
                    </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- Pagination -->
    <?php if (!empty($pagination) && $pagination['total_pages'] > 1): ?>
    <div class="ess-pagination">
        <div class="ess-pagination__info">
            Showing <?= $pagination['from'] ?? 1 ?> - <?= $pagination['to'] ?? 0 ?> of <?= $pagination['total'] ?? 0 ?> events
        </div>
        <div class="ess-pagination__nav">
            <?php if ($pagination['current_page'] > 1): ?>
            <a href="?<?= http_build_query(array_merge($filters ?? [], ['page' => $pagination['current_page'] - 1])) ?>"
               class="ess-pagination__btn">
                Previous
            </a>
            <?php endif; ?>

            <?php for ($i = max(1, $pagination['current_page'] - 2); $i <= min($pagination['total_pages'], $pagination['current_page'] + 2); $i++): ?>
            <a href="?<?= http_build_query(array_merge($filters ?? [], ['page' => $i])) ?>"
               class="ess-pagination__btn <?= $i === $pagination['current_page'] ? 'ess-pagination__btn--active' : '' ?>">
                <?= $i ?>
            </a>
            <?php endfor; ?>

            <?php if ($pagination['current_page'] < $pagination['total_pages']): ?>
            <a href="?<?= http_build_query(array_merge($filters ?? [], ['page' => $pagination['current_page'] + 1])) ?>"
               class="ess-pagination__btn">
                Next
            </a>
            <?php endif; ?>
        </div>
    </div>
    <?php endif; ?>
</div>

<!-- Event Detail Modals -->
<?php foreach ($events ?? [] as $event): ?>
<div class="ess-modal" id="ess-modal-event-<?= htmlspecialchars($event['id'] ?? '') ?>" data-ess-modal-target>
    <div class="ess-modal__backdrop" data-ess-modal-close></div>
    <div class="ess-modal__content">
        <div class="ess-modal__header">
            <h3 class="ess-modal__title">Event Details</h3>
            <button type="button" class="ess-modal__close" data-ess-modal-close>&times;</button>
        </div>
        <div class="ess-modal__body">
            <div class="ess-detail-grid">
                <div class="ess-detail-grid__item">
                    <span class="ess-detail-grid__label">Event ID</span>
                    <span class="ess-detail-grid__value"><?= htmlspecialchars($event['id'] ?? '') ?></span>
                </div>
                <div class="ess-detail-grid__item">
                    <span class="ess-detail-grid__label">Timestamp</span>
                    <span class="ess-detail-grid__value"><?= htmlspecialchars($event['timestamp'] ?? '') ?></span>
                </div>
                <div class="ess-detail-grid__item">
                    <span class="ess-detail-grid__label">IP Address</span>
                    <span class="ess-detail-grid__value"><code class="ess-code"><?= htmlspecialchars($event['ip'] ?? '') ?></code></span>
                </div>
                <div class="ess-detail-grid__item">
                    <span class="ess-detail-grid__label">Country</span>
                    <span class="ess-detail-grid__value"><?= htmlspecialchars($event['country'] ?? 'Unknown') ?></span>
                </div>
                <div class="ess-detail-grid__item">
                    <span class="ess-detail-grid__label">Type</span>
                    <span class="ess-detail-grid__value">
                        <span class="ess-badge ess-badge--<?= htmlspecialchars(essThreatBadgeClass($event['type'] ?? '')) ?>">
                            <?= htmlspecialchars($event['type'] ?? 'unknown') ?>
                        </span>
                    </span>
                </div>
                <div class="ess-detail-grid__item">
                    <span class="ess-detail-grid__label">Score</span>
                    <span class="ess-detail-grid__value"><?= $event['score'] ?? 0 ?>/100</span>
                </div>
                <div class="ess-detail-grid__item ess-detail-grid__item--full">
                    <span class="ess-detail-grid__label">Request Path</span>
                    <code class="ess-code ess-code--block"><?= htmlspecialchars($event['path'] ?? '') ?></code>
                </div>
                <div class="ess-detail-grid__item ess-detail-grid__item--full">
                    <span class="ess-detail-grid__label">User Agent</span>
                    <code class="ess-code ess-code--block"><?= htmlspecialchars($event['user_agent'] ?? '') ?></code>
                </div>
                <?php if (!empty($event['features'])): ?>
                <div class="ess-detail-grid__item ess-detail-grid__item--full">
                    <span class="ess-detail-grid__label">Detected Features</span>
                    <div class="ess-tag-list">
                        <?php foreach ($event['features'] as $feature): ?>
                        <span class="ess-tag"><?= htmlspecialchars($feature) ?></span>
                        <?php endforeach; ?>
                    </div>
                </div>
                <?php endif; ?>
                <?php if (!empty($event['reasoning'])): ?>
                <div class="ess-detail-grid__item ess-detail-grid__item--full">
                    <span class="ess-detail-grid__label">ML Reasoning</span>
                    <p class="ess-detail-grid__text"><?= htmlspecialchars($event['reasoning']) ?></p>
                </div>
                <?php endif; ?>
            </div>
        </div>
        <div class="ess-modal__footer">
            <?php if (!($event['is_banned'] ?? false)): ?>
            <form method="POST" action="/security/ips/ban" class="ess-form--inline">
                <input type="hidden" name="ip" value="<?= htmlspecialchars($event['ip'] ?? '') ?>">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken ?? '') ?>">
                <button type="submit" class="ess-btn ess-btn--danger">Ban IP</button>
            </form>
            <?php endif; ?>
            <button type="button" class="ess-btn ess-btn--secondary" data-ess-modal-close>Close</button>
        </div>
    </div>
</div>
<?php endforeach; ?>
