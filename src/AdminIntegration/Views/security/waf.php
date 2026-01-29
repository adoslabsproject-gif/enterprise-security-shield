<?php
/**
 * WAF Rules View - Matrix Theme.
 *
 * @var array $rules
 * @var array $detection_stats
 * @var string $page_title
 * @var string $admin_base_path
 */
?>

<!-- Page Header -->
<div class="eap-page-header">
    <div class="eap-page-header__content">
        <h1 class="eap-page-title"><?= htmlspecialchars($page_title) ?></h1>
        <p class="eap-page-subtitle">Web Application Firewall rules and detection statistics</p>
    </div>
    <div class="eap-page-header__actions">
        <span class="eap-badge eap-badge--success">
            <span class="eap-badge__dot"></span>
            WAF Active
        </span>
    </div>
</div>

<!-- Detection Stats Grid -->
<div class="eap-stats-grid eap-stats-grid--6">
    <div class="eap-stat-card eap-stat-card--danger">
        <div class="eap-stat-card__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
            </svg>
        </div>
        <div class="eap-stat-card__content">
            <span class="eap-stat-card__value"><?= number_format($detection_stats['sqli_24h'] ?? 0) ?></span>
            <span class="eap-stat-card__label">SQLi Blocked (24h)</span>
        </div>
    </div>

    <div class="eap-stat-card eap-stat-card--warning">
        <div class="eap-stat-card__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>
            </svg>
        </div>
        <div class="eap-stat-card__content">
            <span class="eap-stat-card__value"><?= number_format($detection_stats['xss_24h'] ?? 0) ?></span>
            <span class="eap-stat-card__label">XSS Blocked (24h)</span>
        </div>
    </div>

    <div class="eap-stat-card eap-stat-card--info">
        <div class="eap-stat-card__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
                <line x1="8" y1="21" x2="16" y2="21"/>
                <line x1="12" y1="17" x2="12" y2="21"/>
            </svg>
        </div>
        <div class="eap-stat-card__content">
            <span class="eap-stat-card__value"><?= number_format($detection_stats['command_24h'] ?? 0) ?></span>
            <span class="eap-stat-card__label">Cmd Injection (24h)</span>
        </div>
    </div>

    <div class="eap-stat-card eap-stat-card--secondary">
        <div class="eap-stat-card__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                <polyline points="14 2 14 8 20 8"/>
            </svg>
        </div>
        <div class="eap-stat-card__content">
            <span class="eap-stat-card__value"><?= number_format($detection_stats['lfi_24h'] ?? 0) ?></span>
            <span class="eap-stat-card__label">Path Traversal (24h)</span>
        </div>
    </div>

    <div class="eap-stat-card eap-stat-card--purple">
        <div class="eap-stat-card__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"/>
                <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/>
                <line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
        </div>
        <div class="eap-stat-card__content">
            <span class="eap-stat-card__value"><?= number_format($detection_stats['scanner_24h'] ?? 0) ?></span>
            <span class="eap-stat-card__label">Scanner Blocked (24h)</span>
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
            <span class="eap-stat-card__value"><?= number_format($detection_stats['total_blocked_24h'] ?? 0) ?></span>
            <span class="eap-stat-card__label">Total Blocked (24h)</span>
        </div>
    </div>
</div>

<!-- WAF Rules Table -->
<div class="eap-card">
    <div class="eap-card__header">
        <h2 class="eap-card__title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            WAF Detection Rules
        </h2>
        <span class="eap-badge eap-badge--secondary"><?= count($rules) ?> rules</span>
    </div>
    <div class="eap-card__body eap-card__body--no-padding">
        <table class="eap-table">
            <thead>
                <tr>
                    <th>Rule</th>
                    <th>Category</th>
                    <th>Description</th>
                    <th class="eap-table__cell--right">Detections</th>
                    <th class="eap-table__cell--center">Status</th>
                    <th class="eap-table__cell--center">Action</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($rules as $rule): ?>
                <tr>
                    <td>
                        <code class="eap-code"><?= htmlspecialchars($rule['id']) ?></code>
                    </td>
                    <td>
                        <?php
                        $categoryColors = [
                            'sqli' => 'danger',
                            'xss' => 'warning',
                            'command' => 'info',
                            'lfi' => 'secondary',
                            'scanner' => 'purple',
                        ];
                    $category = $rule['category'] ?? 'default';
                    $color = $categoryColors[$category] ?? 'secondary';
                    ?>
                        <span class="eap-badge eap-badge--<?= $color ?>"><?= htmlspecialchars(strtoupper($category)) ?></span>
                    </td>
                    <td class="eap-table__cell--muted">
                        <?= htmlspecialchars($rule['description']) ?>
                    </td>
                    <td class="eap-table__cell--right">
                        <span class="eap-badge eap-badge--<?= ($rule['detections'] ?? 0) > 0 ? 'danger' : 'secondary' ?>">
                            <?= number_format($rule['detections'] ?? 0) ?>
                        </span>
                    </td>
                    <td class="eap-table__cell--center">
                        <?php if ($rule['enabled'] ?? true): ?>
                            <span class="eap-status eap-status--success">Active</span>
                        <?php else: ?>
                            <span class="eap-status eap-status--muted">Disabled</span>
                        <?php endif; ?>
                    </td>
                    <td class="eap-table__cell--center">
                        <form method="POST" action="<?= htmlspecialchars($admin_base_path . '/security/waf/toggle') ?>" class="eap-inline-form">
                            <?= $csrf_input ?? '' ?>
                            <input type="hidden" name="rule_id" value="<?= htmlspecialchars($rule['id']) ?>">
                            <input type="hidden" name="enabled" value="<?= ($rule['enabled'] ?? true) ? 'false' : 'true' ?>">
                            <button type="submit" class="eap-btn eap-btn--sm eap-btn--<?= ($rule['enabled'] ?? true) ? 'warning' : 'success' ?>">
                                <?= ($rule['enabled'] ?? true) ? 'Disable' : 'Enable' ?>
                            </button>
                        </form>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<!-- Detection Methods Info -->
<div class="eap-grid eap-grid--2">
    <div class="eap-card">
        <div class="eap-card__header">
            <h3 class="eap-card__title">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                    <polyline points="16 18 22 12 16 6"/>
                    <polyline points="8 6 2 12 8 18"/>
                </svg>
                AST-Based Detection
            </h3>
        </div>
        <div class="eap-card__body">
            <p class="eap-text--muted">The WAF uses Abstract Syntax Tree (AST) parsing for accurate SQL injection detection:</p>
            <ul class="eap-list">
                <li>SQL Tokenization with lexical analysis</li>
                <li>Syntactic structure validation</li>
                <li>Comment injection detection</li>
                <li>String escape analysis</li>
                <li>UNION/OR injection patterns</li>
            </ul>
        </div>
    </div>

    <div class="eap-card">
        <div class="eap-card__header">
            <h3 class="eap-card__title">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                    <path d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/>
                </svg>
                ML Enhancement
            </h3>
        </div>
        <div class="eap-card__body">
            <p class="eap-text--muted">Machine Learning augments rule-based detection:</p>
            <ul class="eap-list">
                <li>Naive Bayes threat classification</li>
                <li>Online learning from new attacks</li>
                <li>Behavioral pattern analysis</li>
                <li>Bot verification (DNS + behavior)</li>
                <li>Anomaly detection</li>
            </ul>
        </div>
    </div>
</div>
