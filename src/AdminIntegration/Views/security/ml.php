<?php
/**
 * ML Threat Detection View - Matrix Theme.
 *
 * @var array $ml_stats
 * @var array $classifications
 * @var string $page_title
 * @var string $admin_base_path
 */
?>

<!-- Page Header -->
<div class="eap-page-header">
    <div class="eap-page-header__content">
        <h1 class="eap-page-title"><?= htmlspecialchars($page_title) ?></h1>
        <p class="eap-page-subtitle">Machine Learning powered threat classification and analysis</p>
    </div>
    <div class="eap-page-header__actions">
        <form method="POST" action="<?= htmlspecialchars($admin_base_path . '/security/ml/retrain') ?>" class="eap-inline-form">
            <button type="submit" class="eap-btn eap-btn--primary">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                    <path d="M23 4v6h-6M1 20v-6h6"/>
                    <path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/>
                </svg>
                Retrain Model
            </button>
        </form>
    </div>
</div>

<!-- ML Stats Grid -->
<div class="eap-stats-grid eap-stats-grid--4">
    <div class="eap-stat-card eap-stat-card--danger">
        <div class="eap-stat-card__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
            </svg>
        </div>
        <div class="eap-stat-card__content">
            <span class="eap-stat-card__value"><?= number_format($ml_stats['threats_detected_24h'] ?? 0) ?></span>
            <span class="eap-stat-card__label">Threats (24h)</span>
        </div>
    </div>

    <div class="eap-stat-card eap-stat-card--success">
        <div class="eap-stat-card__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
        </div>
        <div class="eap-stat-card__content">
            <span class="eap-stat-card__value"><?= number_format($ml_stats['threats_blocked_24h'] ?? 0) ?></span>
            <span class="eap-stat-card__label">Blocked (24h)</span>
        </div>
    </div>

    <div class="eap-stat-card eap-stat-card--info">
        <div class="eap-stat-card__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                <polyline points="22 4 12 14.01 9 11.01"/>
            </svg>
        </div>
        <div class="eap-stat-card__content">
            <span class="eap-stat-card__value"><?= number_format(($ml_stats['model_accuracy'] ?? 0.95) * 100, 1) ?>%</span>
            <span class="eap-stat-card__label">Accuracy</span>
        </div>
    </div>

    <div class="eap-stat-card eap-stat-card--purple">
        <div class="eap-stat-card__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
            </svg>
        </div>
        <div class="eap-stat-card__content">
            <span class="eap-stat-card__value"><?= number_format($ml_stats['total_ml_events_24h'] ?? 0) ?></span>
            <span class="eap-stat-card__label">ML Events (24h)</span>
        </div>
    </div>
</div>

<!-- Threat Categories -->
<div class="eap-card">
    <div class="eap-card__header">
        <h2 class="eap-card__title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                <path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/>
                <line x1="7" y1="7" x2="7.01" y2="7"/>
            </svg>
            Threat Classification Categories
        </h2>
    </div>
    <div class="eap-card__body">
        <div class="eap-grid eap-grid--3">
            <div class="eap-category-item">
                <span class="eap-badge eap-badge--danger">SCANNER</span>
                <span class="eap-category-item__desc">Automated Scanners (Censys, ZGrab, Nmap)</span>
            </div>
            <div class="eap-category-item">
                <span class="eap-badge eap-badge--warning">BOT_SPOOF</span>
                <span class="eap-category-item__desc">Bot Spoofing (Fake Googlebot, Bingbot)</span>
            </div>
            <div class="eap-category-item">
                <span class="eap-badge eap-badge--info">CMS_PROBE</span>
                <span class="eap-category-item__desc">CMS Probing (WordPress, Joomla attacks)</span>
            </div>
            <div class="eap-category-item">
                <span class="eap-badge eap-badge--secondary">CONFIG_HUNT</span>
                <span class="eap-category-item__desc">Config Hunting (.env, phpinfo, configs)</span>
            </div>
            <div class="eap-category-item">
                <span class="eap-badge eap-badge--purple">SQLI_ATTEMPT</span>
                <span class="eap-category-item__desc">SQL Injection (Database attacks)</span>
            </div>
            <div class="eap-category-item">
                <span class="eap-badge eap-badge--cyan">XSS_ATTEMPT</span>
                <span class="eap-category-item__desc">XSS Attack (Cross-site scripting)</span>
            </div>
        </div>
    </div>
</div>

<!-- Recent Classifications -->
<div class="eap-card">
    <div class="eap-card__header">
        <h2 class="eap-card__title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                <circle cx="12" cy="12" r="10"/>
                <polyline points="12 6 12 12 16 14"/>
            </svg>
            Recent ML Classifications
        </h2>
        <span class="eap-badge eap-badge--secondary"><?= count($classifications) ?> entries</span>
    </div>
    <div class="eap-card__body eap-card__body--no-padding">
        <?php if (empty($classifications)): ?>
            <div class="eap-empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="48" height="48">
                    <path d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/>
                </svg>
                <p>No ML events recorded yet</p>
                <span class="eap-text--muted">ML classifications will appear here when threats are detected</span>
            </div>
        <?php else: ?>
            <table class="eap-table">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>IP Address</th>
                        <th>Classification</th>
                        <th class="eap-table__cell--center">Confidence</th>
                        <th>Path</th>
                        <th class="eap-table__cell--center">Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($classifications as $event): ?>
                    <tr>
                        <td class="eap-table__cell--mono">
                            <?= date('Y-m-d H:i:s', strtotime($event['created_at'] ?? 'now')) ?>
                        </td>
                        <td>
                            <code class="eap-code"><?= htmlspecialchars($event['ip'] ?? 'unknown') ?></code>
                        </td>
                        <td>
                            <?php
                            $classification = $event['data']['classification'] ?? 'unknown';
                        $badgeClass = match($classification) {
                            'SCANNER' => 'danger',
                            'BOT_SPOOF' => 'warning',
                            'CMS_PROBE' => 'info',
                            'SQLI_ATTEMPT' => 'purple',
                            'XSS_ATTEMPT' => 'cyan',
                            'LEGITIMATE' => 'success',
                            default => 'secondary',
                        };
                        ?>
                            <span class="eap-badge eap-badge--<?= $badgeClass ?>"><?= htmlspecialchars($classification) ?></span>
                        </td>
                        <td class="eap-table__cell--center">
                            <?php
                        $confidence = $event['data']['confidence'] ?? 0;
                        $confPercent = round($confidence * 100, 1);
                        $confClass = $confidence >= 0.8 ? 'danger' : ($confidence >= 0.6 ? 'warning' : 'info');
                        ?>
                            <span class="eap-badge eap-badge--<?= $confClass ?>"><?= $confPercent ?>%</span>
                        </td>
                        <td class="eap-table__cell--truncate">
                            <code class="eap-code eap-code--sm"><?= htmlspecialchars(substr($event['data']['path'] ?? '', 0, 40)) ?></code>
                        </td>
                        <td class="eap-table__cell--center">
                            <?php if (str_contains($event['type'] ?? '', 'blocked')): ?>
                                <span class="eap-status eap-status--danger">Blocked</span>
                            <?php else: ?>
                                <span class="eap-status eap-status--info">Logged</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</div>

<!-- Model Info -->
<div class="eap-grid eap-grid--2">
    <div class="eap-card">
        <div class="eap-card__header">
            <h3 class="eap-card__title">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                    <circle cx="12" cy="12" r="3"/>
                    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>
                </svg>
                Algorithm Details
            </h3>
        </div>
        <div class="eap-card__body">
            <div class="eap-kv-list">
                <div class="eap-kv-list__item">
                    <span class="eap-kv-list__key">Algorithm</span>
                    <span class="eap-kv-list__value"><code class="eap-code">Naive Bayes + Online Learning</code></span>
                </div>
                <div class="eap-kv-list__item">
                    <span class="eap-kv-list__key">Training Data</span>
                    <span class="eap-kv-list__value">Production attack logs</span>
                </div>
                <div class="eap-kv-list__item">
                    <span class="eap-kv-list__key">Last Training</span>
                    <span class="eap-kv-list__value"><?= htmlspecialchars($ml_stats['last_training'] ?? 'N/A') ?></span>
                </div>
            </div>
        </div>
    </div>

    <div class="eap-card">
        <div class="eap-card__header">
            <h3 class="eap-card__title">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                    <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
                    <polyline points="3.27 6.96 12 12.01 20.73 6.96"/>
                    <line x1="12" y1="22.08" x2="12" y2="12"/>
                </svg>
                Feature Extraction
            </h3>
        </div>
        <div class="eap-card__body">
            <div class="eap-kv-list">
                <div class="eap-kv-list__item">
                    <span class="eap-kv-list__key">Features</span>
                    <span class="eap-kv-list__value">User-Agent, Path, Headers, Behavior</span>
                </div>
                <div class="eap-kv-list__item">
                    <span class="eap-kv-list__key">Bot Verification</span>
                    <span class="eap-kv-list__value">DNS reverse + forward validation</span>
                </div>
                <div class="eap-kv-list__item">
                    <span class="eap-kv-list__key">Feedback Loop</span>
                    <span class="eap-kv-list__value">
                        <span class="eap-badge eap-badge--success">Active</span>
                    </span>
                </div>
            </div>
        </div>
    </div>
</div>
