<?php
/**
 * Security Shield Configuration View - Matrix Theme.
 *
 * @var array $config Current configuration
 * @var array $presets Available presets
 * @var string $csrf_input CSRF input field
 * @var string $admin_base_path Admin base path
 * @var string $page_title Page title
 */
$config ??= [];
?>

<!-- Page Header -->
<div class="eap-page-header">
    <div class="eap-page-header__content">
        <h1 class="eap-page-title"><?= htmlspecialchars($page_title ?? 'Security Configuration') ?></h1>
        <p class="eap-page-subtitle">Configure WAF settings, rate limits, and threat detection</p>
    </div>
</div>

<!-- Quick Presets -->
<div class="eap-card">
    <div class="eap-card__header">
        <h2 class="eap-card__title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                <rect x="3" y="3" width="7" height="7"/>
                <rect x="14" y="3" width="7" height="7"/>
                <rect x="14" y="14" width="7" height="7"/>
                <rect x="3" y="14" width="7" height="7"/>
            </svg>
            Quick Presets
        </h2>
    </div>
    <div class="eap-card__body">
        <div class="eap-grid eap-grid--3">
            <!-- Low Security -->
            <div class="eap-category-item <?= ($config['preset'] ?? '') === 'low' ? 'eap-category-item--active' : '' ?>">
                <div class="eap-flex eap-flex--between eap-flex--center">
                    <span class="eap-badge eap-badge--success">Low Security</span>
                    <?php if (($config['preset'] ?? '') === 'low'): ?>
                        <span class="eap-badge eap-badge--info eap-badge--sm">Active</span>
                    <?php endif; ?>
                </div>
                <p class="eap-category-item__desc">Basic protection. Allows most traffic, monitors suspicious activity. Best for development.</p>
                <ul class="eap-list">
                    <li>Rate limit: 200 req/min</li>
                    <li>Auto-ban: Disabled</li>
                    <li>ML threshold: 80</li>
                </ul>
                <form method="POST" action="<?= htmlspecialchars($admin_base_path . '/security/config/preset') ?>" class="eap-mt-4">
                    <?= $csrf_input ?? '' ?>
                    <input type="hidden" name="preset" value="low">
                    <button type="submit" class="eap-btn eap-btn--sm eap-btn--secondary">Apply</button>
                </form>
            </div>

            <!-- Medium Security -->
            <div class="eap-category-item <?= ($config['preset'] ?? '') === 'medium' ? 'eap-category-item--active' : '' ?>">
                <div class="eap-flex eap-flex--between eap-flex--center">
                    <span class="eap-badge eap-badge--warning">Medium Security</span>
                    <?php if (($config['preset'] ?? '') === 'medium'): ?>
                        <span class="eap-badge eap-badge--info eap-badge--sm">Active</span>
                    <?php endif; ?>
                </div>
                <p class="eap-category-item__desc">Balanced protection. Blocks known threats, challenges suspicious traffic. Recommended.</p>
                <ul class="eap-list">
                    <li>Rate limit: 100 req/min</li>
                    <li>Auto-ban: 24 hours</li>
                    <li>ML threshold: 60</li>
                </ul>
                <form method="POST" action="<?= htmlspecialchars($admin_base_path . '/security/config/preset') ?>" class="eap-mt-4">
                    <?= $csrf_input ?? '' ?>
                    <input type="hidden" name="preset" value="medium">
                    <button type="submit" class="eap-btn eap-btn--sm eap-btn--primary">Apply</button>
                </form>
            </div>

            <!-- High Security -->
            <div class="eap-category-item <?= ($config['preset'] ?? '') === 'high' ? 'eap-category-item--active' : '' ?>">
                <div class="eap-flex eap-flex--between eap-flex--center">
                    <span class="eap-badge eap-badge--danger">High Security</span>
                    <?php if (($config['preset'] ?? '') === 'high'): ?>
                        <span class="eap-badge eap-badge--info eap-badge--sm">Active</span>
                    <?php endif; ?>
                </div>
                <p class="eap-category-item__desc">Maximum protection. Aggressive blocking, strict rate limits. For high-value targets.</p>
                <ul class="eap-list">
                    <li>Rate limit: 30 req/min</li>
                    <li>Auto-ban: Permanent</li>
                    <li>ML threshold: 40</li>
                </ul>
                <form method="POST" action="<?= htmlspecialchars($admin_base_path . '/security/config/preset') ?>" class="eap-mt-4">
                    <?= $csrf_input ?? '' ?>
                    <input type="hidden" name="preset" value="high">
                    <button type="submit" class="eap-btn eap-btn--sm eap-btn--danger">Apply</button>
                </form>
            </div>
        </div>
    </div>
</div>

<!-- Configuration Form -->
<form method="POST" action="<?= htmlspecialchars($admin_base_path . '/security/config') ?>" class="eap-form">
    <?= $csrf_input ?? '' ?>

    <!-- General Settings -->
    <div class="eap-card">
        <div class="eap-card__header">
            <h2 class="eap-card__title">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                    <circle cx="12" cy="12" r="3"/>
                    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>
                </svg>
                General Settings
            </h2>
        </div>
        <div class="eap-card__body">
            <div class="eap-grid eap-grid--2">
                <div class="eap-form-group">
                    <label class="eap-form-label">WAF Status</label>
                    <select name="enabled" class="eap-input">
                        <option value="1" <?= ($config['enabled'] ?? true) ? 'selected' : '' ?>>Enabled</option>
                        <option value="0" <?= !($config['enabled'] ?? true) ? 'selected' : '' ?>>Disabled</option>
                    </select>
                    <span class="eap-form-hint">Enable or disable the Web Application Firewall</span>
                </div>
                <div class="eap-form-group">
                    <label class="eap-form-label">Operating Mode</label>
                    <select name="mode" class="eap-input">
                        <option value="monitor" <?= ($config['mode'] ?? '') === 'monitor' ? 'selected' : '' ?>>Monitor Only</option>
                        <option value="protect" <?= ($config['mode'] ?? 'protect') === 'protect' ? 'selected' : '' ?>>Protect</option>
                        <option value="paranoid" <?= ($config['mode'] ?? '') === 'paranoid' ? 'selected' : '' ?>>Paranoid</option>
                    </select>
                    <span class="eap-form-hint">Monitor logs threats, Protect blocks them</span>
                </div>
            </div>
        </div>
    </div>

    <!-- Rate Limiting -->
    <div class="eap-card">
        <div class="eap-card__header">
            <h2 class="eap-card__title">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                    <circle cx="12" cy="12" r="10"/>
                    <polyline points="12 6 12 12 16 14"/>
                </svg>
                Rate Limiting
            </h2>
        </div>
        <div class="eap-card__body">
            <div class="eap-grid eap-grid--3">
                <div class="eap-form-group">
                    <label class="eap-form-label">Requests per Minute</label>
                    <input type="number" name="rate_limit" class="eap-input"
                           value="<?= (int) ($config['rate_limit'] ?? 100) ?>" min="10" max="1000">
                    <span class="eap-form-hint">Max requests per IP per minute</span>
                </div>
                <div class="eap-form-group">
                    <label class="eap-form-label">Burst Limit</label>
                    <input type="number" name="burst_limit" class="eap-input"
                           value="<?= (int) ($config['burst_limit'] ?? 20) ?>" min="5" max="100">
                    <span class="eap-form-hint">Allowed burst before rate limiting</span>
                </div>
                <div class="eap-form-group">
                    <label class="eap-form-label">Rate Limit Action</label>
                    <select name="rate_limit_action" class="eap-input">
                        <option value="throttle" <?= ($config['rate_limit_action'] ?? '') === 'throttle' ? 'selected' : '' ?>>Throttle</option>
                        <option value="challenge" <?= ($config['rate_limit_action'] ?? 'challenge') === 'challenge' ? 'selected' : '' ?>>Challenge</option>
                        <option value="block" <?= ($config['rate_limit_action'] ?? '') === 'block' ? 'selected' : '' ?>>Block (429)</option>
                    </select>
                    <span class="eap-form-hint">Action when limit exceeded</span>
                </div>
            </div>
        </div>
    </div>

    <!-- ML Detection -->
    <div class="eap-card">
        <div class="eap-card__header">
            <h2 class="eap-card__title">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                    <path d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/>
                </svg>
                ML Threat Detection
            </h2>
        </div>
        <div class="eap-card__body">
            <div class="eap-grid eap-grid--3">
                <div class="eap-form-group">
                    <label class="eap-form-label">ML Detection</label>
                    <select name="ml_enabled" class="eap-input">
                        <option value="1" <?= ($config['ml_enabled'] ?? true) ? 'selected' : '' ?>>Enabled</option>
                        <option value="0" <?= !($config['ml_enabled'] ?? true) ? 'selected' : '' ?>>Disabled</option>
                    </select>
                    <span class="eap-form-hint">ML-based threat classification</span>
                </div>
                <div class="eap-form-group">
                    <label class="eap-form-label">Detection Threshold</label>
                    <input type="number" name="ml_threshold" class="eap-input"
                           value="<?= (int) ($config['ml_threshold'] ?? 60) ?>" min="20" max="95" step="5">
                    <span class="eap-form-hint">Lower = more aggressive (20-95)</span>
                </div>
                <div class="eap-form-group">
                    <label class="eap-form-label">Confidence Threshold</label>
                    <input type="number" name="confidence_threshold" class="eap-input"
                           value="<?= (int) ($config['confidence_threshold'] ?? 70) ?>" min="50" max="99">
                    <span class="eap-form-hint">Min confidence for actions (%)</span>
                </div>
            </div>
        </div>
    </div>

    <!-- Auto-Ban Settings -->
    <div class="eap-card">
        <div class="eap-card__header">
            <h2 class="eap-card__title">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
                </svg>
                Auto-Ban Settings
            </h2>
        </div>
        <div class="eap-card__body">
            <div class="eap-grid eap-grid--3">
                <div class="eap-form-group">
                    <label class="eap-form-label">Auto-Ban</label>
                    <select name="auto_ban_enabled" class="eap-input">
                        <option value="1" <?= ($config['auto_ban_enabled'] ?? true) ? 'selected' : '' ?>>Enabled</option>
                        <option value="0" <?= !($config['auto_ban_enabled'] ?? true) ? 'selected' : '' ?>>Disabled</option>
                    </select>
                    <span class="eap-form-hint">Auto-ban repeat offenders</span>
                </div>
                <div class="eap-form-group">
                    <label class="eap-form-label">Ban Threshold (Score)</label>
                    <input type="number" name="ban_threshold" class="eap-input"
                           value="<?= (int) ($config['ban_threshold'] ?? 500) ?>" min="100" max="2000">
                    <span class="eap-form-hint">Cumulative score before ban</span>
                </div>
                <div class="eap-form-group">
                    <label class="eap-form-label">Ban Duration</label>
                    <select name="ban_duration" class="eap-input">
                        <option value="3600" <?= ($config['ban_duration'] ?? 0) == 3600 ? 'selected' : '' ?>>1 Hour</option>
                        <option value="21600" <?= ($config['ban_duration'] ?? 0) == 21600 ? 'selected' : '' ?>>6 Hours</option>
                        <option value="86400" <?= ($config['ban_duration'] ?? 86400) == 86400 ? 'selected' : '' ?>>24 Hours</option>
                        <option value="604800" <?= ($config['ban_duration'] ?? 0) == 604800 ? 'selected' : '' ?>>7 Days</option>
                        <option value="2592000" <?= ($config['ban_duration'] ?? 0) == 2592000 ? 'selected' : '' ?>>30 Days</option>
                        <option value="0" <?= ($config['ban_duration'] ?? 0) == 0 ? 'selected' : '' ?>>Permanent</option>
                    </select>
                    <span class="eap-form-hint">How long to ban IPs</span>
                </div>
            </div>
        </div>
    </div>

    <!-- Detection Rules -->
    <div class="eap-card">
        <div class="eap-card__header">
            <h2 class="eap-card__title">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
                Payload Detection Rules
            </h2>
        </div>
        <div class="eap-card__body">
            <div class="eap-grid eap-grid--2">
                <div class="eap-form-group">
                    <label class="eap-form-label">SQL Injection Detection</label>
                    <select name="detect_sqli" class="eap-input">
                        <option value="1" <?= ($config['detect_sqli'] ?? true) ? 'selected' : '' ?>>Enabled</option>
                        <option value="0" <?= !($config['detect_sqli'] ?? true) ? 'selected' : '' ?>>Disabled</option>
                    </select>
                </div>
                <div class="eap-form-group">
                    <label class="eap-form-label">XSS Detection</label>
                    <select name="detect_xss" class="eap-input">
                        <option value="1" <?= ($config['detect_xss'] ?? true) ? 'selected' : '' ?>>Enabled</option>
                        <option value="0" <?= !($config['detect_xss'] ?? true) ? 'selected' : '' ?>>Disabled</option>
                    </select>
                </div>
                <div class="eap-form-group">
                    <label class="eap-form-label">Path Traversal Detection</label>
                    <select name="detect_path_traversal" class="eap-input">
                        <option value="1" <?= ($config['detect_path_traversal'] ?? true) ? 'selected' : '' ?>>Enabled</option>
                        <option value="0" <?= !($config['detect_path_traversal'] ?? true) ? 'selected' : '' ?>>Disabled</option>
                    </select>
                </div>
                <div class="eap-form-group">
                    <label class="eap-form-label">Remote Code Execution Detection</label>
                    <select name="detect_rce" class="eap-input">
                        <option value="1" <?= ($config['detect_rce'] ?? true) ? 'selected' : '' ?>>Enabled</option>
                        <option value="0" <?= !($config['detect_rce'] ?? true) ? 'selected' : '' ?>>Disabled</option>
                    </select>
                </div>
            </div>
        </div>
    </div>

    <!-- Bot Management -->
    <div class="eap-card">
        <div class="eap-card__header">
            <h2 class="eap-card__title">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                    <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
                    <circle cx="9" cy="7" r="4"/>
                    <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
                    <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
                </svg>
                Bot Management
            </h2>
        </div>
        <div class="eap-card__body">
            <div class="eap-grid eap-grid--2">
                <div class="eap-form-group">
                    <label class="eap-form-label">Allow Search Bots</label>
                    <select name="allow_search_bots" class="eap-input">
                        <option value="1" <?= ($config['allow_search_bots'] ?? true) ? 'selected' : '' ?>>Yes</option>
                        <option value="0" <?= !($config['allow_search_bots'] ?? true) ? 'selected' : '' ?>>No</option>
                    </select>
                    <span class="eap-form-hint">Google, Bing, etc.</span>
                </div>
                <div class="eap-form-group">
                    <label class="eap-form-label">Allow Social Bots</label>
                    <select name="allow_social_bots" class="eap-input">
                        <option value="1" <?= ($config['allow_social_bots'] ?? true) ? 'selected' : '' ?>>Yes</option>
                        <option value="0" <?= !($config['allow_social_bots'] ?? true) ? 'selected' : '' ?>>No</option>
                    </select>
                    <span class="eap-form-hint">Facebook, Twitter, etc.</span>
                </div>
                <div class="eap-form-group">
                    <label class="eap-form-label">Allow AI Bots</label>
                    <select name="allow_ai_bots" class="eap-input">
                        <option value="1" <?= ($config['allow_ai_bots'] ?? true) ? 'selected' : '' ?>>Yes</option>
                        <option value="0" <?= !($config['allow_ai_bots'] ?? true) ? 'selected' : '' ?>>No</option>
                    </select>
                    <span class="eap-form-hint">GPTBot, Claude, etc.</span>
                </div>
                <div class="eap-form-group">
                    <label class="eap-form-label">Bot Verification Method</label>
                    <select name="bot_verification" class="eap-input">
                        <option value="dns" <?= ($config['bot_verification'] ?? 'dns') === 'dns' ? 'selected' : '' ?>>DNS Verification</option>
                        <option value="ip_range" <?= ($config['bot_verification'] ?? '') === 'ip_range' ? 'selected' : '' ?>>IP Range Only</option>
                        <option value="both" <?= ($config['bot_verification'] ?? '') === 'both' ? 'selected' : '' ?>>Both DNS + IP</option>
                        <option value="none" <?= ($config['bot_verification'] ?? '') === 'none' ? 'selected' : '' ?>>No Verification</option>
                    </select>
                    <span class="eap-form-hint">How to verify legitimate bots</span>
                </div>
            </div>
        </div>
    </div>

    <!-- Form Actions -->
    <div class="eap-form-actions">
        <button type="submit" class="eap-btn eap-btn--primary">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/>
                <polyline points="17 21 17 13 7 13 7 21"/>
                <polyline points="7 3 7 8 15 8"/>
            </svg>
            Save Configuration
        </button>
        <button type="reset" class="eap-btn eap-btn--secondary">Reset Changes</button>
    </div>
</form>
