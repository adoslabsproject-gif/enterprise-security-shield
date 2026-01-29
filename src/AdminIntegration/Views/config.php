<?php
/**
 * Security Shield Configuration View
 *
 * @var array $config Current configuration
 * @var array $presets Available presets
 * @var string $csrfToken CSRF token
 */

$config = $config ?? [];
?>
<div class="ess-config">
    <h1 class="ess-config__title">Security Configuration</h1>

    <!-- Presets -->
    <div class="ess-presets">
        <h2 class="ess-presets__title">Quick Presets</h2>
        <div class="ess-presets__grid">
            <div class="ess-preset-card <?= ($config['preset'] ?? '') === 'low' ? 'ess-preset-card--active' : '' ?>">
                <div class="ess-preset-card__header">
                    <h3 class="ess-preset-card__title">Low Security</h3>
                    <span class="ess-badge ess-badge--success">Minimal</span>
                </div>
                <p class="ess-preset-card__desc">Basic protection. Allows most traffic, monitors suspicious activity. Best for development environments.</p>
                <ul class="ess-preset-card__list">
                    <li class="ess-preset-card__item">Rate limit: 200 req/min</li>
                    <li class="ess-preset-card__item">Auto-ban: Disabled</li>
                    <li class="ess-preset-card__item">ML threshold: 80</li>
                </ul>
                <form method="POST" action="/security/config/preset">
                    <input type="hidden" name="preset" value="low">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken ?? '') ?>">
                    <button type="submit" class="ess-btn ess-btn--sm ess-btn--secondary ess-preset-card__btn">Apply</button>
                </form>
            </div>

            <div class="ess-preset-card <?= ($config['preset'] ?? '') === 'medium' ? 'ess-preset-card--active' : '' ?>">
                <div class="ess-preset-card__header">
                    <h3 class="ess-preset-card__title">Medium Security</h3>
                    <span class="ess-badge ess-badge--warning">Balanced</span>
                </div>
                <p class="ess-preset-card__desc">Balanced protection. Blocks known threats, challenges suspicious traffic. Recommended for most sites.</p>
                <ul class="ess-preset-card__list">
                    <li class="ess-preset-card__item">Rate limit: 100 req/min</li>
                    <li class="ess-preset-card__item">Auto-ban: 24 hours</li>
                    <li class="ess-preset-card__item">ML threshold: 60</li>
                </ul>
                <form method="POST" action="/security/config/preset">
                    <input type="hidden" name="preset" value="medium">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken ?? '') ?>">
                    <button type="submit" class="ess-btn ess-btn--sm ess-btn--primary ess-preset-card__btn">Apply</button>
                </form>
            </div>

            <div class="ess-preset-card <?= ($config['preset'] ?? '') === 'high' ? 'ess-preset-card--active' : '' ?>">
                <div class="ess-preset-card__header">
                    <h3 class="ess-preset-card__title">High Security</h3>
                    <span class="ess-badge ess-badge--danger">Strict</span>
                </div>
                <p class="ess-preset-card__desc">Maximum protection. Aggressive blocking, strict rate limits. For high-value targets or under attack.</p>
                <ul class="ess-preset-card__list">
                    <li class="ess-preset-card__item">Rate limit: 30 req/min</li>
                    <li class="ess-preset-card__item">Auto-ban: Permanent</li>
                    <li class="ess-preset-card__item">ML threshold: 40</li>
                </ul>
                <form method="POST" action="/security/config/preset">
                    <input type="hidden" name="preset" value="high">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken ?? '') ?>">
                    <button type="submit" class="ess-btn ess-btn--sm ess-btn--danger ess-preset-card__btn">Apply</button>
                </form>
            </div>
        </div>
    </div>

    <!-- Configuration Form -->
    <form method="POST" action="/security/config" class="ess-config-form">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken ?? '') ?>">

        <!-- General Settings -->
        <div class="ess-config-section">
            <h2 class="ess-config-section__title">General Settings</h2>

            <div class="ess-config-row">
                <div class="ess-config-field">
                    <label class="ess-config-field__label" for="ess-enabled">WAF Status</label>
                    <div class="ess-toggle">
                        <input type="checkbox" name="enabled" id="ess-enabled" class="ess-toggle__input"
                               <?= ($config['enabled'] ?? true) ? 'checked' : '' ?>>
                        <label for="ess-enabled" class="ess-toggle__slider"></label>
                        <span class="ess-toggle__label">Enable Web Application Firewall</span>
                    </div>
                </div>
            </div>

            <div class="ess-config-row">
                <div class="ess-config-field">
                    <label class="ess-config-field__label" for="ess-mode">Operating Mode</label>
                    <select name="mode" id="ess-mode" class="ess-config-field__select">
                        <option value="monitor" <?= ($config['mode'] ?? '') === 'monitor' ? 'selected' : '' ?>>Monitor Only (Log threats, don't block)</option>
                        <option value="protect" <?= ($config['mode'] ?? 'protect') === 'protect' ? 'selected' : '' ?>>Protect (Block threats)</option>
                        <option value="paranoid" <?= ($config['mode'] ?? '') === 'paranoid' ? 'selected' : '' ?>>Paranoid (Block all suspicious traffic)</option>
                    </select>
                    <p class="ess-config-field__help">Monitor mode is useful for testing before enabling blocking.</p>
                </div>
            </div>
        </div>

        <!-- Rate Limiting -->
        <div class="ess-config-section">
            <h2 class="ess-config-section__title">Rate Limiting</h2>

            <div class="ess-config-row ess-config-row--grid">
                <div class="ess-config-field">
                    <label class="ess-config-field__label" for="ess-rate-limit">Requests per Minute</label>
                    <input type="number" name="rate_limit" id="ess-rate-limit" class="ess-config-field__input"
                           value="<?= htmlspecialchars($config['rate_limit'] ?? 100) ?>" min="10" max="1000">
                    <p class="ess-config-field__help">Maximum requests per IP per minute.</p>
                </div>

                <div class="ess-config-field">
                    <label class="ess-config-field__label" for="ess-burst-limit">Burst Limit</label>
                    <input type="number" name="burst_limit" id="ess-burst-limit" class="ess-config-field__input"
                           value="<?= htmlspecialchars($config['burst_limit'] ?? 20) ?>" min="5" max="100">
                    <p class="ess-config-field__help">Allowed burst requests before rate limiting.</p>
                </div>
            </div>

            <div class="ess-config-row">
                <div class="ess-config-field">
                    <label class="ess-config-field__label" for="ess-rate-limit-action">Rate Limit Action</label>
                    <select name="rate_limit_action" id="ess-rate-limit-action" class="ess-config-field__select">
                        <option value="throttle" <?= ($config['rate_limit_action'] ?? '') === 'throttle' ? 'selected' : '' ?>>Throttle (Delay responses)</option>
                        <option value="challenge" <?= ($config['rate_limit_action'] ?? 'challenge') === 'challenge' ? 'selected' : '' ?>>Challenge (Show CAPTCHA)</option>
                        <option value="block" <?= ($config['rate_limit_action'] ?? '') === 'block' ? 'selected' : '' ?>>Block (Return 429)</option>
                    </select>
                </div>
            </div>
        </div>

        <!-- ML Detection -->
        <div class="ess-config-section">
            <h2 class="ess-config-section__title">ML Threat Detection</h2>

            <div class="ess-config-row">
                <div class="ess-config-field">
                    <label class="ess-config-field__label" for="ess-ml-enabled">ML Detection</label>
                    <div class="ess-toggle">
                        <input type="checkbox" name="ml_enabled" id="ess-ml-enabled" class="ess-toggle__input"
                               <?= ($config['ml_enabled'] ?? true) ? 'checked' : '' ?>>
                        <label for="ess-ml-enabled" class="ess-toggle__slider"></label>
                        <span class="ess-toggle__label">Enable ML-based threat classification</span>
                    </div>
                </div>
            </div>

            <div class="ess-config-row ess-config-row--grid">
                <div class="ess-config-field">
                    <label class="ess-config-field__label" for="ess-ml-threshold">Detection Threshold</label>
                    <input type="range" name="ml_threshold" id="ess-ml-threshold" class="ess-config-field__range"
                           value="<?= htmlspecialchars($config['ml_threshold'] ?? 60) ?>" min="20" max="95" step="5">
                    <div class="ess-config-field__range-labels">
                        <span>Aggressive (20)</span>
                        <span class="ess-config-field__range-value" data-ess-range-value><?= $config['ml_threshold'] ?? 60 ?></span>
                        <span>Permissive (95)</span>
                    </div>
                    <p class="ess-config-field__help">Lower values = more aggressive blocking.</p>
                </div>

                <div class="ess-config-field">
                    <label class="ess-config-field__label" for="ess-confidence-threshold">Confidence Threshold</label>
                    <input type="range" name="confidence_threshold" id="ess-confidence-threshold" class="ess-config-field__range"
                           value="<?= htmlspecialchars($config['confidence_threshold'] ?? 70) ?>" min="50" max="99" step="1">
                    <div class="ess-config-field__range-labels">
                        <span>50%</span>
                        <span class="ess-config-field__range-value" data-ess-range-value><?= $config['confidence_threshold'] ?? 70 ?>%</span>
                        <span>99%</span>
                    </div>
                    <p class="ess-config-field__help">Minimum confidence for automated actions.</p>
                </div>
            </div>
        </div>

        <!-- Bot Management -->
        <div class="ess-config-section">
            <h2 class="ess-config-section__title">Bot Management</h2>

            <div class="ess-config-row">
                <div class="ess-config-field">
                    <label class="ess-config-field__label">Verified Bot Actions</label>
                    <div class="ess-checkbox-group">
                        <label class="ess-checkbox">
                            <input type="checkbox" name="allow_search_bots" class="ess-checkbox__input"
                                   <?= ($config['allow_search_bots'] ?? true) ? 'checked' : '' ?>>
                            <span class="ess-checkbox__label">Allow Search Engine Bots (Google, Bing, etc.)</span>
                        </label>
                        <label class="ess-checkbox">
                            <input type="checkbox" name="allow_social_bots" class="ess-checkbox__input"
                                   <?= ($config['allow_social_bots'] ?? true) ? 'checked' : '' ?>>
                            <span class="ess-checkbox__label">Allow Social Media Bots (Facebook, Twitter, etc.)</span>
                        </label>
                        <label class="ess-checkbox">
                            <input type="checkbox" name="allow_ai_bots" class="ess-checkbox__input"
                                   <?= ($config['allow_ai_bots'] ?? true) ? 'checked' : '' ?>>
                            <span class="ess-checkbox__label">Allow AI Bots (GPTBot, Claude, etc.)</span>
                        </label>
                        <label class="ess-checkbox">
                            <input type="checkbox" name="allow_monitoring_bots" class="ess-checkbox__input"
                                   <?= ($config['allow_monitoring_bots'] ?? true) ? 'checked' : '' ?>>
                            <span class="ess-checkbox__label">Allow Monitoring Bots (Pingdom, UptimeRobot, etc.)</span>
                        </label>
                    </div>
                </div>
            </div>

            <div class="ess-config-row">
                <div class="ess-config-field">
                    <label class="ess-config-field__label" for="ess-bot-verification">Bot Verification Method</label>
                    <select name="bot_verification" id="ess-bot-verification" class="ess-config-field__select">
                        <option value="dns" <?= ($config['bot_verification'] ?? 'dns') === 'dns' ? 'selected' : '' ?>>DNS Verification (Reverse + Forward DNS)</option>
                        <option value="ip_range" <?= ($config['bot_verification'] ?? '') === 'ip_range' ? 'selected' : '' ?>>IP Range Only</option>
                        <option value="both" <?= ($config['bot_verification'] ?? '') === 'both' ? 'selected' : '' ?>>Both DNS + IP Range</option>
                        <option value="none" <?= ($config['bot_verification'] ?? '') === 'none' ? 'selected' : '' ?>>No Verification (Trust User-Agent)</option>
                    </select>
                    <p class="ess-config-field__help">DNS verification is the most secure but adds latency.</p>
                </div>
            </div>
        </div>

        <!-- Auto-Ban Settings -->
        <div class="ess-config-section">
            <h2 class="ess-config-section__title">Auto-Ban Settings</h2>

            <div class="ess-config-row">
                <div class="ess-config-field">
                    <label class="ess-config-field__label" for="ess-auto-ban">Auto-Ban</label>
                    <div class="ess-toggle">
                        <input type="checkbox" name="auto_ban_enabled" id="ess-auto-ban" class="ess-toggle__input"
                               <?= ($config['auto_ban_enabled'] ?? true) ? 'checked' : '' ?>>
                        <label for="ess-auto-ban" class="ess-toggle__slider"></label>
                        <span class="ess-toggle__label">Automatically ban repeat offenders</span>
                    </div>
                </div>
            </div>

            <div class="ess-config-row ess-config-row--grid">
                <div class="ess-config-field">
                    <label class="ess-config-field__label" for="ess-ban-threshold">Ban Threshold (Score)</label>
                    <input type="number" name="ban_threshold" id="ess-ban-threshold" class="ess-config-field__input"
                           value="<?= htmlspecialchars($config['ban_threshold'] ?? 500) ?>" min="100" max="2000">
                    <p class="ess-config-field__help">Cumulative threat score before auto-ban.</p>
                </div>

                <div class="ess-config-field">
                    <label class="ess-config-field__label" for="ess-ban-duration">Ban Duration</label>
                    <select name="ban_duration" id="ess-ban-duration" class="ess-config-field__select">
                        <option value="3600" <?= ($config['ban_duration'] ?? 0) == 3600 ? 'selected' : '' ?>>1 Hour</option>
                        <option value="21600" <?= ($config['ban_duration'] ?? 0) == 21600 ? 'selected' : '' ?>>6 Hours</option>
                        <option value="86400" <?= ($config['ban_duration'] ?? 86400) == 86400 ? 'selected' : '' ?>>24 Hours</option>
                        <option value="604800" <?= ($config['ban_duration'] ?? 0) == 604800 ? 'selected' : '' ?>>7 Days</option>
                        <option value="2592000" <?= ($config['ban_duration'] ?? 0) == 2592000 ? 'selected' : '' ?>>30 Days</option>
                        <option value="0" <?= ($config['ban_duration'] ?? 0) == 0 ? 'selected' : '' ?>>Permanent</option>
                    </select>
                </div>
            </div>
        </div>

        <!-- Payload Analysis -->
        <div class="ess-config-section">
            <h2 class="ess-config-section__title">Payload Analysis</h2>

            <div class="ess-config-row">
                <div class="ess-config-field">
                    <label class="ess-config-field__label">Detection Rules</label>
                    <div class="ess-checkbox-group">
                        <label class="ess-checkbox">
                            <input type="checkbox" name="detect_sqli" class="ess-checkbox__input"
                                   <?= ($config['detect_sqli'] ?? true) ? 'checked' : '' ?>>
                            <span class="ess-checkbox__label">SQL Injection Detection</span>
                        </label>
                        <label class="ess-checkbox">
                            <input type="checkbox" name="detect_xss" class="ess-checkbox__input"
                                   <?= ($config['detect_xss'] ?? true) ? 'checked' : '' ?>>
                            <span class="ess-checkbox__label">XSS (Cross-Site Scripting) Detection</span>
                        </label>
                        <label class="ess-checkbox">
                            <input type="checkbox" name="detect_path_traversal" class="ess-checkbox__input"
                                   <?= ($config['detect_path_traversal'] ?? true) ? 'checked' : '' ?>>
                            <span class="ess-checkbox__label">Path Traversal Detection</span>
                        </label>
                        <label class="ess-checkbox">
                            <input type="checkbox" name="detect_rce" class="ess-checkbox__input"
                                   <?= ($config['detect_rce'] ?? true) ? 'checked' : '' ?>>
                            <span class="ess-checkbox__label">Remote Code Execution Detection</span>
                        </label>
                        <label class="ess-checkbox">
                            <input type="checkbox" name="detect_file_inclusion" class="ess-checkbox__input"
                                   <?= ($config['detect_file_inclusion'] ?? true) ? 'checked' : '' ?>>
                            <span class="ess-checkbox__label">File Inclusion Detection (LFI/RFI)</span>
                        </label>
                    </div>
                </div>
            </div>
        </div>

        <!-- GeoIP Settings -->
        <div class="ess-config-section">
            <h2 class="ess-config-section__title">GeoIP Settings</h2>

            <div class="ess-config-row">
                <div class="ess-config-field">
                    <label class="ess-config-field__label" for="ess-geoip-mode">GeoIP Mode</label>
                    <select name="geoip_mode" id="ess-geoip-mode" class="ess-config-field__select">
                        <option value="disabled" <?= ($config['geoip_mode'] ?? '') === 'disabled' ? 'selected' : '' ?>>Disabled</option>
                        <option value="whitelist" <?= ($config['geoip_mode'] ?? '') === 'whitelist' ? 'selected' : '' ?>>Whitelist (Allow only selected countries)</option>
                        <option value="blacklist" <?= ($config['geoip_mode'] ?? 'blacklist') === 'blacklist' ? 'selected' : '' ?>>Blacklist (Block selected countries)</option>
                    </select>
                </div>
            </div>

            <div class="ess-config-row">
                <div class="ess-config-field">
                    <label class="ess-config-field__label" for="ess-geoip-countries">Countries</label>
                    <textarea name="geoip_countries" id="ess-geoip-countries" class="ess-config-field__textarea"
                              rows="3" placeholder="Enter country codes, one per line (e.g., CN, RU, KP)"><?= htmlspecialchars($config['geoip_countries'] ?? '') ?></textarea>
                    <p class="ess-config-field__help">Use ISO 3166-1 alpha-2 country codes.</p>
                </div>
            </div>
        </div>

        <!-- Form Actions -->
        <div class="ess-config-actions">
            <button type="submit" class="ess-btn ess-btn--primary ess-btn--lg">Save Configuration</button>
            <button type="reset" class="ess-btn ess-btn--secondary ess-btn--lg">Reset Changes</button>
        </div>
    </form>
</div>
