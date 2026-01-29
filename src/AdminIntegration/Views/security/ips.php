<?php
/**
 * Security Shield IP Management View.
 *
 * @var array $bannedIps List of banned IPs
 * @var array $whitelistedIps List of whitelisted IPs
 * @var array $ipStats IP statistics
 * @var string $csrfToken CSRF token
 */
?>
<div class="ess-ips">
    <h1 class="ess-ips__title">IP Management</h1>

    <!-- Quick Actions -->
    <div class="ess-quick-actions">
        <div class="ess-quick-actions__card">
            <h3 class="ess-quick-actions__title">Quick Ban</h3>
            <form method="POST" action="/security/ips/ban" class="ess-quick-actions__form">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken ?? '') ?>">
                <div class="ess-input-group">
                    <input type="text" name="ip" class="ess-input-group__input" placeholder="IP address (e.g., 192.168.1.1)"
                           pattern="^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$" required>
                    <button type="submit" class="ess-btn ess-btn--danger">Ban</button>
                </div>
                <div class="ess-input-group ess-input-group--mt">
                    <input type="text" name="reason" class="ess-input-group__input" placeholder="Reason (optional)">
                </div>
            </form>
        </div>

        <div class="ess-quick-actions__card">
            <h3 class="ess-quick-actions__title">Quick Whitelist</h3>
            <form method="POST" action="/security/ips/whitelist" class="ess-quick-actions__form">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken ?? '') ?>">
                <div class="ess-input-group">
                    <input type="text" name="ip" class="ess-input-group__input" placeholder="IP address (e.g., 192.168.1.1)"
                           pattern="^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$" required>
                    <button type="submit" class="ess-btn ess-btn--success">Whitelist</button>
                </div>
                <div class="ess-input-group ess-input-group--mt">
                    <input type="text" name="label" class="ess-input-group__input" placeholder="Label (e.g., Office IP)">
                </div>
            </form>
        </div>

        <div class="ess-quick-actions__card">
            <h3 class="ess-quick-actions__title">IP Lookup</h3>
            <form method="GET" action="/security/ips/lookup" class="ess-quick-actions__form">
                <div class="ess-input-group">
                    <input type="text" name="ip" class="ess-input-group__input" placeholder="IP address to lookup"
                           pattern="^(\d{1,3}\.){3}\d{1,3}$" required>
                    <button type="submit" class="ess-btn ess-btn--primary">Lookup</button>
                </div>
            </form>
        </div>
    </div>

    <!-- IP Statistics -->
    <div class="ess-stats-row">
        <div class="ess-stats-row__item">
            <span class="ess-stats-row__value"><?= number_format($ipStats['total_banned'] ?? 0) ?></span>
            <span class="ess-stats-row__label">Banned IPs</span>
        </div>
        <div class="ess-stats-row__item">
            <span class="ess-stats-row__value"><?= number_format($ipStats['total_whitelisted'] ?? 0) ?></span>
            <span class="ess-stats-row__label">Whitelisted IPs</span>
        </div>
        <div class="ess-stats-row__item">
            <span class="ess-stats-row__value"><?= number_format($ipStats['banned_today'] ?? 0) ?></span>
            <span class="ess-stats-row__label">Banned Today</span>
        </div>
        <div class="ess-stats-row__item">
            <span class="ess-stats-row__value"><?= number_format($ipStats['auto_banned'] ?? 0) ?></span>
            <span class="ess-stats-row__label">Auto-Banned</span>
        </div>
    </div>

    <!-- Tabs -->
    <div class="ess-tabs" data-ess-tabs>
        <div class="ess-tabs__nav">
            <button type="button" class="ess-tabs__btn ess-tabs__btn--active" data-ess-tab="banned">
                Banned IPs
                <span class="ess-tabs__count"><?= count($bannedIps ?? []) ?></span>
            </button>
            <button type="button" class="ess-tabs__btn" data-ess-tab="whitelisted">
                Whitelisted IPs
                <span class="ess-tabs__count"><?= count($whitelistedIps ?? []) ?></span>
            </button>
        </div>

        <!-- Banned IPs Tab -->
        <div class="ess-tabs__panel ess-tabs__panel--active" data-ess-panel="banned">
            <div class="ess-table-card">
                <div class="ess-table-card__header">
                    <h3 class="ess-table-card__title">Banned IP Addresses</h3>
                    <div class="ess-table-card__actions">
                        <form method="POST" action="/security/ips/clear-expired" class="ess-form--inline">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken ?? '') ?>">
                            <button type="submit" class="ess-btn ess-btn--sm ess-btn--secondary">Clear Expired</button>
                        </form>
                    </div>
                </div>
                <div class="ess-table-card__wrapper">
                    <table class="ess-table">
                        <thead class="ess-table__head">
                            <tr class="ess-table__row">
                                <th class="ess-table__th">IP Address</th>
                                <th class="ess-table__th">Country</th>
                                <th class="ess-table__th">Reason</th>
                                <th class="ess-table__th">Banned At</th>
                                <th class="ess-table__th">Expires</th>
                                <th class="ess-table__th">Source</th>
                                <th class="ess-table__th">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="ess-table__body">
                            <?php foreach ($bannedIps ?? [] as $banned): ?>
                            <tr class="ess-table__row">
                                <td class="ess-table__td">
                                    <code class="ess-code"><?= htmlspecialchars($banned['ip'] ?? '') ?></code>
                                </td>
                                <td class="ess-table__td">
                                    <?= htmlspecialchars($banned['country'] ?? 'Unknown') ?>
                                </td>
                                <td class="ess-table__td">
                                    <span class="ess-truncate" title="<?= htmlspecialchars($banned['reason'] ?? '') ?>">
                                        <?= htmlspecialchars(substr($banned['reason'] ?? 'No reason', 0, 30)) ?>
                                    </span>
                                </td>
                                <td class="ess-table__td ess-table__td--muted">
                                    <?= htmlspecialchars($banned['banned_at'] ?? '') ?>
                                </td>
                                <td class="ess-table__td">
                                    <?php if (empty($banned['expires_at'])): ?>
                                    <span class="ess-badge ess-badge--danger">Permanent</span>
                                    <?php else: ?>
                                    <span class="ess-datetime" data-timestamp="<?= htmlspecialchars($banned['expires_at']) ?>">
                                        <?= htmlspecialchars($banned['expires_at']) ?>
                                    </span>
                                    <?php endif; ?>
                                </td>
                                <td class="ess-table__td">
                                    <span class="ess-badge ess-badge--<?= ($banned['source'] ?? '') === 'auto' ? 'warning' : 'secondary' ?>">
                                        <?= htmlspecialchars(ucfirst($banned['source'] ?? 'manual')) ?>
                                    </span>
                                </td>
                                <td class="ess-table__td">
                                    <form method="POST" action="/security/ips/unban" class="ess-form--inline">
                                        <input type="hidden" name="ip" value="<?= htmlspecialchars($banned['ip'] ?? '') ?>">
                                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken ?? '') ?>">
                                        <button type="submit" class="ess-btn ess-btn--sm ess-btn--success">Unban</button>
                                    </form>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                            <?php if (empty($bannedIps)): ?>
                            <tr class="ess-table__row">
                                <td class="ess-table__td ess-table__td--empty" colspan="7">No banned IPs</td>
                            </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Whitelisted IPs Tab -->
        <div class="ess-tabs__panel" data-ess-panel="whitelisted">
            <div class="ess-table-card">
                <div class="ess-table-card__header">
                    <h3 class="ess-table-card__title">Whitelisted IP Addresses</h3>
                </div>
                <div class="ess-table-card__wrapper">
                    <table class="ess-table">
                        <thead class="ess-table__head">
                            <tr class="ess-table__row">
                                <th class="ess-table__th">IP Address / Range</th>
                                <th class="ess-table__th">Label</th>
                                <th class="ess-table__th">Added At</th>
                                <th class="ess-table__th">Added By</th>
                                <th class="ess-table__th">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="ess-table__body">
                            <?php foreach ($whitelistedIps ?? [] as $whitelisted): ?>
                            <tr class="ess-table__row">
                                <td class="ess-table__td">
                                    <code class="ess-code"><?= htmlspecialchars($whitelisted['ip'] ?? '') ?></code>
                                </td>
                                <td class="ess-table__td">
                                    <?= htmlspecialchars($whitelisted['label'] ?? '-') ?>
                                </td>
                                <td class="ess-table__td ess-table__td--muted">
                                    <?= htmlspecialchars($whitelisted['added_at'] ?? '') ?>
                                </td>
                                <td class="ess-table__td">
                                    <?= htmlspecialchars($whitelisted['added_by'] ?? 'System') ?>
                                </td>
                                <td class="ess-table__td">
                                    <form method="POST" action="/security/ips/remove-whitelist" class="ess-form--inline">
                                        <input type="hidden" name="ip" value="<?= htmlspecialchars($whitelisted['ip'] ?? '') ?>">
                                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken ?? '') ?>">
                                        <button type="submit" class="ess-btn ess-btn--sm ess-btn--danger">Remove</button>
                                    </form>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                            <?php if (empty($whitelistedIps)): ?>
                            <tr class="ess-table__row">
                                <td class="ess-table__td ess-table__td--empty" colspan="5">No whitelisted IPs</td>
                            </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>
