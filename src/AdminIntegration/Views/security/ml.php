<?php
/**
 * ML Threat Detection View.
 *
 * @var array $ml_stats
 * @var array $classifications
 * @var string $page_title
 */
?>

<div class="container-fluid py-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h1 class="h3 mb-0"><?= htmlspecialchars($page_title) ?></h1>
        <form method="POST" action="<?= $this->adminUrl('security/ml/retrain') ?>" class="d-inline">
            <button type="submit" class="btn btn-primary">
                <i class="fas fa-sync-alt me-2"></i>Retrain Model
            </button>
        </form>
    </div>

    <!-- ML Stats -->
    <div class="row mb-4">
        <div class="col-md-3">
            <div class="card bg-danger text-white">
                <div class="card-body text-center">
                    <h3 class="mb-0"><?= number_format($ml_stats['threats_detected_24h'] ?? 0) ?></h3>
                    <small>Threats Detected (24h)</small>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card bg-success text-white">
                <div class="card-body text-center">
                    <h3 class="mb-0"><?= number_format($ml_stats['threats_blocked_24h'] ?? 0) ?></h3>
                    <small>Threats Blocked (24h)</small>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card bg-info text-white">
                <div class="card-body text-center">
                    <h3 class="mb-0"><?= number_format(($ml_stats['model_accuracy'] ?? 0.95) * 100, 1) ?>%</h3>
                    <small>Model Accuracy</small>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card bg-secondary text-white">
                <div class="card-body text-center">
                    <h3 class="mb-0"><?= number_format($ml_stats['total_ml_events_24h'] ?? 0) ?></h3>
                    <small>ML Events (24h)</small>
                </div>
            </div>
        </div>
    </div>

    <!-- Classification Categories -->
    <div class="card mb-4">
        <div class="card-header">
            <h5 class="mb-0"><i class="fas fa-tags me-2"></i>Threat Classification Categories</h5>
        </div>
        <div class="card-body">
            <div class="row">
                <div class="col-md-4">
                    <h6><span class="badge bg-danger me-2">SCANNER</span> Automated Scanners</h6>
                    <p class="text-muted small">Censys, ZGrab, Masscan, Nmap, etc.</p>
                </div>
                <div class="col-md-4">
                    <h6><span class="badge bg-warning text-dark me-2">BOT_SPOOF</span> Bot Spoofing</h6>
                    <p class="text-muted small">Fake Googlebot, Bingbot, etc.</p>
                </div>
                <div class="col-md-4">
                    <h6><span class="badge bg-info me-2">CMS_PROBE</span> CMS Probing</h6>
                    <p class="text-muted small">WordPress, Joomla, Drupal attacks</p>
                </div>
                <div class="col-md-4">
                    <h6><span class="badge bg-secondary me-2">CONFIG_HUNT</span> Config Hunting</h6>
                    <p class="text-muted small">.env, phpinfo, config files</p>
                </div>
                <div class="col-md-4">
                    <h6><span class="badge bg-dark me-2">SQLI_ATTEMPT</span> SQL Injection</h6>
                    <p class="text-muted small">Database injection attempts</p>
                </div>
                <div class="col-md-4">
                    <h6><span class="badge bg-primary me-2">XSS_ATTEMPT</span> XSS Attack</h6>
                    <p class="text-muted small">Cross-site scripting attempts</p>
                </div>
            </div>
        </div>
    </div>

    <!-- Recent Classifications -->
    <div class="card">
        <div class="card-header">
            <h5 class="mb-0"><i class="fas fa-history me-2"></i>Recent ML Classifications</h5>
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>IP</th>
                            <th>Classification</th>
                            <th>Confidence</th>
                            <th>Path</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($classifications)): ?>
                        <tr>
                            <td colspan="6" class="text-center text-muted">No ML events recorded yet</td>
                        </tr>
                        <?php else: ?>
                        <?php foreach ($classifications as $event): ?>
                        <tr>
                            <td class="text-nowrap">
                                <?= date('Y-m-d H:i:s', strtotime($event['created_at'] ?? 'now')) ?>
                            </td>
                            <td>
                                <code><?= htmlspecialchars($event['ip'] ?? 'unknown') ?></code>
                            </td>
                            <td>
                                <?php
                                $classification = $event['data']['classification'] ?? 'unknown';
                            $badgeClass = match($classification) {
                                'SCANNER' => 'danger',
                                'BOT_SPOOF' => 'warning',
                                'CMS_PROBE' => 'info',
                                'SQLI_ATTEMPT' => 'dark',
                                'XSS_ATTEMPT' => 'primary',
                                'LEGITIMATE' => 'success',
                                default => 'secondary',
                            };
                            ?>
                                <span class="badge bg-<?= $badgeClass ?>">
                                    <?= htmlspecialchars($classification) ?>
                                </span>
                            </td>
                            <td>
                                <?php
                            $confidence = $event['data']['confidence'] ?? 0;
                            $confidencePercent = round($confidence * 100, 1);
                            $progressClass = $confidence >= 0.8 ? 'danger' : ($confidence >= 0.6 ? 'warning' : 'info');
                            ?>
                                <div class="progress" style="width: 100px; height: 20px;">
                                    <div class="progress-bar bg-<?= $progressClass ?>" style="width: <?= $confidencePercent ?>%">
                                        <?= $confidencePercent ?>%
                                    </div>
                                </div>
                            </td>
                            <td>
                                <code class="small"><?= htmlspecialchars(substr($event['data']['path'] ?? '', 0, 40)) ?></code>
                            </td>
                            <td>
                                <?php if (str_contains($event['type'] ?? '', 'blocked')): ?>
                                    <span class="badge bg-success">Blocked</span>
                                <?php else: ?>
                                    <span class="badge bg-info">Logged</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Model Info -->
    <div class="card mt-4">
        <div class="card-header">
            <h5 class="mb-0"><i class="fas fa-info-circle me-2"></i>Model Information</h5>
        </div>
        <div class="card-body">
            <div class="row">
                <div class="col-md-6">
                    <p><strong>Algorithm:</strong> Naive Bayes + Online Learning</p>
                    <p><strong>Training Data:</strong> Production attack logs</p>
                    <p><strong>Last Training:</strong> <?= htmlspecialchars($ml_stats['last_training'] ?? 'N/A') ?></p>
                </div>
                <div class="col-md-6">
                    <p><strong>Feature Extraction:</strong> User-Agent, Path, Headers, Behavior</p>
                    <p><strong>Bot Verification:</strong> DNS reverse lookup + forward validation</p>
                    <p><strong>Feedback Loop:</strong> Automatic learning from WAF blocks</p>
                </div>
            </div>
        </div>
    </div>
</div>
