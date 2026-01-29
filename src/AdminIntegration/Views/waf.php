<?php
/**
 * WAF Rules View.
 *
 * @var array $rules
 * @var array $detection_stats
 * @var string $page_title
 */
?>

<div class="container-fluid py-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h1 class="h3 mb-0"><?= htmlspecialchars($page_title) ?></h1>
        <div>
            <span class="badge bg-success me-2">
                <i class="fas fa-shield-alt me-1"></i>
                WAF Active
            </span>
        </div>
    </div>

    <!-- Detection Stats -->
    <div class="row mb-4">
        <div class="col-md-2">
            <div class="card bg-danger text-white">
                <div class="card-body text-center">
                    <h3 class="mb-0"><?= number_format($detection_stats['sqli_24h'] ?? 0) ?></h3>
                    <small>SQLi Blocked (24h)</small>
                </div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="card bg-warning text-dark">
                <div class="card-body text-center">
                    <h3 class="mb-0"><?= number_format($detection_stats['xss_24h'] ?? 0) ?></h3>
                    <small>XSS Blocked (24h)</small>
                </div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="card bg-info text-white">
                <div class="card-body text-center">
                    <h3 class="mb-0"><?= number_format($detection_stats['command_24h'] ?? 0) ?></h3>
                    <small>Cmd Injection (24h)</small>
                </div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="card bg-secondary text-white">
                <div class="card-body text-center">
                    <h3 class="mb-0"><?= number_format($detection_stats['xxe_24h'] ?? 0) ?></h3>
                    <small>XXE Blocked (24h)</small>
                </div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="card bg-dark text-white">
                <div class="card-body text-center">
                    <h3 class="mb-0"><?= number_format($detection_stats['traversal_24h'] ?? 0) ?></h3>
                    <small>Path Traversal (24h)</small>
                </div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="card bg-primary text-white">
                <div class="card-body text-center">
                    <h3 class="mb-0"><?= number_format($detection_stats['total_24h'] ?? 0) ?></h3>
                    <small>Total Threats (24h)</small>
                </div>
            </div>
        </div>
    </div>

    <!-- WAF Rules Table -->
    <div class="card">
        <div class="card-header">
            <h5 class="mb-0"><i class="fas fa-shield-alt me-2"></i>WAF Detection Rules</h5>
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th style="width: 50px;">Status</th>
                            <th>Rule Name</th>
                            <th>Description</th>
                            <th class="text-end">Detections (30d)</th>
                            <th style="width: 100px;">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($rules as $rule): ?>
                        <tr>
                            <td>
                                <?php if ($rule['enabled']): ?>
                                    <span class="badge bg-success"><i class="fas fa-check"></i></span>
                                <?php else: ?>
                                    <span class="badge bg-secondary"><i class="fas fa-times"></i></span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <strong><?= htmlspecialchars($rule['name']) ?></strong>
                            </td>
                            <td class="text-muted">
                                <?= htmlspecialchars($rule['description']) ?>
                            </td>
                            <td class="text-end">
                                <span class="badge bg-<?= $rule['detections'] > 0 ? 'danger' : 'secondary' ?>">
                                    <?= number_format($rule['detections']) ?>
                                </span>
                            </td>
                            <td>
                                <form method="POST" action="<?= $this->adminUrl('security/waf/toggle') ?>" class="d-inline">
                                    <input type="hidden" name="rule_id" value="<?= htmlspecialchars($rule['id']) ?>">
                                    <input type="hidden" name="enabled" value="<?= $rule['enabled'] ? 'false' : 'true' ?>">
                                    <button type="submit" class="btn btn-sm btn-<?= $rule['enabled'] ? 'warning' : 'success' ?>">
                                        <?= $rule['enabled'] ? 'Disable' : 'Enable' ?>
                                    </button>
                                </form>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Detection Methods -->
    <div class="row mt-4">
        <div class="col-md-6">
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0"><i class="fas fa-code me-2"></i>AST-Based Detection</h5>
                </div>
                <div class="card-body">
                    <p>The WAF uses Abstract Syntax Tree (AST) parsing for accurate SQL injection detection:</p>
                    <ul>
                        <li>SQL Tokenization with lexical analysis</li>
                        <li>Syntactic structure validation</li>
                        <li>Comment injection detection</li>
                        <li>String escape analysis</li>
                        <li>UNION/OR injection patterns</li>
                    </ul>
                </div>
            </div>
        </div>
        <div class="col-md-6">
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0"><i class="fas fa-brain me-2"></i>ML Enhancement</h5>
                </div>
                <div class="card-body">
                    <p>Machine Learning augments rule-based detection:</p>
                    <ul>
                        <li>Naive Bayes threat classification</li>
                        <li>Online learning from new attacks</li>
                        <li>Behavioral pattern analysis</li>
                        <li>Bot verification (DNS + behavior)</li>
                        <li>Anomaly detection</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
</div>
