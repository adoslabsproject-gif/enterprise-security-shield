<?php
/**
 * Rate Limiting View
 *
 * @var array $config
 * @var array $endpoints
 * @var array $stats
 * @var string $page_title
 */
?>

<div class="container-fluid py-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h1 class="h3 mb-0"><?= htmlspecialchars($page_title) ?></h1>
        <span class="badge bg-warning text-dark">
            <i class="fas fa-tachometer-alt me-1"></i>
            <?= number_format($stats['rate_limit_hits_24h'] ?? 0) ?> rate limits triggered (24h)
        </span>
    </div>

    <!-- Global Rate Limit Settings -->
    <div class="card mb-4">
        <div class="card-header">
            <h5 class="mb-0"><i class="fas fa-cog me-2"></i>Global Rate Limit Settings</h5>
        </div>
        <div class="card-body">
            <form method="POST" action="<?= $this->adminUrl('security/ratelimit/save') ?>">
                <div class="row">
                    <div class="col-md-3">
                        <div class="mb-3">
                            <label class="form-label">Max Requests (Global)</label>
                            <input type="number" name="rate_limit_max" class="form-control"
                                   value="<?= (int) ($config['rate_limit_max'] ?? 100) ?>"
                                   min="1" max="10000">
                            <small class="text-muted">Per IP per window</small>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="mb-3">
                            <label class="form-label">Window (seconds)</label>
                            <input type="number" name="rate_limit_window" class="form-control"
                                   value="<?= (int) ($config['rate_limit_window'] ?? 60) ?>"
                                   min="10" max="3600">
                            <small class="text-muted">Time window for counting</small>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="mb-3">
                            <label class="form-label">Login Attempts</label>
                            <input type="number" name="rate_limit_login" class="form-control"
                                   value="<?= (int) ($config['rate_limit_login'] ?? 5) ?>"
                                   min="1" max="100">
                            <small class="text-muted">Per minute per IP</small>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="mb-3">
                            <label class="form-label">API Requests</label>
                            <input type="number" name="rate_limit_api" class="form-control"
                                   value="<?= (int) ($config['rate_limit_api'] ?? 1000) ?>"
                                   min="1" max="10000">
                            <small class="text-muted">Per minute per key</small>
                        </div>
                    </div>
                </div>
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-save me-2"></i>Save Settings
                </button>
            </form>
        </div>
    </div>

    <!-- Per-Endpoint Rate Limits -->
    <div class="card mb-4">
        <div class="card-header">
            <h5 class="mb-0"><i class="fas fa-route me-2"></i>Per-Endpoint Rate Limits</h5>
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>Endpoint</th>
                            <th>Method</th>
                            <th>Limit</th>
                            <th>Window</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($endpoints as $endpoint): ?>
                        <tr>
                            <td><code><?= htmlspecialchars($endpoint['path']) ?></code></td>
                            <td>
                                <span class="badge bg-<?= $endpoint['method'] === 'POST' ? 'warning' : 'info' ?>">
                                    <?= htmlspecialchars($endpoint['method']) ?>
                                </span>
                            </td>
                            <td><strong><?= number_format($endpoint['limit']) ?></strong> req</td>
                            <td><?= number_format($endpoint['window']) ?>s</td>
                            <td class="text-muted">
                                <?php
                                $desc = match($endpoint['path']) {
                                    '/login' => 'Prevents brute force attacks',
                                    '/api/*' => 'API rate limiting for authenticated users',
                                    '/register' => 'Prevents registration abuse',
                                    '/password/reset' => 'Prevents password reset abuse',
                                    '/contact' => 'Prevents contact form spam',
                                    default => 'Custom endpoint protection',
                                };
                                echo htmlspecialchars($desc);
                                ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Rate Limiting Algorithms -->
    <div class="row">
        <div class="col-md-6">
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0"><i class="fas fa-chart-line me-2"></i>Algorithms Available</h5>
                </div>
                <div class="card-body">
                    <h6><span class="badge bg-primary me-2">Sliding Window</span> Default</h6>
                    <p class="text-muted small mb-3">Most accurate, prevents bursts at window boundaries.</p>

                    <h6><span class="badge bg-secondary me-2">Token Bucket</span> Burst-Friendly</h6>
                    <p class="text-muted small mb-3">Allows controlled bursts up to bucket size.</p>

                    <h6><span class="badge bg-info me-2">Leaky Bucket</span> Strict</h6>
                    <p class="text-muted small mb-3">Strict rate enforcement, no bursts allowed.</p>

                    <h6><span class="badge bg-warning text-dark me-2">Fixed Window</span> Simple</h6>
                    <p class="text-muted small mb-0">Simplest but can allow 2x burst at boundaries.</p>
                </div>
            </div>
        </div>
        <div class="col-md-6">
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0"><i class="fas fa-users me-2"></i>Tier Multipliers</h5>
                </div>
                <div class="card-body">
                    <table class="table table-sm">
                        <thead>
                            <tr>
                                <th>Tier</th>
                                <th>Multiplier</th>
                                <th>Effective Limit</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td><span class="badge bg-secondary">Free</span></td>
                                <td>1x</td>
                                <td><?= number_format($config['rate_limit_max'] ?? 100) ?> req/min</td>
                            </tr>
                            <tr>
                                <td><span class="badge bg-info">Basic</span></td>
                                <td>2x</td>
                                <td><?= number_format(($config['rate_limit_max'] ?? 100) * 2) ?> req/min</td>
                            </tr>
                            <tr>
                                <td><span class="badge bg-warning text-dark">Premium</span></td>
                                <td>5x</td>
                                <td><?= number_format(($config['rate_limit_max'] ?? 100) * 5) ?> req/min</td>
                            </tr>
                            <tr>
                                <td><span class="badge bg-success">Enterprise</span></td>
                                <td>10x</td>
                                <td><?= number_format(($config['rate_limit_max'] ?? 100) * 10) ?> req/min</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <!-- Response Headers -->
    <div class="card mt-4">
        <div class="card-header">
            <h5 class="mb-0"><i class="fas fa-code me-2"></i>Rate Limit Response Headers</h5>
        </div>
        <div class="card-body">
            <p>The following headers are included in responses:</p>
            <pre class="bg-dark text-light p-3 rounded"><code>X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1706536800
Retry-After: 30 (only when rate limited)</code></pre>
        </div>
    </div>
</div>
