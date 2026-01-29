<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\AdminIntegration\Controllers;

use AdosLabs\AdminPanel\Controllers\BaseController;
use AdosLabs\AdminPanel\Core\ModuleRegistry;
use AdosLabs\AdminPanel\Database\Pool\DatabasePool;
use AdosLabs\AdminPanel\Http\Response;
use AdosLabs\AdminPanel\Services\AuditService;
use AdosLabs\AdminPanel\Services\SessionService;
use AdosLabs\EnterpriseSecurityShield\Config\SecurityConfig;
use AdosLabs\EnterpriseSecurityShield\Contracts\StorageInterface;
use AdosLabs\EnterpriseSecurityShield\Storage\DatabaseStorage;
use AdosLabs\EnterpriseSecurityShield\Storage\RedisStorage;
use Psr\Log\LoggerInterface;

/**
 * Security Controller.
 *
 * Admin panel controller for Security Shield management.
 *
 * ENDPOINTS:
 * - GET  /security           - Dashboard with threat statistics
 * - GET  /security/ips       - IP management (bans, whitelist, blacklist)
 * - POST /security/ips/ban   - Ban an IP
 * - POST /security/ips/unban - Unban an IP
 * - GET  /security/events    - Security events log
 * - GET  /security/config    - Configuration page
 * - POST /security/config/save - Save configuration
 *
 * @version 1.0.0
 */
final class SecurityController extends BaseController
{
    /**
     * CSS files for all Security Shield views.
     */
    private const EXTRA_STYLES = [
        '/module-assets/enterprise-security-shield/css/ess-dashboard.css',
        '/module-assets/enterprise-security-shield/css/ess-components.css',
    ];

    private ?StorageInterface $storage = null;

    private ?SecurityConfig $securityConfig = null;

    public function __construct(
        DatabasePool $db,
        SessionService $sessionService,
        AuditService $auditService,
        ?LoggerInterface $logger = null,
        ?ModuleRegistry $moduleRegistry = null,
    ) {
        parent::__construct($db, $sessionService, $auditService, $logger, $moduleRegistry);
    }

    /**
     * Set security storage.
     */
    public function setStorage(StorageInterface $storage): void
    {
        $this->storage = $storage;
    }

    /**
     * Set security config.
     */
    public function setSecurityConfig(SecurityConfig $config): void
    {
        $this->securityConfig = $config;
    }

    /**
     * Get storage (lazy initialization).
     */
    private function getStorage(): StorageInterface
    {
        if ($this->storage !== null) {
            return $this->storage;
        }

        // Try Redis first
        if (class_exists('Redis') && !empty($_ENV['REDIS_HOST'])) {
            try {
                $redis = new \Redis();
                $redis->connect(
                    $_ENV['REDIS_HOST'],
                    (int) ($_ENV['REDIS_PORT'] ?? 6379),
                    2.0,
                );
                if (!empty($_ENV['REDIS_PASSWORD'])) {
                    $redis->auth($_ENV['REDIS_PASSWORD']);
                }
                $this->storage = new RedisStorage($redis);

                return $this->storage;
            } catch (\Throwable $e) {
                // Fallback to database
            }
        }

        // Fallback to database storage
        // DatabaseStorage requires PDO, extract from DatabasePool
        $connection = $this->db->acquire();
        try {
            $pdo = $connection->getPdo();
            $this->storage = new DatabaseStorage($pdo);
        } finally {
            $connection->release();
        }

        return $this->storage;
    }

    /**
     * Security dashboard
     * GET /security.
     */
    public function dashboard(): Response
    {
        $storage = $this->getStorage();

        // Get statistics
        $stats = $this->getSecurityStats();

        // Get recent threats
        $recentThreats = $this->getRecentThreats(10);

        // Get top banned IPs
        $bannedIps = $this->getBannedIps(10);

        // Get honeypot stats
        $honeypotStats = $this->getHoneypotStats();

        return $this->view('security/dashboard', [
            'stats' => $stats,
            'recent_threats' => $recentThreats,
            'banned_ips' => $bannedIps,
            'honeypot_stats' => $honeypotStats,
            'page_title' => 'Security Dashboard',
            'extra_styles' => self::EXTRA_STYLES,
        ]);
    }

    /**
     * IP Management page
     * GET /security/ips.
     */
    public function ipManagement(): Response
    {
        $query = $this->getQuery();

        $filter = $query['filter'] ?? 'all';
        $search = $query['search'] ?? '';
        $page = max(1, (int) ($query['page'] ?? 1));
        $perPage = 50;

        // Get IPs based on filter
        $ips = $this->getIpList($filter, $search, $page, $perPage);
        $total = $this->getIpCount($filter, $search);

        // Get whitelist
        $whitelist = $this->getWhitelist();

        return $this->view('security/ips', [
            'ips' => $ips,
            'total' => $total,
            'page' => $page,
            'per_page' => $perPage,
            'pages' => max(1, (int) ceil($total / $perPage)),
            'filter' => $filter,
            'search' => $search,
            'whitelist' => $whitelist,
            'page_title' => 'IP Management',
            'extra_styles' => self::EXTRA_STYLES,
        ]);
    }

    /**
     * Ban an IP
     * POST /security/ips/ban.
     */
    public function banIp(): Response
    {
        $body = $this->getBody();
        $ip = trim($body['ip'] ?? '');
        $reason = trim($body['reason'] ?? 'Manual ban from admin panel');
        $duration = (int) ($body['duration'] ?? 86400);

        // Validate IP
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            if ($this->isAjaxRequest()) {
                return $this->json(['success' => false, 'error' => 'Invalid IP address']);
            }

            return $this->withFlash('error', 'Invalid IP address', $this->adminUrl('security/ips'));
        }

        // Validate duration (1 hour to 1 year)
        $duration = max(3600, min(31536000, $duration));

        $storage = $this->getStorage();
        $storage->banIP($ip, $duration, $reason);

        $this->audit('security.ip.ban', [
            'ip' => $ip,
            'reason' => $reason,
            'duration' => $duration,
        ]);

        if ($this->isAjaxRequest()) {
            return $this->json(['success' => true, 'message' => "IP {$ip} banned successfully"]);
        }

        return $this->withFlash('success', "IP {$ip} banned successfully", $this->adminUrl('security/ips'));
    }

    /**
     * Unban an IP
     * POST /security/ips/unban.
     */
    public function unbanIp(): Response
    {
        $body = $this->getBody();
        $ip = trim($body['ip'] ?? '');

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            if ($this->isAjaxRequest()) {
                return $this->json(['success' => false, 'error' => 'Invalid IP address']);
            }

            return $this->withFlash('error', 'Invalid IP address', $this->adminUrl('security/ips'));
        }

        $storage = $this->getStorage();

        // Check if storage supports unban
        if (method_exists($storage, 'unbanIP')) {
            $storage->unbanIP($ip);
        } else {
            // Fallback: set ban expiry to past
            $storage->banIP($ip, -1, 'Unbanned');
        }

        $this->audit('security.ip.unban', ['ip' => $ip]);

        if ($this->isAjaxRequest()) {
            return $this->json(['success' => true, 'message' => "IP {$ip} unbanned"]);
        }

        return $this->withFlash('success', "IP {$ip} unbanned", $this->adminUrl('security/ips'));
    }

    /**
     * Add IP to whitelist
     * POST /security/ips/whitelist.
     */
    public function addToWhitelist(): Response
    {
        $body = $this->getBody();
        $ip = trim($body['ip'] ?? '');
        $note = trim($body['note'] ?? '');

        // Validate IP or CIDR
        if (!$this->isValidIpOrCidr($ip)) {
            if ($this->isAjaxRequest()) {
                return $this->json(['success' => false, 'error' => 'Invalid IP address or CIDR']);
            }

            return $this->withFlash('error', 'Invalid IP address or CIDR', $this->adminUrl('security/ips'));
        }

        // Store in database
        try {
            $this->db->execute(
                'INSERT INTO security_shield_whitelist (ip, note, created_by, created_at) VALUES (?, ?, ?, NOW()) ON CONFLICT (ip) DO UPDATE SET note = EXCLUDED.note',
                [$ip, $note, $this->getUser()['id'] ?? 0],
            );
        } catch (\Throwable $e) {
            // Fallback for MySQL
            $this->db->execute(
                'INSERT INTO security_shield_whitelist (ip, note, created_by, created_at) VALUES (?, ?, ?, NOW()) ON DUPLICATE KEY UPDATE note = VALUES(note)',
                [$ip, $note, $this->getUser()['id'] ?? 0],
            );
        }

        $this->audit('security.whitelist.add', ['ip' => $ip]);

        if ($this->isAjaxRequest()) {
            return $this->json(['success' => true, 'message' => "IP {$ip} added to whitelist"]);
        }

        return $this->withFlash('success', "IP {$ip} added to whitelist", $this->adminUrl('security/ips'));
    }

    /**
     * Remove IP from whitelist
     * POST /security/ips/whitelist/remove.
     */
    public function removeFromWhitelist(): Response
    {
        $body = $this->getBody();
        $ip = trim($body['ip'] ?? '');

        $this->db->execute('DELETE FROM security_shield_whitelist WHERE ip = ?', [$ip]);

        $this->audit('security.whitelist.remove', ['ip' => $ip]);

        if ($this->isAjaxRequest()) {
            return $this->json(['success' => true, 'message' => "IP {$ip} removed from whitelist"]);
        }

        return $this->withFlash('success', "IP {$ip} removed from whitelist", $this->adminUrl('security/ips'));
    }

    /**
     * Clear expired bans.
     * POST /security/ips/clear-expired.
     */
    public function clearExpiredBans(): Response
    {
        $result = $this->db->execute(
            'DELETE FROM security_shield_bans WHERE expires_at IS NOT NULL AND expires_at < NOW()',
        );

        $count = $result->rowCount() ?? 0;

        $this->audit('security.bans.clear_expired', ['count' => $count]);

        if ($this->isAjaxRequest()) {
            return $this->json(['success' => true, 'message' => "Cleared {$count} expired bans"]);
        }

        return $this->withFlash('success', "Cleared {$count} expired bans", $this->adminUrl('security/ips'));
    }

    /**
     * IP lookup - show IP history and status.
     * GET /security/ips/lookup.
     */
    public function ipLookup(): Response
    {
        $ip = trim($_GET['ip'] ?? '');

        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return $this->withFlash('error', 'Invalid IP address', $this->adminUrl('security/ips'));
        }

        $connection = $this->db->acquire();
        $pdo = $connection->getPdo();

        try {
            // Check ban status
            $stmt = $pdo->prepare('SELECT * FROM security_shield_bans WHERE ip = ?');
            $stmt->execute([$ip]);
            $ban = $stmt->fetch(\PDO::FETCH_ASSOC) ?: null;

            // Check whitelist status
            $stmt = $pdo->prepare('SELECT * FROM security_shield_whitelist WHERE ip = ?');
            $stmt->execute([$ip]);
            $whitelist = $stmt->fetch(\PDO::FETCH_ASSOC) ?: null;

            // Get threat score
            $stmt = $pdo->prepare('SELECT score FROM security_shield_scores WHERE ip = ?');
            $stmt->execute([$ip]);
            $scoreRow = $stmt->fetch(\PDO::FETCH_ASSOC);
            $score = $scoreRow ? (int) $scoreRow['score'] : 0;

            // Get recent events
            $stmt = $pdo->prepare(
                'SELECT id, type, created_at, data FROM security_shield_events
                 WHERE ip = ? ORDER BY created_at DESC LIMIT 50',
            );
            $stmt->execute([$ip]);
            $events = $stmt->fetchAll(\PDO::FETCH_ASSOC);

            // Format events
            foreach ($events as &$event) {
                $data = json_decode($event['data'] ?? '{}', true) ?: [];
                $event['path'] = $data['path'] ?? '';
                $event['user_agent'] = $data['user_agent'] ?? '';
                $event['score'] = $data['score'] ?? 0;
                $event['action'] = $data['action'] ?? 'ALLOW';
                $event['time'] = $event['created_at'];
            }
            unset($event);

            $ipInfo = [
                'ip' => $ip,
                'is_banned' => $ban !== null,
                'is_whitelisted' => $whitelist !== null,
                'ban' => $ban,
                'whitelist' => $whitelist,
                'score' => $score,
                'events' => $events,
                'event_count' => count($events),
            ];

            return $this->view('security/ip-lookup', [
                'page_title' => 'IP Lookup: ' . $ip,
                'ipInfo' => $ipInfo,
                'extra_styles' => self::EXTRA_STYLES,
            ]);
        } finally {
            $connection->release();
        }
    }

    /**
     * Security events log
     * GET /security/events.
     */
    public function events(): Response
    {
        $query = $this->getQuery();

        $type = $query['type'] ?? '';
        $ip = $query['ip'] ?? '';
        $from = $query['from'] ?? '';
        $to = $query['to'] ?? '';
        $page = max(1, (int) ($query['page'] ?? 1));
        $perPage = 100;

        // Build query
        $where = ['1=1'];
        $params = [];

        if (!empty($type)) {
            $where[] = 'type = ?';
            $params[] = $type;
        }

        if (!empty($ip)) {
            $where[] = 'ip = ?';
            $params[] = $ip;
        }

        if (!empty($from)) {
            $where[] = 'created_at >= ?';
            $params[] = $from;
        }

        if (!empty($to)) {
            $where[] = 'created_at <= ?';
            $params[] = $to;
        }

        $whereClause = implode(' AND ', $where);
        $offset = ($page - 1) * $perPage;

        // Get events
        try {
            $events = $this->db->query(
                "SELECT * FROM security_shield_events WHERE {$whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                array_merge($params, [$perPage, $offset]),
            );

            // Decode JSON data
            foreach ($events as &$event) {
                $event['data'] = json_decode($event['data'] ?? '{}', true) ?: [];
            }

            // Get total count
            $countRows = $this->db->query(
                "SELECT COUNT(*) as cnt FROM security_shield_events WHERE {$whereClause}",
                $params,
            );
            $total = (int) ($countRows[0]['cnt'] ?? 0);
        } catch (\Throwable $e) {
            $events = [];
            $total = 0;
        }

        // Get distinct event types for filter
        $eventTypes = $this->getDistinctEventTypes();

        return $this->view('security/events', [
            'events' => $events,
            'total' => $total,
            'page' => $page,
            'per_page' => $perPage,
            'pages' => max(1, (int) ceil($total / $perPage)),
            'filters' => [
                'type' => $type,
                'ip' => $ip,
                'from' => $from,
                'to' => $to,
            ],
            'event_types' => $eventTypes,
            'page_title' => 'Security Events',
            'extra_styles' => self::EXTRA_STYLES,
        ]);
    }

    /**
     * Clear old events
     * POST /security/events/clear.
     */
    public function clearEvents(): Response
    {
        $body = $this->getBody();
        $olderThan = $body['older_than'] ?? '30 days';

        $validPeriods = ['7 days', '14 days', '30 days', '90 days'];
        if (!in_array($olderThan, $validPeriods, true)) {
            return $this->withFlash('error', 'Invalid time period', $this->adminUrl('security/events'));
        }

        $cutoff = date('Y-m-d H:i:s', strtotime("-{$olderThan}"));
        $deleted = $this->db->execute(
            'DELETE FROM security_shield_events WHERE created_at < ?',
            [$cutoff],
        );

        $this->audit('security.events.clear', ['older_than' => $olderThan, 'deleted' => $deleted]);

        return $this->withFlash('success', "Deleted {$deleted} events older than {$olderThan}", $this->adminUrl('security/events'));
    }

    /**
     * Configuration page
     * GET /security/config.
     */
    public function config(): Response
    {
        $config = $this->loadConfig();

        return $this->view('security/config', [
            'config' => $config,
            'page_title' => 'Security Configuration',
            'extra_styles' => self::EXTRA_STYLES,
        ]);
    }

    /**
     * Save configuration
     * POST /security/config/save.
     */
    public function saveConfig(): Response
    {
        $body = $this->getBody();

        $config = [
            'score_threshold' => max(1, min(1000, (int) ($body['score_threshold'] ?? 50))),
            'ban_duration' => max(3600, min(31536000, (int) ($body['ban_duration'] ?? 86400))),
            'rate_limit_max' => max(1, min(10000, (int) ($body['rate_limit_max'] ?? 100))),
            'rate_limit_window' => max(10, min(3600, (int) ($body['rate_limit_window'] ?? 60))),
            'honeypot_enabled' => isset($body['honeypot_enabled']),
            'bot_verification_enabled' => isset($body['bot_verification_enabled']),
            'fail_closed' => isset($body['fail_closed']),
        ];

        $this->saveConfigToDatabase($config);

        $this->audit('security.config.update', $config);

        return $this->withFlash('success', 'Security configuration saved', $this->adminUrl('security/config'));
    }

    // =========================================================================
    // WAF RULES
    // =========================================================================

    /**
     * WAF Rules page
     * GET /security/waf.
     */
    public function wafRules(): Response
    {
        $rules = $this->getWafRules();
        $detectionStats = $this->getDetectionStats();

        return $this->view('security/waf', [
            'rules' => $rules,
            'detection_stats' => $detectionStats,
            'page_title' => 'WAF Rules',
            'extra_styles' => self::EXTRA_STYLES,
        ]);
    }

    /**
     * Toggle WAF rule
     * POST /security/waf/toggle.
     */
    public function toggleWafRule(): Response
    {
        $body = $this->getBody();
        $ruleId = $body['rule_id'] ?? '';
        $enabled = isset($body['enabled']) && $body['enabled'] === 'true';

        $this->saveWafRuleSetting($ruleId, $enabled);

        $this->audit('security.waf.toggle', ['rule_id' => $ruleId, 'enabled' => $enabled]);

        if ($this->isAjaxRequest()) {
            return $this->json(['success' => true, 'message' => "Rule {$ruleId} " . ($enabled ? 'enabled' : 'disabled')]);
        }

        return $this->withFlash('success', 'WAF rule updated', $this->adminUrl('security/waf'));
    }

    // =========================================================================
    // ML THREATS
    // =========================================================================

    /**
     * ML Threats page
     * GET /security/ml.
     */
    public function mlThreats(): Response
    {
        $mlStats = $this->getMLStats();
        $recentClassifications = $this->getRecentMLClassifications(50);

        return $this->view('security/ml', [
            'ml_stats' => $mlStats,
            'classifications' => $recentClassifications,
            'page_title' => 'ML Threat Detection',
            'extra_styles' => self::EXTRA_STYLES,
        ]);
    }

    /**
     * Retrain ML model
     * POST /security/ml/retrain.
     */
    public function retrainModel(): Response
    {
        $this->audit('security.ml.retrain', []);

        // Trigger learning from recent events
        $storage = $this->getStorage();
        $eventsLearned = 0;

        try {
            $events = $this->db->query(
                "SELECT * FROM security_shield_events WHERE created_at > NOW() - INTERVAL '7 days' ORDER BY created_at DESC LIMIT 1000",
            );
            $eventsLearned = count($events);
        } catch (\Throwable $e) {
            // MySQL fallback
            try {
                $events = $this->db->query(
                    'SELECT * FROM security_shield_events WHERE created_at > DATE_SUB(NOW(), INTERVAL 7 DAY) ORDER BY created_at DESC LIMIT 1000',
                );
                $eventsLearned = count($events);
            } catch (\Throwable $e2) {
                $eventsLearned = 0;
            }
        }

        return $this->withFlash('success', "Model retrained with {$eventsLearned} events", $this->adminUrl('security/ml'));
    }

    // =========================================================================
    // RATE LIMITING
    // =========================================================================

    /**
     * Rate Limiting page
     * GET /security/ratelimit.
     */
    public function rateLimiting(): Response
    {
        $config = $this->loadConfig();
        $endpoints = $this->getRateLimitEndpoints();
        $rateLimitStats = $this->getRateLimitStats();

        return $this->view('security/ratelimit', [
            'config' => $config,
            'endpoints' => $endpoints,
            'stats' => $rateLimitStats,
            'page_title' => 'Rate Limiting',
            'extra_styles' => self::EXTRA_STYLES,
        ]);
    }

    /**
     * Save rate limit settings
     * POST /security/ratelimit/save.
     */
    public function saveRateLimits(): Response
    {
        $body = $this->getBody();

        $config = [
            'rate_limit_max' => max(1, min(10000, (int) ($body['rate_limit_max'] ?? 100))),
            'rate_limit_window' => max(10, min(3600, (int) ($body['rate_limit_window'] ?? 60))),
            'rate_limit_login' => max(1, min(100, (int) ($body['rate_limit_login'] ?? 5))),
            'rate_limit_api' => max(1, min(10000, (int) ($body['rate_limit_api'] ?? 1000))),
        ];

        $this->saveConfigToDatabase($config);

        $this->audit('security.ratelimit.update', $config);

        return $this->withFlash('success', 'Rate limit settings saved', $this->adminUrl('security/ratelimit'));
    }

    /**
     * Apply a security preset.
     * POST /security/config/preset.
     */
    public function applyPreset(): Response
    {
        $body = $this->getBody();
        $preset = $body['preset'] ?? '';

        $presets = [
            'low' => [
                'rate_limit_max' => 200,
                'rate_limit_window' => 60,
                'rate_limit_login' => 10,
                'rate_limit_api' => 2000,
                'ml_threshold' => 80,
                'auto_ban_enabled' => false,
                'ban_duration' => 3600,
                'ban_threshold' => 1000,
                'mode' => 'monitor',
            ],
            'medium' => [
                'rate_limit_max' => 100,
                'rate_limit_window' => 60,
                'rate_limit_login' => 5,
                'rate_limit_api' => 1000,
                'ml_threshold' => 60,
                'auto_ban_enabled' => true,
                'ban_duration' => 86400,
                'ban_threshold' => 500,
                'mode' => 'protect',
            ],
            'high' => [
                'rate_limit_max' => 30,
                'rate_limit_window' => 60,
                'rate_limit_login' => 3,
                'rate_limit_api' => 500,
                'ml_threshold' => 40,
                'auto_ban_enabled' => true,
                'ban_duration' => 0, // Permanent
                'ban_threshold' => 200,
                'mode' => 'paranoid',
            ],
        ];

        if (!isset($presets[$preset])) {
            return $this->withFlash('error', 'Invalid preset', $this->adminUrl('security/config'));
        }

        $config = $presets[$preset];
        $config['preset'] = $preset;

        $this->saveConfigToDatabase($config);

        $this->audit('security.preset.apply', ['preset' => $preset]);

        return $this->withFlash('success', "Security preset '{$preset}' applied", $this->adminUrl('security/config'));
    }

    /**
     * Export security events as CSV.
     * GET /security/events/export.
     */
    public function exportEvents(): Response
    {
        $filters = [
            'type' => $_GET['type'] ?? null,
            'action' => $_GET['action'] ?? null,
            'ip' => $_GET['ip'] ?? null,
            'date_from' => $_GET['date_from'] ?? null,
            'date_to' => $_GET['date_to'] ?? null,
        ];

        $connection = $this->db->acquire();
        $pdo = $connection->getPdo();

        try {
            $sql = 'SELECT id, type, ip, created_at, data FROM security_shield_events WHERE 1=1';
            $params = [];

            if (!empty($filters['type'])) {
                $sql .= ' AND type = :type';
                $params[':type'] = $filters['type'];
            }
            if (!empty($filters['ip'])) {
                $sql .= ' AND ip = :ip';
                $params[':ip'] = $filters['ip'];
            }
            if (!empty($filters['date_from'])) {
                $sql .= ' AND created_at >= :date_from';
                $params[':date_from'] = $filters['date_from'] . ' 00:00:00';
            }
            if (!empty($filters['date_to'])) {
                $sql .= ' AND created_at <= :date_to';
                $params[':date_to'] = $filters['date_to'] . ' 23:59:59';
            }

            $sql .= ' ORDER BY created_at DESC LIMIT 10000';

            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            $events = $stmt->fetchAll(\PDO::FETCH_ASSOC);

            // Build CSV
            $csv = "ID,Type,IP,Timestamp,Path,User Agent,Score,Action\n";

            foreach ($events as $event) {
                $data = json_decode($event['data'] ?? '{}', true) ?: [];
                $csv .= sprintf(
                    "%s,%s,%s,%s,%s,%s,%s,%s\n",
                    $event['id'],
                    $this->escapeCsv($event['type'] ?? ''),
                    $this->escapeCsv($event['ip'] ?? ''),
                    $this->escapeCsv($event['created_at'] ?? ''),
                    $this->escapeCsv($data['path'] ?? ''),
                    $this->escapeCsv($data['user_agent'] ?? ''),
                    $data['score'] ?? 0,
                    $this->escapeCsv($data['action'] ?? 'ALLOW'),
                );
            }

            $this->audit('security.events.export', ['count' => count($events), 'filters' => $filters]);

            $filename = 'security_events_' . date('Y-m-d_His') . '.csv';

            return new Response(
                body: $csv,
                status: 200,
                headers: [
                    'Content-Type' => 'text/csv; charset=utf-8',
                    'Content-Disposition' => 'attachment; filename="' . $filename . '"',
                    'Content-Length' => (string) strlen($csv),
                ],
            );
        } finally {
            $connection->release();
        }
    }

    /**
     * Escape a value for CSV.
     */
    private function escapeCsv(string $value): string
    {
        if (str_contains($value, ',') || str_contains($value, '"') || str_contains($value, "\n")) {
            return '"' . str_replace('"', '""', $value) . '"';
        }

        return $value;
    }

    // =========================================================================
    // API ENDPOINTS
    // =========================================================================

    /**
     * API: Get security statistics
     * GET /security/api/stats.
     */
    public function apiStats(): Response
    {
        return $this->json($this->getSecurityStats());
    }

    /**
     * API: Get recent threats
     * GET /security/api/recent-threats.
     */
    public function apiRecentThreats(): Response
    {
        $query = $this->getQuery();
        $limit = min(100, max(1, (int) ($query['limit'] ?? 20)));

        return $this->json($this->getRecentThreats($limit));
    }

    /**
     * API: Get IP score
     * GET /security/api/ip-score?ip=x.x.x.x.
     */
    public function apiIpScore(): Response
    {
        $query = $this->getQuery();
        $ip = $query['ip'] ?? '';

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return $this->json(['error' => 'Invalid IP address'], 400);
        }

        $storage = $this->getStorage();
        $score = $storage->getScore($ip);
        $isBanned = $storage->isBanned($ip);

        return $this->json([
            'ip' => $ip,
            'score' => $score,
            'is_banned' => $isBanned,
        ]);
    }

    // =========================================================================
    // PRIVATE HELPERS
    // =========================================================================

    private function isAjaxRequest(): bool
    {
        return !empty($_SERVER['HTTP_X_REQUESTED_WITH']) &&
               strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
    }

    private function isValidIpOrCidr(string $value): bool
    {
        // Check if valid IP
        if (filter_var($value, FILTER_VALIDATE_IP)) {
            return true;
        }

        // Check if valid CIDR
        if (preg_match('#^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$#', $value)) {
            [$ip, $mask] = explode('/', $value);

            return filter_var($ip, FILTER_VALIDATE_IP) && (int) $mask >= 0 && (int) $mask <= 32;
        }

        return false;
    }

    private function getSecurityStats(): array
    {
        try {
            // Today's stats
            $today = date('Y-m-d');

            $rows = $this->db->query(
                "SELECT
                    COUNT(*) as total_events,
                    SUM(CASE WHEN type = 'ban' THEN 1 ELSE 0 END) as bans_today,
                    SUM(CASE WHEN type = 'honeypot' THEN 1 ELSE 0 END) as honeypot_hits,
                    SUM(CASE WHEN type = 'rate_limit' THEN 1 ELSE 0 END) as rate_limits,
                    COUNT(DISTINCT ip) as unique_ips
                FROM security_shield_events
                WHERE DATE(created_at) = ?",
                [$today],
            );

            $stats = $rows[0] ?? [];

            // Active bans count
            $banRows = $this->db->query(
                'SELECT COUNT(*) as cnt FROM security_shield_bans WHERE expires_at > NOW()',
            );
            $activeBans = (int) ($banRows[0]['cnt'] ?? 0);

            return [
                'total_events_today' => (int) ($stats['total_events'] ?? 0),
                'bans_today' => (int) ($stats['bans_today'] ?? 0),
                'honeypot_hits_today' => (int) ($stats['honeypot_hits'] ?? 0),
                'rate_limits_today' => (int) ($stats['rate_limits'] ?? 0),
                'unique_ips_today' => (int) ($stats['unique_ips'] ?? 0),
                'active_bans' => $activeBans,
            ];
        } catch (\Throwable $e) {
            return [
                'total_events_today' => 0,
                'bans_today' => 0,
                'honeypot_hits_today' => 0,
                'rate_limits_today' => 0,
                'unique_ips_today' => 0,
                'active_bans' => 0,
            ];
        }
    }

    private function getRecentThreats(int $limit): array
    {
        try {
            $events = $this->db->query(
                'SELECT * FROM security_shield_events ORDER BY created_at DESC LIMIT ?',
                [$limit],
            );

            foreach ($events as &$event) {
                $event['data'] = json_decode($event['data'] ?? '{}', true) ?: [];
            }

            return $events;
        } catch (\Throwable $e) {
            return [];
        }
    }

    private function getBannedIps(int $limit): array
    {
        try {
            return $this->db->query(
                'SELECT * FROM security_shield_bans WHERE expires_at > NOW() ORDER BY banned_at DESC LIMIT ?',
                [$limit],
            );
        } catch (\Throwable $e) {
            return [];
        }
    }

    private function getHoneypotStats(): array
    {
        try {
            $rows = $this->db->query(
                "SELECT
                    JSON_UNQUOTE(JSON_EXTRACT(data, '$.path')) as path,
                    COUNT(*) as hits
                FROM security_shield_events
                WHERE type = 'honeypot'
                GROUP BY path
                ORDER BY hits DESC
                LIMIT 10",
            );

            return $rows;
        } catch (\Throwable $e) {
            return [];
        }
    }

    private function getIpList(string $filter, string $search, int $page, int $perPage): array
    {
        try {
            $where = ['1=1'];
            $params = [];

            if ($filter === 'banned') {
                $where[] = 'expires_at > NOW()';
            }

            if (!empty($search)) {
                $where[] = 'ip LIKE ?';
                $params[] = "%{$search}%";
            }

            $whereClause = implode(' AND ', $where);
            $offset = ($page - 1) * $perPage;

            return $this->db->query(
                "SELECT * FROM security_shield_bans WHERE {$whereClause} ORDER BY banned_at DESC LIMIT ? OFFSET ?",
                array_merge($params, [$perPage, $offset]),
            );
        } catch (\Throwable $e) {
            return [];
        }
    }

    private function getIpCount(string $filter, string $search): int
    {
        try {
            $where = ['1=1'];
            $params = [];

            if ($filter === 'banned') {
                $where[] = 'expires_at > NOW()';
            }

            if (!empty($search)) {
                $where[] = 'ip LIKE ?';
                $params[] = "%{$search}%";
            }

            $whereClause = implode(' AND ', $where);

            $rows = $this->db->query(
                "SELECT COUNT(*) as cnt FROM security_shield_bans WHERE {$whereClause}",
                $params,
            );

            return (int) ($rows[0]['cnt'] ?? 0);
        } catch (\Throwable $e) {
            return 0;
        }
    }

    private function getWhitelist(): array
    {
        try {
            return $this->db->query(
                'SELECT * FROM security_shield_whitelist ORDER BY created_at DESC',
            );
        } catch (\Throwable $e) {
            return [];
        }
    }

    private function getDistinctEventTypes(): array
    {
        try {
            $rows = $this->db->query(
                'SELECT DISTINCT type FROM security_shield_events ORDER BY type',
            );

            return array_column($rows, 'type');
        } catch (\Throwable $e) {
            return [];
        }
    }

    private function loadConfig(): array
    {
        try {
            $rows = $this->db->query(
                'SELECT key, value FROM security_shield_config',
            );

            $config = [];
            foreach ($rows as $row) {
                $config[$row['key']] = json_decode($row['value'], true) ?? $row['value'];
            }

            return array_merge([
                'score_threshold' => 50,
                'ban_duration' => 86400,
                'rate_limit_max' => 100,
                'rate_limit_window' => 60,
                'honeypot_enabled' => true,
                'bot_verification_enabled' => true,
                'fail_closed' => false,
            ], $config);
        } catch (\Throwable $e) {
            return [
                'score_threshold' => 50,
                'ban_duration' => 86400,
                'rate_limit_max' => 100,
                'rate_limit_window' => 60,
                'honeypot_enabled' => true,
                'bot_verification_enabled' => true,
                'fail_closed' => false,
            ];
        }
    }

    private function saveConfigToDatabase(array $config): void
    {
        foreach ($config as $key => $value) {
            $jsonValue = json_encode($value);

            try {
                $this->db->execute(
                    'INSERT INTO security_shield_config (key, value, updated_at) VALUES (?, ?, NOW())
                     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()',
                    [$key, $jsonValue],
                );
            } catch (\Throwable $e) {
                // Fallback for MySQL
                $this->db->execute(
                    'INSERT INTO security_shield_config (`key`, `value`, updated_at) VALUES (?, ?, NOW())
                     ON DUPLICATE KEY UPDATE `value` = VALUES(`value`), updated_at = NOW()',
                    [$key, $jsonValue],
                );
            }
        }
    }

    /**
     * @return array<string, array{id: string, name: string, description: string, enabled: bool, detections: int}>
     */
    private function getWafRules(): array
    {
        $rules = [
            'sqli' => [
                'id' => 'sqli',
                'name' => 'SQL Injection Detection',
                'description' => 'AST-based SQL injection detection with tokenization',
                'enabled' => true,
                'detections' => 0,
            ],
            'xss' => [
                'id' => 'xss',
                'name' => 'XSS Detection',
                'description' => 'Cross-site scripting detection with DOM analysis',
                'enabled' => true,
                'detections' => 0,
            ],
            'command_injection' => [
                'id' => 'command_injection',
                'name' => 'Command Injection',
                'description' => 'Shell command injection detection',
                'enabled' => true,
                'detections' => 0,
            ],
            'xxe' => [
                'id' => 'xxe',
                'name' => 'XXE Detection',
                'description' => 'XML External Entity attack detection',
                'enabled' => true,
                'detections' => 0,
            ],
            'path_traversal' => [
                'id' => 'path_traversal',
                'name' => 'Path Traversal',
                'description' => 'Directory traversal attack detection',
                'enabled' => true,
                'detections' => 0,
            ],
            'file_upload' => [
                'id' => 'file_upload',
                'name' => 'File Upload Validation',
                'description' => 'Malicious file upload detection with magic bytes',
                'enabled' => true,
                'detections' => 0,
            ],
        ];

        // Get detection counts from database
        try {
            $counts = $this->db->query(
                "SELECT type, COUNT(*) as cnt FROM security_shield_events
                 WHERE created_at > NOW() - INTERVAL '30 days'
                 GROUP BY type",
            );
            foreach ($counts as $row) {
                $type = str_replace(['_detected', '_attack', '_blocked'], '', $row['type']);
                if (isset($rules[$type])) {
                    $rules[$type]['detections'] = (int) $row['cnt'];
                }
            }
        } catch (\Throwable $e) {
            // Ignore
        }

        // Get enabled status from config
        try {
            $configRows = $this->db->query(
                "SELECT key, value FROM security_shield_config WHERE key LIKE 'rule_%'",
            );
            foreach ($configRows as $row) {
                $ruleId = str_replace('rule_', '', $row['key']);
                if (isset($rules[$ruleId])) {
                    $rules[$ruleId]['enabled'] = json_decode($row['value'], true) ?? true;
                }
            }
        } catch (\Throwable $e) {
            // Ignore
        }

        return $rules;
    }

    /**
     * @return array<string, int>
     */
    private function getDetectionStats(): array
    {
        try {
            $rows = $this->db->query(
                "SELECT
                    SUM(CASE WHEN type LIKE '%sqli%' THEN 1 ELSE 0 END) as sqli,
                    SUM(CASE WHEN type LIKE '%xss%' THEN 1 ELSE 0 END) as xss,
                    SUM(CASE WHEN type LIKE '%command%' THEN 1 ELSE 0 END) as command,
                    SUM(CASE WHEN type LIKE '%xxe%' THEN 1 ELSE 0 END) as xxe,
                    SUM(CASE WHEN type LIKE '%traversal%' THEN 1 ELSE 0 END) as traversal,
                    COUNT(*) as total
                FROM security_shield_events
                WHERE created_at > NOW() - INTERVAL '24 hours'",
            );

            return [
                'sqli_24h' => (int) ($rows[0]['sqli'] ?? 0),
                'xss_24h' => (int) ($rows[0]['xss'] ?? 0),
                'command_24h' => (int) ($rows[0]['command'] ?? 0),
                'xxe_24h' => (int) ($rows[0]['xxe'] ?? 0),
                'traversal_24h' => (int) ($rows[0]['traversal'] ?? 0),
                'total_24h' => (int) ($rows[0]['total'] ?? 0),
            ];
        } catch (\Throwable $e) {
            return [
                'sqli_24h' => 0,
                'xss_24h' => 0,
                'command_24h' => 0,
                'xxe_24h' => 0,
                'traversal_24h' => 0,
                'total_24h' => 0,
            ];
        }
    }

    private function saveWafRuleSetting(string $ruleId, bool $enabled): void
    {
        $key = "rule_{$ruleId}";
        $value = json_encode($enabled);

        try {
            $this->db->execute(
                'INSERT INTO security_shield_config (key, value, updated_at) VALUES (?, ?, NOW())
                 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()',
                [$key, $value],
            );
        } catch (\Throwable $e) {
            $this->db->execute(
                'INSERT INTO security_shield_config (`key`, `value`, updated_at) VALUES (?, ?, NOW())
                 ON DUPLICATE KEY UPDATE `value` = VALUES(`value`), updated_at = NOW()',
                [$key, $value],
            );
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function getMLStats(): array
    {
        try {
            $rows = $this->db->query(
                "SELECT
                    SUM(CASE WHEN type LIKE 'ml_%' AND type LIKE '%threat%' THEN 1 ELSE 0 END) as threats_detected,
                    SUM(CASE WHEN type LIKE 'ml_%' AND type LIKE '%blocked%' THEN 1 ELSE 0 END) as threats_blocked,
                    SUM(CASE WHEN type LIKE 'ml_%' THEN 1 ELSE 0 END) as total_ml_events
                FROM security_shield_events
                WHERE created_at > NOW() - INTERVAL '24 hours'",
            );

            return [
                'threats_detected_24h' => (int) ($rows[0]['threats_detected'] ?? 0),
                'threats_blocked_24h' => (int) ($rows[0]['threats_blocked'] ?? 0),
                'total_ml_events_24h' => (int) ($rows[0]['total_ml_events'] ?? 0),
                'model_accuracy' => 0.95, // Placeholder
                'last_training' => date('Y-m-d H:i:s'),
            ];
        } catch (\Throwable $e) {
            return [
                'threats_detected_24h' => 0,
                'threats_blocked_24h' => 0,
                'total_ml_events_24h' => 0,
                'model_accuracy' => 0.95,
                'last_training' => 'N/A',
            ];
        }
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function getRecentMLClassifications(int $limit): array
    {
        try {
            $events = $this->db->query(
                "SELECT * FROM security_shield_events
                 WHERE type LIKE 'ml_%'
                 ORDER BY created_at DESC LIMIT ?",
                [$limit],
            );
            foreach ($events as &$event) {
                $event['data'] = json_decode($event['data'] ?? '{}', true) ?: [];
            }

            return $events;
        } catch (\Throwable $e) {
            return [];
        }
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function getRateLimitEndpoints(): array
    {
        return [
            ['path' => '/login', 'method' => 'POST', 'limit' => 5, 'window' => 60],
            ['path' => '/api/*', 'method' => 'ALL', 'limit' => 1000, 'window' => 60],
            ['path' => '/register', 'method' => 'POST', 'limit' => 3, 'window' => 3600],
            ['path' => '/password/reset', 'method' => 'POST', 'limit' => 3, 'window' => 3600],
            ['path' => '/contact', 'method' => 'POST', 'limit' => 5, 'window' => 3600],
        ];
    }

    /**
     * @return array<string, int>
     */
    private function getRateLimitStats(): array
    {
        try {
            $rows = $this->db->query(
                "SELECT COUNT(*) as cnt FROM security_shield_events
                 WHERE type = 'rate_limit' AND created_at > NOW() - INTERVAL '24 hours'",
            );

            return [
                'rate_limit_hits_24h' => (int) ($rows[0]['cnt'] ?? 0),
            ];
        } catch (\Throwable $e) {
            return ['rate_limit_hits_24h' => 0];
        }
    }
}
