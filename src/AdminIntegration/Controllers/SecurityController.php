<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\AdminIntegration\Controllers;

use AdosLabs\AdminPanel\Controllers\BaseController;
use AdosLabs\AdminPanel\Database\Pool\DatabasePool;
use AdosLabs\AdminPanel\Http\Response;
use AdosLabs\AdminPanel\Services\AuditService;
use AdosLabs\AdminPanel\Services\SessionService;
use AdosLabs\AdminPanel\Core\ModuleRegistry;
use AdosLabs\EnterpriseSecurityShield\Contracts\StorageInterface;
use AdosLabs\EnterpriseSecurityShield\Config\SecurityConfig;
use AdosLabs\EnterpriseSecurityShield\Storage\DatabaseStorage;
use AdosLabs\EnterpriseSecurityShield\Storage\RedisStorage;
use Psr\Log\LoggerInterface;

/**
 * Security Controller
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
    private ?StorageInterface $storage = null;
    private ?SecurityConfig $securityConfig = null;

    public function __construct(
        DatabasePool $db,
        SessionService $sessionService,
        AuditService $auditService,
        ?LoggerInterface $logger = null,
        ?ModuleRegistry $moduleRegistry = null
    ) {
        parent::__construct($db, $sessionService, $auditService, $logger, $moduleRegistry);
    }

    /**
     * Set security storage
     */
    public function setStorage(StorageInterface $storage): void
    {
        $this->storage = $storage;
    }

    /**
     * Set security config
     */
    public function setSecurityConfig(SecurityConfig $config): void
    {
        $this->securityConfig = $config;
    }

    /**
     * Get storage (lazy initialization)
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
                    2.0
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
        $this->storage = new DatabaseStorage($this->db);
        return $this->storage;
    }

    /**
     * Security dashboard
     * GET /security
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
        ]);
    }

    /**
     * IP Management page
     * GET /security/ips
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
        ]);
    }

    /**
     * Ban an IP
     * POST /security/ips/ban
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
     * POST /security/ips/unban
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
     * POST /security/ips/whitelist
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
                [$ip, $note, $this->getUser()['id'] ?? 0]
            );
        } catch (\Throwable $e) {
            // Fallback for MySQL
            $this->db->execute(
                'INSERT INTO security_shield_whitelist (ip, note, created_by, created_at) VALUES (?, ?, ?, NOW()) ON DUPLICATE KEY UPDATE note = VALUES(note)',
                [$ip, $note, $this->getUser()['id'] ?? 0]
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
     * POST /security/ips/whitelist/remove
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
     * Security events log
     * GET /security/events
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
                array_merge($params, [$perPage, $offset])
            );

            // Decode JSON data
            foreach ($events as &$event) {
                $event['data'] = json_decode($event['data'] ?? '{}', true) ?: [];
            }

            // Get total count
            $countRows = $this->db->query(
                "SELECT COUNT(*) as cnt FROM security_shield_events WHERE {$whereClause}",
                $params
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
        ]);
    }

    /**
     * Clear old events
     * POST /security/events/clear
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
            [$cutoff]
        );

        $this->audit('security.events.clear', ['older_than' => $olderThan, 'deleted' => $deleted]);

        return $this->withFlash('success', "Deleted {$deleted} events older than {$olderThan}", $this->adminUrl('security/events'));
    }

    /**
     * Configuration page
     * GET /security/config
     */
    public function config(): Response
    {
        $config = $this->loadConfig();

        return $this->view('security/config', [
            'config' => $config,
            'page_title' => 'Security Configuration',
        ]);
    }

    /**
     * Save configuration
     * POST /security/config/save
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
    // API ENDPOINTS
    // =========================================================================

    /**
     * API: Get security statistics
     * GET /security/api/stats
     */
    public function apiStats(): Response
    {
        return $this->json($this->getSecurityStats());
    }

    /**
     * API: Get recent threats
     * GET /security/api/recent-threats
     */
    public function apiRecentThreats(): Response
    {
        $query = $this->getQuery();
        $limit = min(100, max(1, (int) ($query['limit'] ?? 20)));

        return $this->json($this->getRecentThreats($limit));
    }

    /**
     * API: Get IP score
     * GET /security/api/ip-score?ip=x.x.x.x
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
                [$today]
            );

            $stats = $rows[0] ?? [];

            // Active bans count
            $banRows = $this->db->query(
                "SELECT COUNT(*) as cnt FROM security_shield_bans WHERE expires_at > NOW()"
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
                "SELECT * FROM security_shield_events ORDER BY created_at DESC LIMIT ?",
                [$limit]
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
                "SELECT * FROM security_shield_bans WHERE expires_at > NOW() ORDER BY banned_at DESC LIMIT ?",
                [$limit]
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
                LIMIT 10"
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
                array_merge($params, [$perPage, $offset])
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
                $params
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
                "SELECT * FROM security_shield_whitelist ORDER BY created_at DESC"
            );
        } catch (\Throwable $e) {
            return [];
        }
    }

    private function getDistinctEventTypes(): array
    {
        try {
            $rows = $this->db->query(
                "SELECT DISTINCT type FROM security_shield_events ORDER BY type"
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
                "SELECT key, value FROM security_shield_config"
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
                    "INSERT INTO security_shield_config (key, value, updated_at) VALUES (?, ?, NOW())
                     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
                    [$key, $jsonValue]
                );
            } catch (\Throwable $e) {
                // Fallback for MySQL
                $this->db->execute(
                    "INSERT INTO security_shield_config (`key`, `value`, updated_at) VALUES (?, ?, NOW())
                     ON DUPLICATE KEY UPDATE `value` = VALUES(`value`), updated_at = NOW()",
                    [$key, $jsonValue]
                );
            }
        }
    }
}
