<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\AdminIntegration;

use AdosLabs\AdminPanel\Core\AdminModuleInterface;
use AdosLabs\AdminPanel\Database\Pool\DatabasePool;
use AdosLabs\EnterpriseSecurityShield\AdminIntegration\Controllers\SecurityController;
use AdosLabs\EnterpriseSecurityShield\Config\SecurityConfig;
use AdosLabs\EnterpriseSecurityShield\Contracts\StorageInterface;
use AdosLabs\EnterpriseSecurityShield\Storage\DatabaseStorage;
use AdosLabs\EnterpriseSecurityShield\Storage\RedisStorage;
use Psr\Log\LoggerInterface;

/**
 * Security Shield Admin Module.
 *
 * Integrates Enterprise Security Shield with Enterprise Admin Panel.
 *
 * FEATURES:
 * - Security dashboard with threat statistics
 * - IP management (ban/unban/whitelist/blacklist)
 * - Real-time threat monitoring
 * - Configuration management
 * - Security event logs
 * - Rate limiting settings
 * - Honeypot statistics
 *
 * @version 1.0.0
 */
final class SecurityShieldAdminModule implements AdminModuleInterface
{
    private ?StorageInterface $storage = null;

    private ?SecurityConfig $config = null;

    private ?DatabasePool $db = null;

    private ?LoggerInterface $logger = null;

    /**
     * Constructor compatible with ModuleRegistry auto-instantiation.
     *
     * ModuleRegistry calls: new $moduleClass($db, $logger)
     * So we accept DatabasePool as first param, LoggerInterface as second.
     *
     * @param DatabasePool|StorageInterface|null $dbOrStorage DatabasePool (from ModuleRegistry) or StorageInterface (manual setup)
     * @param \Psr\Log\LoggerInterface|SecurityConfig|null $loggerOrConfig LoggerInterface (from ModuleRegistry) or SecurityConfig (manual setup)
     * @param DatabasePool|null $db DatabasePool (only for manual setup with 3 params)
     */
    public function __construct(
        DatabasePool|StorageInterface|null $dbOrStorage = null,
        LoggerInterface|SecurityConfig|null $loggerOrConfig = null,
        ?DatabasePool $db = null,
    ) {
        // Handle ModuleRegistry signature: new Module($db, $logger)
        if ($dbOrStorage instanceof DatabasePool) {
            $this->db = $dbOrStorage;
            if ($loggerOrConfig instanceof LoggerInterface) {
                $this->logger = $loggerOrConfig;
            }
        }
        // Handle manual signature: new Module($storage, $config, $db)
        elseif ($dbOrStorage instanceof StorageInterface) {
            $this->storage = $dbOrStorage;
            if ($loggerOrConfig instanceof SecurityConfig) {
                $this->config = $loggerOrConfig;
            }
            $this->db = $db;
        }
    }

    /**
     * Set storage backend.
     */
    public function setStorage(StorageInterface $storage): self
    {
        $this->storage = $storage;

        return $this;
    }

    /**
     * Set security configuration.
     */
    public function setConfig(SecurityConfig $config): self
    {
        $this->config = $config;

        return $this;
    }

    /**
     * Set database pool for DatabaseStorage.
     */
    public function setDatabasePool(DatabasePool $db): self
    {
        $this->db = $db;

        return $this;
    }

    /**
     * Get storage (lazy initialization).
     *
     * Returns null if no storage backend is available.
     * This allows the module to be instantiated for admin panel
     * registration even without a working storage backend.
     */
    public function getStorage(): ?StorageInterface
    {
        if ($this->storage === null) {
            // Try Redis first, fallback to Database
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
                } catch (\Throwable $e) {
                    // Fallback to database
                }
            }

            if ($this->storage === null && $this->db !== null) {
                $this->storage = new DatabaseStorage($this->db);
            }

            // Don't throw - return null and let caller handle gracefully
        }

        return $this->storage;
    }

    public function getName(): string
    {
        return 'Security Shield';
    }

    public function getDescription(): string
    {
        return 'Enterprise WAF with honeypot detection, rate limiting, IP management, and threat monitoring';
    }

    public function getVersion(): string
    {
        return '1.0.0';
    }

    public function getTabs(): array
    {
        // NOTE: Admin panel sidebar expects FLAT tabs, not nested children
        // Each tab is a separate entry in the sidebar under the module section
        return [
            [
                'label' => 'WAF Dashboard',
                'url' => '/security',
                'icon' => 'shield',
                'priority' => 15,
            ],
            [
                'label' => 'WAF Rules',
                'url' => '/security/waf',
                'icon' => 'shield',
                'priority' => 16,
            ],
            [
                'label' => 'ML Threats',
                'url' => '/security/ml',
                'icon' => 'activity',
                'priority' => 17,
            ],
            [
                'label' => 'Rate Limiting',
                'url' => '/security/ratelimit',
                'icon' => 'activity',
                'priority' => 18,
            ],
            [
                'label' => 'IP Management',
                'url' => '/security/ips',
                'icon' => 'shield',
                'priority' => 19,
            ],
            [
                'label' => 'Security Events',
                'url' => '/security/events',
                'icon' => 'file-text',
                'priority' => 20,
            ],
            [
                'label' => 'WAF Config',
                'url' => '/security/config',
                'icon' => 'database',
                'priority' => 21,
            ],
        ];
    }

    public function getRoutes(): array
    {
        return [
            // Dashboard
            [
                'method' => 'GET',
                'path' => '/security',
                'handler' => [SecurityController::class, 'dashboard'],
            ],

            // IP Management
            [
                'method' => 'GET',
                'path' => '/security/ips',
                'handler' => [SecurityController::class, 'ipManagement'],
            ],
            [
                'method' => 'POST',
                'path' => '/security/ips/ban',
                'handler' => [SecurityController::class, 'banIp'],
            ],
            [
                'method' => 'POST',
                'path' => '/security/ips/unban',
                'handler' => [SecurityController::class, 'unbanIp'],
            ],
            [
                'method' => 'POST',
                'path' => '/security/ips/whitelist',
                'handler' => [SecurityController::class, 'addToWhitelist'],
            ],
            [
                'method' => 'POST',
                'path' => '/security/ips/whitelist/remove',
                'handler' => [SecurityController::class, 'removeFromWhitelist'],
            ],

            // Events Log
            [
                'method' => 'GET',
                'path' => '/security/events',
                'handler' => [SecurityController::class, 'events'],
            ],
            [
                'method' => 'POST',
                'path' => '/security/events/clear',
                'handler' => [SecurityController::class, 'clearEvents'],
            ],

            // Configuration
            [
                'method' => 'GET',
                'path' => '/security/config',
                'handler' => [SecurityController::class, 'config'],
            ],
            [
                'method' => 'POST',
                'path' => '/security/config/save',
                'handler' => [SecurityController::class, 'saveConfig'],
            ],

            // WAF Rules
            [
                'method' => 'GET',
                'path' => '/security/waf',
                'handler' => [SecurityController::class, 'wafRules'],
            ],
            [
                'method' => 'POST',
                'path' => '/security/waf/toggle',
                'handler' => [SecurityController::class, 'toggleWafRule'],
            ],

            // ML Threats
            [
                'method' => 'GET',
                'path' => '/security/ml',
                'handler' => [SecurityController::class, 'mlThreats'],
            ],
            [
                'method' => 'POST',
                'path' => '/security/ml/retrain',
                'handler' => [SecurityController::class, 'retrainModel'],
            ],

            // Rate Limiting
            [
                'method' => 'GET',
                'path' => '/security/ratelimit',
                'handler' => [SecurityController::class, 'rateLimiting'],
            ],
            [
                'method' => 'POST',
                'path' => '/security/ratelimit/save',
                'handler' => [SecurityController::class, 'saveRateLimits'],
            ],

            // API endpoints for AJAX
            [
                'method' => 'GET',
                'path' => '/security/api/stats',
                'handler' => [SecurityController::class, 'apiStats'],
            ],
            [
                'method' => 'GET',
                'path' => '/security/api/recent-threats',
                'handler' => [SecurityController::class, 'apiRecentThreats'],
            ],
            [
                'method' => 'GET',
                'path' => '/security/api/ip-score',
                'handler' => [SecurityController::class, 'apiIpScore'],
            ],
        ];
    }

    public function install(): void
    {
        if ($this->db === null) {
            return;
        }

        // Determine database driver
        $driver = 'postgresql';

        try {
            $driverMethod = method_exists($this->db, 'getConfig')
                ? $this->db->getConfig()->getDriver()
                : 'postgresql';
            $driver = strtolower($driverMethod);
            if (str_contains($driver, 'mysql') || str_contains($driver, 'mariadb')) {
                $driver = 'mysql';
            } else {
                $driver = 'postgresql';
            }
        } catch (\Throwable $e) {
            $driver = 'postgresql';
        }

        // Find migrations directory
        $migrationPath = dirname(__DIR__, 2) . "/database/migrations/{$driver}";

        if (!is_dir($migrationPath)) {
            $migrationPath = dirname(__DIR__, 2) . '/database/migrations/postgresql';
        }

        if (!is_dir($migrationPath)) {
            if ($this->logger) {
                $this->logger->warning('SecurityShield: No migrations found', [
                    'path' => $migrationPath,
                ]);
            }

            return;
        }

        // Run migrations
        $migrations = glob($migrationPath . '/*.sql');
        if ($migrations === false) {
            return;
        }
        sort($migrations);

        foreach ($migrations as $file) {
            $sql = file_get_contents($file);
            if ($sql === false) {
                continue;
            }

            // Split SQL into individual statements (handle MySQL DELIMITER)
            $statements = $this->parseSqlStatements($sql);

            foreach ($statements as $statement) {
                $statement = trim($statement);
                if (empty($statement)) {
                    continue;
                }

                try {
                    $this->db->execute($statement);
                } catch (\Throwable $e) {
                    // Table might already exist - this is OK
                    if ($this->logger) {
                        $this->logger->debug('SecurityShield migration notice', [
                            'file' => basename($file),
                            'message' => $e->getMessage(),
                        ]);
                    }
                }
            }
        }

        if ($this->logger) {
            $this->logger->info('SecurityShield: Database migrations completed');
        }
    }

    /**
     * Parse SQL file into individual statements.
     *
     * @param string $sql
     *
     * @return array<string>
     */
    private function parseSqlStatements(string $sql): array
    {
        // Remove DELIMITER statements and handle MySQL stored procedures
        $sql = preg_replace('/DELIMITER\s+\/\/.*?\/\/\s*DELIMITER\s*;/s', '', $sql);
        $sql = preg_replace('/DELIMITER\s+[^\s]+/', '', $sql);

        // Split by semicolon (but not inside strings or comments)
        $statements = [];
        $current = '';
        $inString = false;
        $stringChar = '';
        $length = strlen($sql);

        for ($i = 0; $i < $length; $i++) {
            $char = $sql[$i];

            // Track string state
            if (!$inString && ($char === '"' || $char === "'")) {
                $inString = true;
                $stringChar = $char;
            } elseif ($inString && $char === $stringChar && ($i === 0 || $sql[$i - 1] !== '\\')) {
                $inString = false;
            }

            // Check for statement end
            if (!$inString && $char === ';') {
                $statements[] = trim($current);
                $current = '';
            } else {
                $current .= $char;
            }
        }

        if (trim($current) !== '') {
            $statements[] = trim($current);
        }

        return array_filter($statements, fn ($s) => !empty(trim($s)));
    }

    public function uninstall(): void
    {
        // Note: We do NOT drop tables to preserve security logs
        // Admin can manually drop tables if needed
    }

    public function getConfigSchema(): array
    {
        return [
            [
                'key' => 'score_threshold',
                'label' => 'Score Threshold',
                'type' => 'number',
                'default' => 50,
                'description' => 'IP score threshold for automatic ban (1-1000)',
            ],
            [
                'key' => 'ban_duration',
                'label' => 'Ban Duration (seconds)',
                'type' => 'number',
                'default' => 86400,
                'description' => 'How long to ban IPs (86400 = 24 hours)',
            ],
            [
                'key' => 'rate_limit_max',
                'label' => 'Rate Limit (requests)',
                'type' => 'number',
                'default' => 100,
                'description' => 'Maximum requests per window',
            ],
            [
                'key' => 'rate_limit_window',
                'label' => 'Rate Limit Window (seconds)',
                'type' => 'number',
                'default' => 60,
                'description' => 'Time window for rate limiting',
            ],
            [
                'key' => 'honeypot_enabled',
                'label' => 'Enable Honeypot',
                'type' => 'boolean',
                'default' => true,
                'description' => 'Trap endpoints for scanner detection',
            ],
            [
                'key' => 'bot_verification_enabled',
                'label' => 'Enable Bot Verification',
                'type' => 'boolean',
                'default' => true,
                'description' => 'Verify legitimate bots via DNS',
            ],
            [
                'key' => 'fail_closed',
                'label' => 'Fail Closed Mode',
                'type' => 'boolean',
                'default' => false,
                'description' => 'Block all traffic if storage is down (high security mode)',
            ],
        ];
    }

    public function getDependencies(): array
    {
        return [];
    }

    public function getPermissions(): array
    {
        return [
            'security.view',
            'security.manage_ips',
            'security.view_events',
            'security.configure',
        ];
    }

    public function getViewsPath(): ?string
    {
        // __DIR__ = .../src/AdminIntegration
        // Views are at .../src/AdminIntegration/Views
        return __DIR__ . '/Views';
    }

    public function getAssetsPath(): ?string
    {
        return dirname(__DIR__, 2) . '/assets';
    }
}
