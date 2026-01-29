<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\AdminIntegration;

use AdosLabs\AdminPanel\Core\AdminModuleInterface;
use AdosLabs\AdminPanel\Database\Pool\DatabasePool;
use AdosLabs\EnterpriseSecurityShield\AdminIntegration\Controllers\SecurityController;
use AdosLabs\EnterpriseSecurityShield\Config\SecurityConfig;
use AdosLabs\EnterpriseSecurityShield\Storage\DatabaseStorage;
use AdosLabs\EnterpriseSecurityShield\Storage\RedisStorage;
use AdosLabs\EnterpriseSecurityShield\Contracts\StorageInterface;
use Psr\Log\LoggerInterface;

/**
 * Security Shield Admin Module
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
        ?DatabasePool $db = null
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
     * Set storage backend
     */
    public function setStorage(StorageInterface $storage): self
    {
        $this->storage = $storage;
        return $this;
    }

    /**
     * Set security configuration
     */
    public function setConfig(SecurityConfig $config): self
    {
        $this->config = $config;
        return $this;
    }

    /**
     * Set database pool for DatabaseStorage
     */
    public function setDatabasePool(DatabasePool $db): self
    {
        $this->db = $db;
        return $this;
    }

    /**
     * Get storage (lazy initialization)
     */
    public function getStorage(): StorageInterface
    {
        if ($this->storage === null) {
            // Try Redis first, fallback to Database
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
                } catch (\Throwable $e) {
                    // Fallback to database
                }
            }

            if ($this->storage === null && $this->db !== null) {
                $this->storage = new DatabaseStorage($this->db);
            }

            if ($this->storage === null) {
                throw new \RuntimeException(
                    'No storage backend available. Configure REDIS_HOST or provide DatabasePool.'
                );
            }
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
        return [
            [
                'label' => 'Security',
                'url' => '/security',
                'icon' => 'shield',
                'priority' => 15,
                'children' => [
                    [
                        'label' => 'Dashboard',
                        'url' => '/security',
                        'icon' => 'chart-bar',
                    ],
                    [
                        'label' => 'IP Management',
                        'url' => '/security/ips',
                        'icon' => 'ban',
                    ],
                    [
                        'label' => 'Events Log',
                        'url' => '/security/events',
                        'icon' => 'list',
                    ],
                    [
                        'label' => 'Configuration',
                        'url' => '/security/config',
                        'icon' => 'cog',
                    ],
                ],
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

        $driver = $this->db->getConfig()->getDriver();
        $migrationPath = dirname(__DIR__, 2) . "/database/migrations/{$driver}";

        if (!is_dir($migrationPath)) {
            $migrationPath = dirname(__DIR__, 2) . '/database/migrations/postgresql';
        }

        // Run migrations
        $migrations = glob($migrationPath . '/*.sql');
        sort($migrations);

        foreach ($migrations as $file) {
            $sql = file_get_contents($file);
            if ($sql !== false) {
                try {
                    $this->db->execute($sql);
                } catch (\Throwable $e) {
                    // Table might already exist
                    error_log("SecurityShield migration warning: " . $e->getMessage());
                }
            }
        }
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
        return dirname(__DIR__) . '/AdminIntegration/Views';
    }

    public function getAssetsPath(): ?string
    {
        return null;
    }
}
