<?php

namespace App\Http\Middleware;

use Senza1dio\SecurityShield\Config\SecurityConfig;
use Senza1dio\SecurityShield\Middleware\WafMiddleware;
use Senza1dio\SecurityShield\Middleware\HoneypotMiddleware;
use Senza1dio\SecurityShield\Storage\RedisStorage;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

/**
 * Laravel Security Shield Middleware
 *
 * Integrates Enterprise Security Shield with Laravel.
 *
 * Installation:
 * 1. Copy this file to app/Http/Middleware/SecurityShieldMiddleware.php
 * 2. Register in app/Http/Kernel.php:
 *    protected $middleware = [
 *        \App\Http\Middleware\SecurityShieldMiddleware::class,
 *    ];
 * 3. Configure in config/security-shield.php (see config.php example)
 */
class SecurityShieldMiddleware
{
    private SecurityConfig $config;
    private WafMiddleware $waf;
    private HoneypotMiddleware $honeypot;

    public function __construct()
    {
        // Initialize storage backend
        $storage = $this->createStorage();

        // Create SecurityConfig from Laravel config
        $this->config = SecurityConfig::fromArray([
            'score_threshold' => config('security-shield.score_threshold', 50),
            'ban_duration' => config('security-shield.ban_duration', 86400),
            'tracking_window' => config('security-shield.tracking_window', 3600),
            'honeypot_ban_duration' => config('security-shield.honeypot_ban_duration', 604800),
            'honeypot_enabled' => config('security-shield.honeypot_enabled', true),
            'bot_verification_enabled' => config('security-shield.bot_verification_enabled', true),
            'bot_cache_ttl' => config('security-shield.bot_cache_ttl', 604800),
            'ip_whitelist' => config('security-shield.ip_whitelist', []),
            'ip_blacklist' => config('security-shield.ip_blacklist', []),
            'intelligence_enabled' => config('security-shield.intelligence_enabled', true),
            'alerts_enabled' => config('security-shield.alerts_enabled', false),
            'alert_webhook' => config('security-shield.alert_webhook'),
            'environment' => config('security-shield.environment', 'production'),
            'storage' => $storage,
            'logger' => new LaravelLoggerAdapter(),
        ]);

        // Create WAF and Honeypot middlewares
        $this->waf = new WafMiddleware($this->config);
        $this->honeypot = new HoneypotMiddleware(
            $this->config,
            config('security-shield.honeypot_paths', [])
        );
    }

    /**
     * Handle an incoming request
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Convert Laravel Request to array format
        $server = $request->server->all();
        $get = $request->query->all();
        $post = $request->request->all();

        // Check honeypot FIRST (instant ban + fake response)
        if ($this->config->isHoneypotEnabled()) {
            $path = $request->getPathInfo();

            if ($this->honeypot->isHoneypotPath($path)) {
                // Log honeypot access
                Log::channel('security')->warning('Honeypot accessed', [
                    'ip' => $request->ip(),
                    'path' => $path,
                    'user_agent' => $request->userAgent(),
                ]);

                // Ban and send fake response
                $this->honeypot->handle($server, $get, $post);
                exit; // Never reached - middleware exits
            }
        }

        // Check WAF security rules
        if (!$this->waf->handle($server, $get, $post)) {
            // Request blocked - log and return 403
            Log::channel('security')->warning('WAF blocked request', [
                'ip' => $request->ip(),
                'path' => $request->getPathInfo(),
                'reason' => $this->waf->getBlockReason(),
                'score' => $this->waf->getThreatScore(),
                'user_agent' => $request->userAgent(),
            ]);

            return response()->json([
                'error' => 'Access Denied',
                'reason' => $this->waf->getBlockReason(),
                'timestamp' => time(),
            ], 403);
        }

        // Request allowed - continue
        return $next($request);
    }

    /**
     * Create storage backend based on config
     */
    private function createStorage(): \Senza1dio\SecurityShield\Contracts\StorageInterface
    {
        $storageType = config('security-shield.storage', 'redis');

        switch ($storageType) {
            case 'redis':
                $connectionName = config('security-shield.redis_connection', 'default');
                $redis = Redis::connection($connectionName)->client();
                $keyPrefix = config('security-shield.redis_key_prefix', 'security_shield:');
                return new RedisStorage($redis, $keyPrefix);

            case 'memory':
                return new \Senza1dio\SecurityShield\Storage\NullStorage();

            default:
                throw new \InvalidArgumentException("Unsupported storage type: {$storageType}");
        }
    }
}

/**
 * Laravel Logger Adapter - PSR-3 Compatible
 */
class LaravelLoggerAdapter implements \Senza1dio\SecurityShield\Contracts\LoggerInterface
{
    public function emergency(string $message, array $context = []): void
    {
        Log::channel('security')->emergency($message, $context);
    }

    public function critical(string $message, array $context = []): void
    {
        Log::channel('security')->critical($message, $context);
    }

    public function error(string $message, array $context = []): void
    {
        Log::channel('security')->error($message, $context);
    }

    public function warning(string $message, array $context = []): void
    {
        Log::channel('security')->warning($message, $context);
    }

    public function info(string $message, array $context = []): void
    {
        Log::channel('security')->info($message, $context);
    }

    public function debug(string $message, array $context = []): void
    {
        Log::channel('security')->debug($message, $context);
    }
}
