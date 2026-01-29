<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\RateLimiting;

use AdosLabs\EnterpriseSecurityShield\Contracts\StorageInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Per-Endpoint Rate Limiter Middleware (PSR-15).
 *
 * Enterprise-grade rate limiting with per-endpoint configuration.
 *
 * FEATURES:
 * 1. Different limits for different endpoints
 * 2. Pattern-based endpoint matching (regex, wildcard, exact)
 * 3. Multiple rate limit tiers (IP, user, API key)
 * 4. Dynamic rate limits based on user tier
 * 5. Burst allowance for specific endpoints
 * 6. Cost-based rate limiting (expensive operations cost more)
 * 7. Standard rate limit headers (X-RateLimit-*)
 *
 * ENDPOINT CONFIGURATION:
 * ```php
 * [
 *     'path' => '/api/login',
 *     'methods' => ['POST'],
 *     'limits' => [
 *         'ip' => ['requests' => 5, 'window' => 60],     // 5 per minute per IP
 *         'user' => ['requests' => 10, 'window' => 60],  // 10 per minute per user
 *     ],
 *     'cost' => 1,
 *     'burst' => 2,
 * ]
 * ```
 *
 * @version 1.0.0
 */
final class EndpointRateLimiter implements MiddlewareInterface
{
    private StorageInterface $storage;

    private LoggerInterface $logger;

    /**
     * Global default limits.
     *
     * @var array{requests: int, window: int}
     */
    private array $defaultLimits = [
        'requests' => 100,
        'window' => 60,
    ];

    /**
     * Endpoint-specific configurations.
     *
     * @var array<int, array{
     *     path: string,
     *     pattern?: string,
     *     methods?: array<string>,
     *     limits: array<string, array{requests: int, window: int, algorithm?: string}>,
     *     cost?: int,
     *     burst?: int,
     *     skip_conditions?: array<string, mixed>,
     *     key_generator?: callable
     * }>
     */
    private array $endpoints = [];

    /**
     * User tier configurations (premium users get higher limits).
     *
     * @var array<string, float>
     */
    private array $tierMultipliers = [
        'free' => 1.0,
        'basic' => 2.0,
        'premium' => 5.0,
        'enterprise' => 10.0,
        'unlimited' => PHP_FLOAT_MAX,
    ];

    /**
     * Request attribute for user tier.
     */
    private string $tierAttribute = 'user.tier';

    /**
     * Request attribute for user ID.
     */
    private string $userIdAttribute = 'user.id';

    /**
     * Request attribute for API key.
     */
    private string $apiKeyAttribute = 'api.key';

    /**
     * Excluded IPs (trusted, not rate limited).
     *
     * @var array<string>
     */
    private array $trustedIPs = [];

    /**
     * Excluded paths.
     *
     * @var array<string>
     */
    private array $excludedPaths = [];

    /**
     * Rate limiters cache.
     *
     * @var array<string, RateLimiter>
     */
    private array $limiters = [];

    /**
     * Response factory.
     *
     * @var callable|null
     */
    private $responseFactory = null;

    /**
     * Enable rate limit headers.
     */
    private bool $includeHeaders = true;

    /**
     * @param array{
     *     default_limits?: array{requests?: int, window?: int},
     *     endpoints?: array,
     *     tier_multipliers?: array<string, float>,
     *     tier_attribute?: string,
     *     user_id_attribute?: string,
     *     api_key_attribute?: string,
     *     trusted_ips?: array<string>,
     *     excluded_paths?: array<string>,
     *     include_headers?: bool,
     *     response_factory?: callable
     * } $config
     */
    public function __construct(
        StorageInterface $storage,
        array $config = [],
        ?LoggerInterface $logger = null,
    ) {
        $this->storage = $storage;
        $this->logger = $logger ?? new NullLogger();

        // Apply configuration
        if (isset($config['default_limits'])) {
            $this->defaultLimits = array_merge($this->defaultLimits, $config['default_limits']);
        }
        if (isset($config['endpoints'])) {
            $this->endpoints = $config['endpoints'];
        }
        if (isset($config['tier_multipliers'])) {
            $this->tierMultipliers = array_merge($this->tierMultipliers, $config['tier_multipliers']);
        }
        if (isset($config['tier_attribute'])) {
            $this->tierAttribute = $config['tier_attribute'];
        }
        if (isset($config['user_id_attribute'])) {
            $this->userIdAttribute = $config['user_id_attribute'];
        }
        if (isset($config['api_key_attribute'])) {
            $this->apiKeyAttribute = $config['api_key_attribute'];
        }
        if (isset($config['trusted_ips'])) {
            $this->trustedIPs = $config['trusted_ips'];
        }
        if (isset($config['excluded_paths'])) {
            $this->excludedPaths = $config['excluded_paths'];
        }
        if (isset($config['include_headers'])) {
            $this->includeHeaders = $config['include_headers'];
        }
        if (isset($config['response_factory'])) {
            $this->responseFactory = $config['response_factory'];
        }
    }

    /**
     * Add endpoint configuration.
     *
     * @param array{
     *     path: string,
     *     pattern?: string,
     *     methods?: array<string>,
     *     limits: array<string, array{requests: int, window: int, algorithm?: string}>,
     *     cost?: int,
     *     burst?: int
     * } $config
     */
    public function addEndpoint(array $config): self
    {
        $this->endpoints[] = $config;

        return $this;
    }

    /**
     * Configure login endpoint with strict limits.
     */
    public function protectLogin(string $path = '/login', int $attemptsPerMinute = 5): self
    {
        return $this->addEndpoint([
            'path' => $path,
            'methods' => ['POST'],
            'limits' => [
                'ip' => ['requests' => $attemptsPerMinute, 'window' => 60],
                'user' => ['requests' => $attemptsPerMinute * 2, 'window' => 60],
            ],
            'cost' => 3, // Login attempts are expensive
        ]);
    }

    /**
     * Configure API endpoint.
     */
    public function protectAPI(string $pattern = '/api/*', int $requestsPerMinute = 60): self
    {
        return $this->addEndpoint([
            'pattern' => $this->wildcardToRegex($pattern),
            'limits' => [
                'api_key' => ['requests' => $requestsPerMinute, 'window' => 60],
                'ip' => ['requests' => $requestsPerMinute / 2, 'window' => 60],
            ],
        ]);
    }

    /**
     * Configure expensive operation.
     */
    public function protectExpensiveOperation(string $path, int $requestsPerHour = 10): self
    {
        return $this->addEndpoint([
            'path' => $path,
            'limits' => [
                'user' => ['requests' => $requestsPerHour, 'window' => 3600],
                'ip' => ['requests' => $requestsPerHour / 2, 'window' => 3600],
            ],
            'cost' => 10,
        ]);
    }

    /**
     * Set trusted IPs (bypasses rate limiting).
     *
     * @param array<string> $ips
     */
    public function setTrustedIPs(array $ips): self
    {
        $this->trustedIPs = $ips;

        return $this;
    }

    /**
     * Set tier multipliers.
     *
     * @param array<string, float> $multipliers
     */
    public function setTierMultipliers(array $multipliers): self
    {
        $this->tierMultipliers = array_merge($this->tierMultipliers, $multipliers);

        return $this;
    }

    /**
     * Process request.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $path = $request->getUri()->getPath();
        $method = $request->getMethod();
        $ip = $this->getClientIP($request);

        // Skip trusted IPs
        if (in_array($ip, $this->trustedIPs, true)) {
            return $handler->handle($request);
        }

        // Skip excluded paths
        foreach ($this->excludedPaths as $excludedPath) {
            if (str_starts_with($path, $excludedPath)) {
                return $handler->handle($request);
            }
        }

        // Find matching endpoint configuration
        $endpointConfig = $this->findEndpointConfig($path, $method);

        // Get identifiers
        $identifiers = $this->getIdentifiers($request, $ip);

        // Get user tier for limit multiplier
        $tier = $request->getAttribute($this->tierAttribute, 'free');
        $multiplier = $this->tierMultipliers[$tier] ?? 1.0;

        // Apply rate limits
        $results = [];
        $limits = $endpointConfig['limits'] ?? ['ip' => $this->defaultLimits];
        $cost = $endpointConfig['cost'] ?? 1;

        foreach ($limits as $type => $limitConfig) {
            if (!isset($identifiers[$type])) {
                continue;
            }

            $identifier = $identifiers[$type];
            $limiter = $this->getLimiter($path, $type, $limitConfig, $multiplier);

            $result = $limiter->attempt($identifier, $cost);
            $results[$type] = $result;

            if (!$result->allowed) {
                $this->logger->warning('Rate limit exceeded', [
                    'path' => $path,
                    'method' => $method,
                    'type' => $type,
                    'identifier' => $this->maskIdentifier($identifier),
                    'limit' => $result->limit,
                    'remaining' => $result->remaining,
                    'retry_after' => $result->retryAfter,
                ]);

                return $this->createRateLimitResponse($result, $type);
            }
        }

        // Continue with request
        $response = $handler->handle($request);

        // Add rate limit headers
        if ($this->includeHeaders && !empty($results)) {
            $response = $this->addRateLimitHeaders($response, $results);
        }

        return $response;
    }

    /**
     * Find endpoint configuration matching path and method.
     *
     * @return array<string, mixed>
     */
    private function findEndpointConfig(string $path, string $method): array
    {
        foreach ($this->endpoints as $config) {
            // Check method
            if (isset($config['methods']) && !in_array($method, $config['methods'], true)) {
                continue;
            }

            // Check exact path
            if (isset($config['path']) && $config['path'] === $path) {
                return $config;
            }

            // Check pattern
            if (isset($config['pattern']) && preg_match($config['pattern'], $path)) {
                return $config;
            }

            // Check prefix match for paths ending with *
            if (isset($config['path']) && str_ends_with($config['path'], '*')) {
                $prefix = rtrim($config['path'], '*');
                if (str_starts_with($path, $prefix)) {
                    return $config;
                }
            }
        }

        // Return default configuration
        return [
            'limits' => ['ip' => $this->defaultLimits],
        ];
    }

    /**
     * Get identifiers from request.
     *
     * @return array<string, string>
     */
    private function getIdentifiers(ServerRequestInterface $request, string $ip): array
    {
        $identifiers = ['ip' => $ip];

        // User ID
        $userId = $request->getAttribute($this->userIdAttribute);
        if ($userId !== null) {
            $identifiers['user'] = (string) $userId;
        }

        // API Key
        $apiKey = $request->getAttribute($this->apiKeyAttribute);
        if ($apiKey === null) {
            $apiKey = $request->getHeaderLine('X-API-Key');
        }
        if (!empty($apiKey)) {
            $identifiers['api_key'] = $apiKey;
        }

        return $identifiers;
    }

    /**
     * Get or create rate limiter for endpoint/type.
     *
     * @param array{requests: int, window: int, algorithm?: string} $config
     */
    private function getLimiter(string $path, string $type, array $config, float $multiplier): RateLimiter
    {
        $key = md5($path . ':' . $type . ':' . json_encode($config));

        if (!isset($this->limiters[$key])) {
            $requests = (int) ($config['requests'] * $multiplier);
            $window = $config['window'];
            $algorithm = $config['algorithm'] ?? 'sliding_window';
            $prefix = "rate_limit:endpoint:{$type}:";

            $this->limiters[$key] = match ($algorithm) {
                'token_bucket' => RateLimiter::tokenBucket($this->storage, $requests, $requests / $window, $prefix),
                'leaky_bucket' => RateLimiter::leakyBucket($this->storage, $requests, $requests / $window, $prefix),
                'fixed_window' => RateLimiter::fixedWindow($this->storage, $requests, $window, $prefix),
                default => RateLimiter::slidingWindow($this->storage, $requests, $window, $prefix),
            };
        }

        return $this->limiters[$key];
    }

    /**
     * Create rate limit exceeded response.
     */
    private function createRateLimitResponse(RateLimitResult $result, string $type): ResponseInterface
    {
        if ($this->responseFactory !== null) {
            return ($this->responseFactory)($result, $type);
        }

        $responseClass = class_exists(\Nyholm\Psr7\Response::class)
            ? \Nyholm\Psr7\Response::class
            : (class_exists(\GuzzleHttp\Psr7\Response::class)
                ? \GuzzleHttp\Psr7\Response::class
                : null);

        if ($responseClass === null) {
            throw new \RuntimeException('No PSR-7 response implementation available');
        }

        $body = json_encode([
            'error' => 'Too Many Requests',
            'message' => 'Rate limit exceeded. Please try again later.',
            'retry_after' => $result->retryAfter,
        ]);

        $headers = [
            'Content-Type' => 'application/json',
            'Retry-After' => (string) $result->retryAfter,
            'X-RateLimit-Limit' => (string) $result->limit,
            'X-RateLimit-Remaining' => '0',
            'X-RateLimit-Reset' => (string) $result->resetAt,
        ];

        return new $responseClass(429, $headers, $body);
    }

    /**
     * Add rate limit headers to response.
     *
     * @param array<string, RateLimitResult> $results
     */
    private function addRateLimitHeaders(ResponseInterface $response, array $results): ResponseInterface
    {
        // Use the most restrictive result
        $minRemaining = PHP_INT_MAX;
        $limit = 0;
        $resetAt = 0;

        foreach ($results as $result) {
            if ($result->remaining < $minRemaining) {
                $minRemaining = $result->remaining;
                $limit = $result->limit;
                $resetAt = $result->resetAt;
            }
        }

        return $response
            ->withHeader('X-RateLimit-Limit', (string) $limit)
            ->withHeader('X-RateLimit-Remaining', (string) $minRemaining)
            ->withHeader('X-RateLimit-Reset', (string) $resetAt);
    }

    /**
     * Get client IP from request.
     */
    private function getClientIP(ServerRequestInterface $request): string
    {
        $headers = ['X-Forwarded-For', 'X-Real-IP', 'CF-Connecting-IP'];

        foreach ($headers as $header) {
            $value = $request->getHeaderLine($header);
            if (!empty($value)) {
                $ips = explode(',', $value);

                return trim($ips[0]);
            }
        }

        $serverParams = $request->getServerParams();

        return $serverParams['REMOTE_ADDR'] ?? 'unknown';
    }

    /**
     * Convert wildcard pattern to regex.
     */
    private function wildcardToRegex(string $pattern): string
    {
        $regex = preg_quote($pattern, '/');
        $regex = str_replace('\*', '.*', $regex);

        return '/^' . $regex . '$/';
    }

    /**
     * Mask identifier for logging.
     */
    private function maskIdentifier(string $identifier): string
    {
        if (filter_var($identifier, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return preg_replace('/\.\d+$/', '.xxx', $identifier) ?? $identifier;
        }

        $len = strlen($identifier);
        if ($len <= 4) {
            return str_repeat('*', $len);
        }

        return $identifier[0] . str_repeat('*', min(8, $len - 2)) . $identifier[$len - 1];
    }

    /**
     * Create common presets.
     */

    /**
     * Create for API with standard tiers.
     */
    public static function forAPI(StorageInterface $storage, ?LoggerInterface $logger = null): self
    {
        return new self($storage, [
            'default_limits' => ['requests' => 60, 'window' => 60],
            'tier_multipliers' => [
                'free' => 1.0,
                'developer' => 3.0,
                'business' => 10.0,
                'enterprise' => 50.0,
            ],
            'endpoints' => [
                [
                    'pattern' => '/api/v[0-9]+/.*',
                    'limits' => [
                        'api_key' => ['requests' => 1000, 'window' => 60],
                        'ip' => ['requests' => 100, 'window' => 60],
                    ],
                ],
            ],
        ], $logger);
    }

    /**
     * Create for web application with login protection.
     */
    public static function forWebApp(StorageInterface $storage, ?LoggerInterface $logger = null): self
    {
        $limiter = new self($storage, [
            'default_limits' => ['requests' => 120, 'window' => 60],
        ], $logger);

        return $limiter
            ->protectLogin('/login', 5)
            ->protectLogin('/wp-login.php', 3)
            ->addEndpoint([
                'path' => '/register',
                'methods' => ['POST'],
                'limits' => [
                    'ip' => ['requests' => 3, 'window' => 3600],
                ],
            ])
            ->addEndpoint([
                'path' => '/password/reset',
                'methods' => ['POST'],
                'limits' => [
                    'ip' => ['requests' => 3, 'window' => 3600],
                ],
            ])
            ->addEndpoint([
                'path' => '/contact',
                'methods' => ['POST'],
                'limits' => [
                    'ip' => ['requests' => 5, 'window' => 3600],
                ],
            ]);
    }

    /**
     * Create strict configuration for admin endpoints.
     */
    public static function forAdmin(StorageInterface $storage, ?LoggerInterface $logger = null): self
    {
        return new self($storage, [
            'default_limits' => ['requests' => 30, 'window' => 60],
            'endpoints' => [
                [
                    'pattern' => '/admin/.*',
                    'limits' => [
                        'ip' => ['requests' => 30, 'window' => 60],
                        'user' => ['requests' => 60, 'window' => 60],
                    ],
                ],
                [
                    'path' => '/admin/delete',
                    'methods' => ['POST', 'DELETE'],
                    'limits' => [
                        'user' => ['requests' => 10, 'window' => 60],
                    ],
                    'cost' => 5,
                ],
            ],
        ], $logger);
    }
}
