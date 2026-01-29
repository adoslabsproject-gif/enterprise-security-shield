<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\ML;

use AdosLabs\EnterpriseSecurityShield\Contracts\StorageInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Machine Learning Security Middleware (PSR-15)
 *
 * Integrates ML threat classification into the request pipeline.
 * Provides real-time threat detection with online learning feedback loop.
 *
 * FEATURES:
 * 1. Pre-request classification using ML models
 * 2. Automatic feedback loop from security events
 * 3. Configurable actions (block, challenge, log)
 * 4. Request attribute enrichment for downstream middleware
 * 5. Performance metrics and model health monitoring
 *
 * FEEDBACK LOOP:
 * - When WAF blocks a request → positive sample for threat class
 * - When rate limiter triggers → positive sample (with lower weight)
 * - When bot verification fails → BOT_SPOOF sample
 * - Periodic learning from security event log
 *
 * @version 1.0.0
 */
final class MLSecurityMiddleware implements MiddlewareInterface
{
    /**
     * Request attribute keys for classification results
     */
    public const ATTR_CLASSIFICATION = 'ml.classification';
    public const ATTR_CONFIDENCE = 'ml.confidence';
    public const ATTR_IS_THREAT = 'ml.is_threat';
    public const ATTR_FEATURES = 'ml.features';

    private OnlineLearningClassifier $classifier;
    private ThreatClassifier $threatClassifier;
    private StorageInterface $storage;
    private LoggerInterface $logger;

    /**
     * Configuration
     * @var array<string, mixed>
     */
    private array $config;

    /**
     * Action to take on threat detection
     */
    public const ACTION_LOG = 'log';
    public const ACTION_CHALLENGE = 'challenge';
    public const ACTION_BLOCK = 'block';

    /**
     * @param array{
     *     action?: string,
     *     confidence_threshold?: float,
     *     block_classes?: array<string>,
     *     challenge_classes?: array<string>,
     *     enable_feedback?: bool,
     *     feedback_batch_size?: int,
     *     exclude_paths?: array<string>,
     *     exclude_ips?: array<string>
     * } $config
     */
    public function __construct(
        OnlineLearningClassifier $classifier,
        ThreatClassifier $threatClassifier,
        StorageInterface $storage,
        ?LoggerInterface $logger = null,
        array $config = []
    ) {
        $this->classifier = $classifier;
        $this->threatClassifier = $threatClassifier;
        $this->storage = $storage;
        $this->logger = $logger ?? new NullLogger();

        $this->config = array_merge([
            // Default action on threat detection
            'action' => self::ACTION_LOG,

            // Confidence threshold for threat classification
            'confidence_threshold' => 0.70,

            // Classes that should be blocked immediately
            'block_classes' => [
                OnlineLearningClassifier::CLASS_SQLI_ATTEMPT,
                OnlineLearningClassifier::CLASS_XSS_ATTEMPT,
                OnlineLearningClassifier::CLASS_PATH_TRAVERSAL,
                OnlineLearningClassifier::CLASS_IOT_EXPLOIT,
            ],

            // Classes that should trigger challenge (CAPTCHA)
            'challenge_classes' => [
                OnlineLearningClassifier::CLASS_SCANNER,
                OnlineLearningClassifier::CLASS_BRUTE_FORCE,
            ],

            // Enable automatic learning from events
            'enable_feedback' => true,

            // Batch size for learning
            'feedback_batch_size' => 100,

            // Paths to exclude from ML classification
            'exclude_paths' => [
                '/health',
                '/metrics',
                '/favicon.ico',
            ],

            // IPs to exclude (trusted)
            'exclude_ips' => [],

            // Enable dual classifier mode
            'use_dual_classifier' => true,

            // Response factory for blocking
            'response_factory' => null,
        ], $config);
    }

    /**
     * Process request through ML classification
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $path = $request->getUri()->getPath();
        $ip = $this->getClientIp($request);

        // Skip excluded paths/IPs
        if ($this->isExcluded($path, $ip)) {
            return $handler->handle($request);
        }

        // Extract request data
        $requestData = $this->extractRequestData($request);

        // Classify using Online Learning Classifier
        $onlineResult = $this->classifier->classify($requestData);

        // Optionally use dual classifier for comparison
        $staticResult = null;
        if ($this->config['use_dual_classifier']) {
            $staticResult = $this->threatClassifier->classify(
                $ip,
                $requestData['user_agent'] ?? '',
                $path,
                $request->getMethod(),
                $requestData['headers'] ?? [],
                $requestData['behavior'] ?? []
            );
        }

        // Merge results (prefer higher confidence threat)
        $classification = $this->mergeClassifications($onlineResult, $staticResult);

        // Enrich request with classification
        $request = $request
            ->withAttribute(self::ATTR_CLASSIFICATION, $classification['classification'])
            ->withAttribute(self::ATTR_CONFIDENCE, $classification['confidence'])
            ->withAttribute(self::ATTR_IS_THREAT, $classification['is_threat'])
            ->withAttribute(self::ATTR_FEATURES, $classification['features_used'] ?? []);

        // Log classification
        $this->logger->debug('ML classification', [
            'ip' => $ip,
            'path' => $path,
            'classification' => $classification['classification'],
            'confidence' => $classification['confidence'],
            'is_threat' => $classification['is_threat'],
        ]);

        // Handle threat based on action
        if ($classification['is_threat']) {
            $action = $this->determineAction($classification);

            if ($action === self::ACTION_BLOCK) {
                $this->logThreatBlocked($request, $classification);

                // Learn from this blocking decision
                if ($this->config['enable_feedback']) {
                    $this->learnFromBlock($requestData, $classification);
                }

                return $this->createBlockResponse($classification);
            }

            if ($action === self::ACTION_CHALLENGE) {
                $request = $request->withAttribute('ml.requires_challenge', true);
            }

            // Log threat for monitoring
            $this->logThreat($request, $classification);
        }

        // Continue with request
        $response = $handler->handle($request);

        // Learn from response if enabled
        if ($this->config['enable_feedback']) {
            $this->learnFromResponse($requestData, $classification, $response);
        }

        return $response;
    }

    /**
     * Merge classifications from both classifiers
     *
     * @param array<string, mixed> $onlineResult
     * @param array<string, mixed>|null $staticResult
     * @return array<string, mixed>
     */
    private function mergeClassifications(array $onlineResult, ?array $staticResult): array
    {
        if ($staticResult === null) {
            return $onlineResult;
        }

        // If both agree, use higher confidence
        if ($onlineResult['classification'] === $staticResult['classification']) {
            return [
                'classification' => $onlineResult['classification'],
                'confidence' => max($onlineResult['confidence'], $staticResult['confidence']),
                'is_threat' => $onlineResult['is_threat'] || $staticResult['is_threat'],
                'features_used' => array_merge(
                    $onlineResult['features_used'] ?? [],
                    $staticResult['features_detected'] ?? []
                ),
                'online_confidence' => $onlineResult['confidence'],
                'static_confidence' => $staticResult['confidence'],
                'source' => 'merged',
            ];
        }

        // If they disagree, prefer threat classification with higher confidence
        $onlineIsThreat = $onlineResult['classification'] !== OnlineLearningClassifier::CLASS_LEGITIMATE;
        $staticIsThreat = $staticResult['classification'] !== 'LEGITIMATE';

        // If one says threat and other says legitimate, prefer threat if confident
        if ($onlineIsThreat && !$staticIsThreat) {
            if ($onlineResult['confidence'] >= $this->config['confidence_threshold']) {
                return array_merge($onlineResult, ['source' => 'online']);
            }
        }

        if ($staticIsThreat && !$onlineIsThreat) {
            if ($staticResult['confidence'] >= $this->config['confidence_threshold']) {
                return [
                    'classification' => $staticResult['classification'],
                    'confidence' => $staticResult['confidence'],
                    'is_threat' => true,
                    'features_used' => $staticResult['features_detected'] ?? [],
                    'source' => 'static',
                ];
            }
        }

        // Both are threats, use higher confidence
        if ($onlineIsThreat && $staticIsThreat) {
            if ($onlineResult['confidence'] >= $staticResult['confidence']) {
                return array_merge($onlineResult, ['source' => 'online']);
            }
            return [
                'classification' => $staticResult['classification'],
                'confidence' => $staticResult['confidence'],
                'is_threat' => true,
                'features_used' => $staticResult['features_detected'] ?? [],
                'source' => 'static',
            ];
        }

        // Default to online classifier
        return array_merge($onlineResult, ['source' => 'online']);
    }

    /**
     * Determine action based on classification
     */
    private function determineAction(array $classification): string
    {
        $class = $classification['classification'];
        $confidence = $classification['confidence'];

        // Check if class should be blocked
        if (in_array($class, $this->config['block_classes'], true)) {
            if ($confidence >= $this->config['confidence_threshold']) {
                return self::ACTION_BLOCK;
            }
        }

        // Check if class should be challenged
        if (in_array($class, $this->config['challenge_classes'], true)) {
            return self::ACTION_CHALLENGE;
        }

        // Fall back to default action
        return $this->config['action'];
    }

    /**
     * Extract request data for classification
     *
     * @return array<string, mixed>
     */
    private function extractRequestData(ServerRequestInterface $request): array
    {
        $headers = [];
        foreach ($request->getHeaders() as $name => $values) {
            $headers[strtolower($name)] = $values[0] ?? '';
        }

        $ip = $this->getClientIp($request);
        $path = $request->getUri()->getPath();
        $userAgent = $request->getHeaderLine('User-Agent');

        // Get behavior metrics from storage
        $behaviorMetrics = $this->getBehaviorMetrics($ip);

        return [
            'ip' => $ip,
            'path' => $path,
            'user_agent' => $userAgent,
            'method' => $request->getMethod(),
            'headers' => $headers,
            'missing_accept' => !$request->hasHeader('Accept'),
            'x_forwarded_for' => $headers['x-forwarded-for'] ?? '',

            // Behavior metrics
            'error_404_count' => $behaviorMetrics['404_count'] ?? 0,
            'request_count' => $behaviorMetrics['request_count'] ?? 0,
            'login_failures' => $behaviorMetrics['login_failures'] ?? 0,
            'rate_limited' => $behaviorMetrics['rate_limited'] ?? false,
            'honeypot_hit' => $behaviorMetrics['honeypot_hit'] ?? false,
            'sqli_detected' => $behaviorMetrics['sqli_detected'] ?? false,
            'xss_detected' => $behaviorMetrics['xss_detected'] ?? false,

            // Bot verification status (may be set by earlier middleware)
            'bot_verified' => $request->getAttribute('bot_verified', true),

            // Behavior array for static classifier
            'behavior' => $behaviorMetrics,
        ];
    }

    /**
     * Get behavior metrics for IP from storage
     *
     * @return array<string, mixed>
     */
    private function getBehaviorMetrics(string $ip): array
    {
        $key = "metrics:ip:{$ip}";
        $stored = $this->storage->get($key);

        if ($stored === null) {
            return [];
        }

        if (is_string($stored)) {
            $decoded = json_decode($stored, true);
            return is_array($decoded) ? $decoded : [];
        }

        return is_array($stored) ? $stored : [];
    }

    /**
     * Learn from a blocked request
     *
     * @param array<string, mixed> $requestData
     * @param array<string, mixed> $classification
     */
    private function learnFromBlock(array $requestData, array $classification): void
    {
        // Blocking is high-confidence positive sample
        $this->classifier->learn(
            $requestData,
            $classification['classification'],
            1.0 // Full weight for blocked threats
        );

        $this->logger->info('ML model learned from block', [
            'classification' => $classification['classification'],
            'confidence' => $classification['confidence'],
        ]);
    }

    /**
     * Learn from response (post-request feedback)
     *
     * @param array<string, mixed> $requestData
     * @param array<string, mixed> $classification
     */
    private function learnFromResponse(array $requestData, array $classification, ResponseInterface $response): void
    {
        $statusCode = $response->getStatusCode();

        // 403/401 responses suggest blocked threat
        if ($statusCode === 403 || $statusCode === 401) {
            if ($classification['classification'] !== OnlineLearningClassifier::CLASS_LEGITIMATE) {
                // Confirm threat classification
                $this->classifier->learn(
                    $requestData,
                    $classification['classification'],
                    0.5 // Lower weight for indirect confirmation
                );
            }
        }

        // 404 responses might indicate scanning
        if ($statusCode === 404) {
            // Update behavior metrics
            $this->incrementMetric($requestData['ip'], '404_count');
        }

        // Successful responses for threat classifications could be false positives
        if ($statusCode >= 200 && $statusCode < 300) {
            if ($classification['is_threat'] && $classification['confidence'] < 0.9) {
                // Potentially false positive - don't learn, but log
                $this->logger->debug('Potential false positive', [
                    'classification' => $classification['classification'],
                    'confidence' => $classification['confidence'],
                ]);
            }
        }
    }

    /**
     * Increment a behavior metric for IP
     */
    private function incrementMetric(string $ip, string $metric): void
    {
        $key = "metrics:ip:{$ip}";
        $stored = $this->storage->get($key);

        $metrics = [];
        if ($stored !== null && is_string($stored)) {
            $decoded = json_decode($stored, true);
            if (is_array($decoded)) {
                $metrics = $decoded;
            }
        }

        $metrics[$metric] = ($metrics[$metric] ?? 0) + 1;
        $metrics['last_seen'] = time();

        $this->storage->set($key, json_encode($metrics), 3600); // 1 hour TTL
    }

    /**
     * Log threat detection
     */
    private function logThreat(ServerRequestInterface $request, array $classification): void
    {
        $this->logger->warning('ML threat detected', [
            'ip' => $this->getClientIp($request),
            'path' => $request->getUri()->getPath(),
            'method' => $request->getMethod(),
            'classification' => $classification['classification'],
            'confidence' => $classification['confidence'],
            'features' => $classification['features_used'] ?? [],
        ]);

        // Store event for analytics
        $ip = $this->getClientIp($request);
        $this->storage->logSecurityEvent('ml_threat_detected', $ip, [
            'path' => $request->getUri()->getPath(),
            'classification' => $classification['classification'],
            'confidence' => $classification['confidence'],
            'user_agent' => $request->getHeaderLine('User-Agent'),
        ]);
    }

    /**
     * Log blocked threat
     */
    private function logThreatBlocked(ServerRequestInterface $request, array $classification): void
    {
        $this->logger->error('ML threat blocked', [
            'ip' => $this->getClientIp($request),
            'path' => $request->getUri()->getPath(),
            'classification' => $classification['classification'],
            'confidence' => $classification['confidence'],
        ]);

        $ip = $this->getClientIp($request);
        $this->storage->logSecurityEvent('ml_threat_blocked', $ip, [
            'path' => $request->getUri()->getPath(),
            'classification' => $classification['classification'],
            'confidence' => $classification['confidence'],
            'user_agent' => $request->getHeaderLine('User-Agent'),
        ]);
    }

    /**
     * Create block response
     */
    private function createBlockResponse(array $classification): ResponseInterface
    {
        if (isset($this->config['response_factory']) && is_callable($this->config['response_factory'])) {
            return ($this->config['response_factory'])($classification);
        }

        // Create basic 403 response
        $responseClass = class_exists(\Nyholm\Psr7\Response::class)
            ? \Nyholm\Psr7\Response::class
            : (class_exists(\GuzzleHttp\Psr7\Response::class)
                ? \GuzzleHttp\Psr7\Response::class
                : null);

        if ($responseClass === null) {
            throw new \RuntimeException('No PSR-7 response implementation available');
        }

        $body = json_encode([
            'error' => 'Access denied',
            'reason' => 'Security threat detected',
            'classification' => $classification['classification'],
        ]);

        return new $responseClass(
            403,
            ['Content-Type' => 'application/json'],
            $body
        );
    }

    /**
     * Get client IP address
     */
    private function getClientIp(ServerRequestInterface $request): string
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
     * Check if path/IP is excluded
     */
    private function isExcluded(string $path, string $ip): bool
    {
        foreach ($this->config['exclude_paths'] as $excludePath) {
            if (str_starts_with($path, $excludePath)) {
                return true;
            }
        }

        if (in_array($ip, $this->config['exclude_ips'], true)) {
            return true;
        }

        return false;
    }

    /**
     * Trigger periodic learning from events
     *
     * Call this from a cron job or scheduled task
     */
    public function runPeriodicLearning(int $since = 0): int
    {
        if (!$this->config['enable_feedback']) {
            return 0;
        }

        return $this->classifier->autoLearnFromEvents(
            $this->config['feedback_batch_size'],
            $since
        );
    }

    /**
     * Get ML model statistics
     *
     * @return array<string, mixed>
     */
    public function getModelStats(): array
    {
        return [
            'online_classifier' => $this->classifier->getStats(),
            'static_classifier' => $this->threatClassifier->getModelStats(),
            'config' => [
                'action' => $this->config['action'],
                'confidence_threshold' => $this->config['confidence_threshold'],
                'enable_feedback' => $this->config['enable_feedback'],
                'use_dual_classifier' => $this->config['use_dual_classifier'],
            ],
        ];
    }

    /**
     * Export models for backup/analysis
     *
     * @return array<string, mixed>
     */
    public function exportModels(): array
    {
        return [
            'online_model' => $this->classifier->exportModel(),
            'exported_at' => date('c'),
        ];
    }

    /**
     * Create with default configuration
     */
    public static function create(
        StorageInterface $storage,
        ?LoggerInterface $logger = null
    ): self {
        $onlineClassifier = new OnlineLearningClassifier($storage, $logger);
        $threatClassifier = new ThreatClassifier();

        return new self(
            $onlineClassifier,
            $threatClassifier,
            $storage,
            $logger
        );
    }

    /**
     * Create with strict blocking mode
     */
    public static function strict(
        StorageInterface $storage,
        ?LoggerInterface $logger = null
    ): self {
        $onlineClassifier = new OnlineLearningClassifier($storage, $logger);
        $threatClassifier = new ThreatClassifier();

        return new self(
            $onlineClassifier,
            $threatClassifier,
            $storage,
            $logger,
            [
                'action' => self::ACTION_BLOCK,
                'confidence_threshold' => 0.75,
                'enable_feedback' => true,
            ]
        );
    }

    /**
     * Create for monitoring only (no blocking)
     */
    public static function monitoring(
        StorageInterface $storage,
        ?LoggerInterface $logger = null
    ): self {
        $onlineClassifier = new OnlineLearningClassifier($storage, $logger);
        $threatClassifier = new ThreatClassifier();

        return new self(
            $onlineClassifier,
            $threatClassifier,
            $storage,
            $logger,
            [
                'action' => self::ACTION_LOG,
                'block_classes' => [], // Never block
                'challenge_classes' => [], // Never challenge
                'enable_feedback' => true,
            ]
        );
    }
}
