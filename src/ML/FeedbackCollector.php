<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\ML;

use AdosLabs\EnterpriseSecurityShield\Contracts\StorageInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * ML Feedback Collector
 *
 * Collects and processes feedback signals for online learning.
 * Integrates with various WAF components to gather training data.
 *
 * FEEDBACK SOURCES:
 * 1. WAF blocking decisions (high confidence)
 * 2. Rate limiter triggers (medium confidence)
 * 3. Bot verification failures (high confidence for BOT_SPOOF)
 * 4. Honeypot access (very high confidence)
 * 5. SQLi/XSS detection (high confidence)
 * 6. Admin feedback (explicit labeling)
 *
 * DEDUPLICATION:
 * - Prevents learning from the same event multiple times
 * - Uses content-based hashing for event identification
 *
 * @version 1.0.0
 */
final class FeedbackCollector
{
    private StorageInterface $storage;
    private OnlineLearningClassifier $classifier;
    private LoggerInterface $logger;

    /**
     * Feedback types and their confidence weights
     */
    private const FEEDBACK_WEIGHTS = [
        'waf_block' => 1.0,
        'honeypot' => 1.0,
        'sqli_detected' => 0.95,
        'xss_detected' => 0.95,
        'bot_spoof' => 0.90,
        'brute_force' => 0.85,
        'rate_limit' => 0.60,
        'admin_label' => 1.0,
        'legitimate_verified' => 0.90,
    ];

    /**
     * Storage key prefix
     */
    private const STORAGE_PREFIX = 'ml:feedback:';

    /**
     * Pending feedback queue
     * @var array<int, array{type: string, features: array, class: string, weight: float, hash: string}>
     */
    private array $pendingFeedback = [];

    /**
     * Batch size for processing
     */
    private int $batchSize = 50;

    /**
     * Hash TTL for deduplication (24 hours)
     */
    private int $deduplicationTTL = 86400;

    public function __construct(
        StorageInterface $storage,
        OnlineLearningClassifier $classifier,
        ?LoggerInterface $logger = null
    ) {
        $this->storage = $storage;
        $this->classifier = $classifier;
        $this->logger = $logger ?? new NullLogger();
    }

    /**
     * Record WAF blocking decision
     *
     * @param array<string, mixed> $requestData
     * @param string $blockReason
     */
    public function recordWAFBlock(array $requestData, string $blockReason): void
    {
        $class = $this->mapBlockReasonToClass($blockReason);
        $this->addFeedback('waf_block', $requestData, $class);
    }

    /**
     * Record honeypot access
     *
     * @param array<string, mixed> $requestData
     */
    public function recordHoneypotAccess(array $requestData): void
    {
        $this->addFeedback('honeypot', $requestData, OnlineLearningClassifier::CLASS_SCANNER);
    }

    /**
     * Record SQLi detection
     *
     * @param array<string, mixed> $requestData
     */
    public function recordSQLiDetection(array $requestData): void
    {
        $this->addFeedback('sqli_detected', $requestData, OnlineLearningClassifier::CLASS_SQLI_ATTEMPT);
    }

    /**
     * Record XSS detection
     *
     * @param array<string, mixed> $requestData
     */
    public function recordXSSDetection(array $requestData): void
    {
        $this->addFeedback('xss_detected', $requestData, OnlineLearningClassifier::CLASS_XSS_ATTEMPT);
    }

    /**
     * Record bot spoofing detection
     *
     * @param array<string, mixed> $requestData
     */
    public function recordBotSpoof(array $requestData): void
    {
        $this->addFeedback('bot_spoof', $requestData, OnlineLearningClassifier::CLASS_BOT_SPOOF);
    }

    /**
     * Record brute force detection
     *
     * @param array<string, mixed> $requestData
     */
    public function recordBruteForce(array $requestData): void
    {
        $this->addFeedback('brute_force', $requestData, OnlineLearningClassifier::CLASS_BRUTE_FORCE);
    }

    /**
     * Record rate limit trigger
     *
     * @param array<string, mixed> $requestData
     */
    public function recordRateLimitTrigger(array $requestData): void
    {
        // Rate limiting could be legitimate high traffic, use lower weight
        $this->addFeedback('rate_limit', $requestData, OnlineLearningClassifier::CLASS_SCANNER);
    }

    /**
     * Record verified legitimate bot
     *
     * @param array<string, mixed> $requestData
     */
    public function recordLegitimateBot(array $requestData): void
    {
        $this->addFeedback('legitimate_verified', $requestData, OnlineLearningClassifier::CLASS_LEGITIMATE);
    }

    /**
     * Record admin feedback (explicit labeling)
     *
     * @param array<string, mixed> $requestData
     * @param string $labeledClass
     */
    public function recordAdminFeedback(array $requestData, string $labeledClass): void
    {
        $this->addFeedback('admin_label', $requestData, $labeledClass);
    }

    /**
     * Record path traversal detection
     *
     * @param array<string, mixed> $requestData
     */
    public function recordPathTraversal(array $requestData): void
    {
        $this->addFeedback('waf_block', $requestData, OnlineLearningClassifier::CLASS_PATH_TRAVERSAL);
    }

    /**
     * Record IoT exploit attempt
     *
     * @param array<string, mixed> $requestData
     */
    public function recordIoTExploit(array $requestData): void
    {
        $this->addFeedback('waf_block', $requestData, OnlineLearningClassifier::CLASS_IOT_EXPLOIT);
    }

    /**
     * Record CMS probe attempt
     *
     * @param array<string, mixed> $requestData
     */
    public function recordCMSProbe(array $requestData): void
    {
        $this->addFeedback('waf_block', $requestData, OnlineLearningClassifier::CLASS_CMS_PROBE);
    }

    /**
     * Record config hunting attempt
     *
     * @param array<string, mixed> $requestData
     */
    public function recordConfigHunt(array $requestData): void
    {
        $this->addFeedback('waf_block', $requestData, OnlineLearningClassifier::CLASS_CONFIG_HUNT);
    }

    /**
     * Record credential theft attempt
     *
     * @param array<string, mixed> $requestData
     */
    public function recordCredentialTheft(array $requestData): void
    {
        $this->addFeedback('waf_block', $requestData, OnlineLearningClassifier::CLASS_CREDENTIAL_THEFT);
    }

    /**
     * Add feedback to pending queue
     *
     * @param array<string, mixed> $features
     */
    private function addFeedback(string $type, array $features, string $class): void
    {
        // Calculate content hash for deduplication
        $hash = $this->calculateHash($features, $class);

        // Check if already processed
        if ($this->isDuplicate($hash)) {
            $this->logger->debug('Duplicate feedback ignored', [
                'type' => $type,
                'class' => $class,
                'hash' => $hash,
            ]);
            return;
        }

        $weight = self::FEEDBACK_WEIGHTS[$type] ?? 0.5;

        $this->pendingFeedback[] = [
            'type' => $type,
            'features' => $features,
            'class' => $class,
            'weight' => $weight,
            'hash' => $hash,
            'timestamp' => time(),
        ];

        // Mark as processed
        $this->markProcessed($hash);

        $this->logger->debug('Feedback collected', [
            'type' => $type,
            'class' => $class,
            'weight' => $weight,
        ]);

        // Auto-flush if batch is full
        if (count($this->pendingFeedback) >= $this->batchSize) {
            $this->flush();
        }
    }

    /**
     * Flush pending feedback to classifier
     */
    public function flush(): void
    {
        if (empty($this->pendingFeedback)) {
            return;
        }

        $samples = [];
        foreach ($this->pendingFeedback as $feedback) {
            $samples[] = [
                'features' => $feedback['features'],
                'class' => $feedback['class'],
                'weight' => $feedback['weight'],
            ];
        }

        $this->classifier->learnBatch($samples);

        $this->logger->info('Feedback flushed to classifier', [
            'samples' => count($samples),
        ]);

        $this->pendingFeedback = [];
    }

    /**
     * Calculate hash for deduplication
     *
     * @param array<string, mixed> $features
     */
    private function calculateHash(array $features, string $class): string
    {
        // Use key features that define uniqueness
        $key = implode('|', [
            $features['ip'] ?? '',
            $features['user_agent'] ?? '',
            $features['path'] ?? '',
            $class,
        ]);

        return md5($key);
    }

    /**
     * Check if feedback is duplicate
     */
    private function isDuplicate(string $hash): bool
    {
        $key = self::STORAGE_PREFIX . "hash:{$hash}";
        return $this->storage->get($key) !== null;
    }

    /**
     * Mark feedback as processed
     */
    private function markProcessed(string $hash): void
    {
        $key = self::STORAGE_PREFIX . "hash:{$hash}";
        $this->storage->set($key, '1', $this->deduplicationTTL);
    }

    /**
     * Map WAF block reason to classification class
     */
    private function mapBlockReasonToClass(string $reason): string
    {
        $reason = strtolower($reason);

        // SQL injection patterns
        if (str_contains($reason, 'sql') || str_contains($reason, 'injection')) {
            return OnlineLearningClassifier::CLASS_SQLI_ATTEMPT;
        }

        // XSS patterns
        if (str_contains($reason, 'xss') || str_contains($reason, 'script')) {
            return OnlineLearningClassifier::CLASS_XSS_ATTEMPT;
        }

        // Path traversal
        if (str_contains($reason, 'traversal') || str_contains($reason, 'path')) {
            return OnlineLearningClassifier::CLASS_PATH_TRAVERSAL;
        }

        // Bot spoofing
        if (str_contains($reason, 'spoof') || str_contains($reason, 'bot')) {
            return OnlineLearningClassifier::CLASS_BOT_SPOOF;
        }

        // Brute force
        if (str_contains($reason, 'brute') || str_contains($reason, 'login')) {
            return OnlineLearningClassifier::CLASS_BRUTE_FORCE;
        }

        // Scanner
        if (str_contains($reason, 'scan') || str_contains($reason, 'probe')) {
            return OnlineLearningClassifier::CLASS_SCANNER;
        }

        // Config hunting
        if (str_contains($reason, 'config') || str_contains($reason, 'env')) {
            return OnlineLearningClassifier::CLASS_CONFIG_HUNT;
        }

        // IoT exploit
        if (str_contains($reason, 'gpon') || str_contains($reason, 'iot') || str_contains($reason, 'router')) {
            return OnlineLearningClassifier::CLASS_IOT_EXPLOIT;
        }

        // CMS probe
        if (str_contains($reason, 'wordpress') || str_contains($reason, 'wp-') || str_contains($reason, 'cms')) {
            return OnlineLearningClassifier::CLASS_CMS_PROBE;
        }

        // Credential theft
        if (str_contains($reason, 'credential') || str_contains($reason, 'aws') || str_contains($reason, 'git')) {
            return OnlineLearningClassifier::CLASS_CREDENTIAL_THEFT;
        }

        // Generic threat
        return OnlineLearningClassifier::CLASS_SCANNER;
    }

    /**
     * Get pending feedback count
     */
    public function getPendingCount(): int
    {
        return count($this->pendingFeedback);
    }

    /**
     * Get statistics
     *
     * @return array<string, mixed>
     */
    public function getStats(): array
    {
        return [
            'pending_feedback' => count($this->pendingFeedback),
            'batch_size' => $this->batchSize,
            'deduplication_ttl' => $this->deduplicationTTL,
            'feedback_weights' => self::FEEDBACK_WEIGHTS,
        ];
    }

    /**
     * Set batch size
     */
    public function setBatchSize(int $size): self
    {
        $this->batchSize = max(1, $size);
        return $this;
    }

    /**
     * Set deduplication TTL
     */
    public function setDeduplicationTTL(int $seconds): self
    {
        $this->deduplicationTTL = max(60, $seconds);
        return $this;
    }

    /**
     * Clear pending feedback without flushing
     */
    public function clear(): void
    {
        $this->pendingFeedback = [];
    }

    /**
     * Destructor - flush pending on shutdown
     */
    public function __destruct()
    {
        $this->flush();
    }
}
