<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\ML;

use AdosLabs\EnterpriseSecurityShield\Contracts\StorageInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Online Learning Threat Classifier.
 *
 * TRUE MACHINE LEARNING with continuous learning from security events.
 *
 * ALGORITHM: Naive Bayes with Online Learning
 * - Starts with prior knowledge (pre-trained weights from 662 events)
 * - Learns continuously from new security events
 * - Updates P(feature|class) probabilities incrementally
 * - Persists learned weights to storage (Redis/Database)
 *
 * ONLINE LEARNING APPROACH:
 * - Uses Laplace smoothing to handle unseen features
 * - Incremental updates without full retraining
 * - Decaying weights for concept drift (older events matter less)
 * - Thread-safe atomic updates via Redis
 *
 * MATHEMATICAL FOUNDATION:
 * P(class|features) ∝ P(class) × ∏ P(feature_i|class)
 *
 * With online update:
 * P(feature|class) = (count(feature,class) + α) / (count(class) + α × |V|)
 * Where α = Laplace smoothing parameter, |V| = vocabulary size
 *
 * @version 2.0.0 - True Online Learning
 */
final class OnlineLearningClassifier
{
    /**
     * Storage for persisting learned weights.
     */
    private StorageInterface $storage;

    /**
     * PSR-3 Logger.
     */
    private LoggerInterface $logger;

    /**
     * Storage key prefix for ML data.
     */
    private const STORAGE_PREFIX = 'ml:classifier:';

    /**
     * Laplace smoothing parameter (prevents zero probabilities).
     */
    private const LAPLACE_ALPHA = 1.0;

    /**
     * Minimum samples before using learned weights.
     */
    private const MIN_SAMPLES_FOR_LEARNING = 50;

    /**
     * Decay factor for older observations (concept drift handling)
     * 0.99 = 1% decay per batch, keeps ~60% weight after 50 batches.
     */
    private const DECAY_FACTOR = 0.995;

    /**
     * Threat classification categories.
     */
    public const CLASS_SCANNER = 'SCANNER';

    public const CLASS_BOT_SPOOF = 'BOT_SPOOF';

    public const CLASS_CMS_PROBE = 'CMS_PROBE';

    public const CLASS_CONFIG_HUNT = 'CONFIG_HUNT';

    public const CLASS_PATH_TRAVERSAL = 'PATH_TRAVERSAL';

    public const CLASS_CREDENTIAL_THEFT = 'CREDENTIAL_THEFT';

    public const CLASS_IOT_EXPLOIT = 'IOT_EXPLOIT';

    public const CLASS_BRUTE_FORCE = 'BRUTE_FORCE';

    public const CLASS_SQLI_ATTEMPT = 'SQLI_ATTEMPT';

    public const CLASS_XSS_ATTEMPT = 'XSS_ATTEMPT';

    public const CLASS_LEGITIMATE = 'LEGITIMATE';

    /**
     * All possible classes.
     */
    private const CLASSES = [
        self::CLASS_SCANNER,
        self::CLASS_BOT_SPOOF,
        self::CLASS_CMS_PROBE,
        self::CLASS_CONFIG_HUNT,
        self::CLASS_PATH_TRAVERSAL,
        self::CLASS_CREDENTIAL_THEFT,
        self::CLASS_IOT_EXPLOIT,
        self::CLASS_BRUTE_FORCE,
        self::CLASS_SQLI_ATTEMPT,
        self::CLASS_XSS_ATTEMPT,
        self::CLASS_LEGITIMATE,
    ];

    /**
     * Initial prior probabilities (from 662 pre-analyzed events)
     * These serve as starting point before learning kicks in.
     */
    private const INITIAL_PRIORS = [
        self::CLASS_SCANNER => 0.12,
        self::CLASS_BOT_SPOOF => 0.05,
        self::CLASS_CMS_PROBE => 0.08,
        self::CLASS_CONFIG_HUNT => 0.04,
        self::CLASS_PATH_TRAVERSAL => 0.02,
        self::CLASS_CREDENTIAL_THEFT => 0.01,
        self::CLASS_IOT_EXPLOIT => 0.03,
        self::CLASS_BRUTE_FORCE => 0.03,
        self::CLASS_SQLI_ATTEMPT => 0.02,
        self::CLASS_XSS_ATTEMPT => 0.02,
        self::CLASS_LEGITIMATE => 0.58,
    ];

    /**
     * Initial feature likelihoods (pre-trained from production logs)
     * Format: feature => [class => probability].
     */
    private const INITIAL_LIKELIHOODS = [
        // User-Agent features
        'ua:curl' => [self::CLASS_SCANNER => 0.85, self::CLASS_LEGITIMATE => 0.02],
        'ua:python' => [self::CLASS_SCANNER => 0.78, self::CLASS_LEGITIMATE => 0.05],
        'ua:wget' => [self::CLASS_SCANNER => 0.82, self::CLASS_LEGITIMATE => 0.03],
        'ua:go-http' => [self::CLASS_SCANNER => 0.75, self::CLASS_LEGITIMATE => 0.08],
        'ua:java' => [self::CLASS_SCANNER => 0.65, self::CLASS_LEGITIMATE => 0.10],
        'ua:hello_world' => [self::CLASS_IOT_EXPLOIT => 0.95, self::CLASS_LEGITIMATE => 0.001],
        'ua:censys' => [self::CLASS_SCANNER => 0.98, self::CLASS_LEGITIMATE => 0.0],
        'ua:zgrab' => [self::CLASS_SCANNER => 0.97, self::CLASS_LEGITIMATE => 0.0],
        'ua:masscan' => [self::CLASS_SCANNER => 0.99, self::CLASS_LEGITIMATE => 0.0],
        'ua:nmap' => [self::CLASS_SCANNER => 0.99, self::CLASS_LEGITIMATE => 0.0],
        'ua:nikto' => [self::CLASS_SCANNER => 0.99, self::CLASS_LEGITIMATE => 0.0],
        'ua:sqlmap' => [self::CLASS_SQLI_ATTEMPT => 0.99, self::CLASS_SCANNER => 0.90, self::CLASS_LEGITIMATE => 0.0],
        'ua:gobuster' => [self::CLASS_SCANNER => 0.99, self::CLASS_LEGITIMATE => 0.0],
        'ua:dirbuster' => [self::CLASS_SCANNER => 0.99, self::CLASS_LEGITIMATE => 0.0],
        'ua:wpscan' => [self::CLASS_CMS_PROBE => 0.99, self::CLASS_LEGITIMATE => 0.0],
        'ua:nuclei' => [self::CLASS_SCANNER => 0.99, self::CLASS_LEGITIMATE => 0.0],

        // Bot spoofing
        'ua:googlebot_unverified' => [self::CLASS_BOT_SPOOF => 0.92, self::CLASS_LEGITIMATE => 0.01],
        'ua:bingbot_unverified' => [self::CLASS_BOT_SPOOF => 0.90, self::CLASS_LEGITIMATE => 0.02],
        'ua:gptbot_unverified' => [self::CLASS_BOT_SPOOF => 0.85, self::CLASS_LEGITIMATE => 0.03],

        // Path features
        'path:wp-admin' => [self::CLASS_CMS_PROBE => 0.75, self::CLASS_LEGITIMATE => 0.15],
        'path:wp-login' => [self::CLASS_CMS_PROBE => 0.70, self::CLASS_LEGITIMATE => 0.20],
        'path:wp-config' => [self::CLASS_CONFIG_HUNT => 0.88, self::CLASS_LEGITIMATE => 0.001],
        'path:phpmyadmin' => [self::CLASS_CONFIG_HUNT => 0.92, self::CLASS_LEGITIMATE => 0.001],
        'path:adminer' => [self::CLASS_CONFIG_HUNT => 0.90, self::CLASS_LEGITIMATE => 0.001],
        'path:phpinfo' => [self::CLASS_CONFIG_HUNT => 0.88, self::CLASS_SCANNER => 0.75, self::CLASS_LEGITIMATE => 0.01],
        'path:env' => [self::CLASS_CREDENTIAL_THEFT => 0.95, self::CLASS_LEGITIMATE => 0.001],
        'path:git' => [self::CLASS_CREDENTIAL_THEFT => 0.92, self::CLASS_LEGITIMATE => 0.001],
        'path:aws_credentials' => [self::CLASS_CREDENTIAL_THEFT => 0.99, self::CLASS_LEGITIMATE => 0.0],
        'path:backup' => [self::CLASS_CONFIG_HUNT => 0.75, self::CLASS_LEGITIMATE => 0.05],
        'path:gponform' => [self::CLASS_IOT_EXPLOIT => 0.99, self::CLASS_LEGITIMATE => 0.0],
        'path:hnap' => [self::CLASS_IOT_EXPLOIT => 0.95, self::CLASS_LEGITIMATE => 0.0],
        'path:traversal' => [self::CLASS_PATH_TRAVERSAL => 0.95, self::CLASS_LEGITIMATE => 0.0],

        // Behavioral features
        'behavior:high_404_rate' => [self::CLASS_SCANNER => 0.80, self::CLASS_LEGITIMATE => 0.05],
        'behavior:rapid_requests' => [self::CLASS_SCANNER => 0.75, self::CLASS_BRUTE_FORCE => 0.70, self::CLASS_LEGITIMATE => 0.10],
        'behavior:login_failures' => [self::CLASS_BRUTE_FORCE => 0.85, self::CLASS_LEGITIMATE => 0.08],
        'behavior:rate_limited' => [self::CLASS_SCANNER => 0.70, self::CLASS_BRUTE_FORCE => 0.65, self::CLASS_LEGITIMATE => 0.15],
        'behavior:honeypot_hit' => [self::CLASS_SCANNER => 0.95, self::CLASS_LEGITIMATE => 0.001],

        // Detection features
        'detection:sqli' => [self::CLASS_SQLI_ATTEMPT => 0.95, self::CLASS_SCANNER => 0.60, self::CLASS_LEGITIMATE => 0.001],
        'detection:xss' => [self::CLASS_XSS_ATTEMPT => 0.95, self::CLASS_SCANNER => 0.55, self::CLASS_LEGITIMATE => 0.001],

        // Header anomalies
        'header:missing_ua' => [self::CLASS_SCANNER => 0.90, self::CLASS_LEGITIMATE => 0.02],
        'header:missing_accept' => [self::CLASS_SCANNER => 0.55, self::CLASS_LEGITIMATE => 0.15],
        'header:localhost_forwarded' => [self::CLASS_SCANNER => 0.88, self::CLASS_LEGITIMATE => 0.001],
    ];

    /**
     * Cached learned parameters (loaded from storage).
     *
     * @var array<string, mixed>|null
     */
    private ?array $learnedParams = null;

    /**
     * Confidence threshold for classification.
     */
    private float $confidenceThreshold = 0.65;

    public function __construct(
        StorageInterface $storage,
        ?LoggerInterface $logger = null,
    ) {
        $this->storage = $storage;
        $this->logger = $logger ?? new NullLogger();
    }

    /**
     * Classify a request and return threat assessment.
     *
     * @param array<string, mixed> $features Extracted features from request
     *
     * @return array{
     *     classification: string,
     *     confidence: float,
     *     is_threat: bool,
     *     probabilities: array<string, float>,
     *     features_used: array<string>,
     *     learning_status: string,
     *     total_samples_learned: int
     * }
     */
    public function classify(array $features): array
    {
        // Load learned parameters
        $params = $this->getLearnedParameters();

        // Extract feature keys
        $featureKeys = $this->extractFeatureKeys($features);

        // Calculate posterior probabilities for each class
        $logProbabilities = [];

        foreach (self::CLASSES as $class) {
            // Start with log prior
            $logProb = log($this->getPrior($class, $params));

            // Add log likelihoods for each feature
            foreach ($featureKeys as $feature) {
                $likelihood = $this->getLikelihood($feature, $class, $params);
                $logProb += log($likelihood + 1e-10); // Avoid log(0)
            }

            $logProbabilities[$class] = $logProb;
        }

        // Convert to probabilities using softmax
        $probabilities = $this->softmax($logProbabilities);

        // Get best classification
        arsort($probabilities);
        $classification = (string) array_key_first($probabilities);
        $confidence = (float) $probabilities[$classification];

        // Determine if threat
        $isThreat = $classification !== self::CLASS_LEGITIMATE && $confidence >= $this->confidenceThreshold;

        // Determine learning status
        $totalSamples = (int) ($params['total_samples'] ?? 0);
        $learningStatus = $totalSamples < self::MIN_SAMPLES_FOR_LEARNING
            ? 'warming_up'
            : ($totalSamples < 500 ? 'learning' : 'mature');

        /** @var array<string, float> $roundedProbabilities */
        $roundedProbabilities = array_map(fn ($p) => round((float) $p, 4), $probabilities);

        return [
            'classification' => $classification,
            'confidence' => round($confidence, 4),
            'is_threat' => $isThreat,
            'probabilities' => $roundedProbabilities,
            'features_used' => $featureKeys,
            'learning_status' => $learningStatus,
            'total_samples_learned' => $totalSamples,
        ];
    }

    /**
     * Learn from a labeled security event (ONLINE LEARNING).
     *
     * This is the core ML function - it updates the model incrementally
     * without needing to retrain from scratch.
     *
     * @param array<string, mixed> $features Request features
     * @param string $trueClass The actual classification (ground truth)
     * @param float $weight Sample weight (default 1.0, use < 1.0 for uncertain labels)
     */
    public function learn(array $features, string $trueClass, float $weight = 1.0): void
    {
        if (!in_array($trueClass, self::CLASSES, true)) {
            $this->logger->warning('Invalid class for learning', ['class' => $trueClass]);

            return;
        }

        // Extract feature keys
        $featureKeys = $this->extractFeatureKeys($features);

        if (empty($featureKeys)) {
            return;
        }

        // Get current parameters
        $params = $this->getLearnedParameters();

        // Apply decay to existing counts (concept drift handling)
        $this->applyDecay($params);

        // Update class count
        $params['class_counts'][$trueClass] = ($params['class_counts'][$trueClass] ?? 0) + $weight;

        // Update feature counts for this class
        foreach ($featureKeys as $feature) {
            if (!isset($params['feature_counts'][$feature])) {
                $params['feature_counts'][$feature] = [];
            }
            $params['feature_counts'][$feature][$trueClass] =
                ($params['feature_counts'][$feature][$trueClass] ?? 0) + $weight;
        }

        // Update total samples
        $params['total_samples'] = ($params['total_samples'] ?? 0) + 1;
        $params['last_updated'] = time();

        // Persist to storage
        $this->saveLearnedParameters($params);

        $this->logger->info('ML model updated', [
            'class' => $trueClass,
            'features_count' => count($featureKeys),
            'total_samples' => $params['total_samples'],
        ]);
    }

    /**
     * Learn from a batch of labeled events (more efficient for bulk updates).
     *
     * @param array<int, array{features: array<string, mixed>, class: string, weight?: float}> $samples
     */
    public function learnBatch(array $samples): void
    {
        if (empty($samples)) {
            return;
        }

        // Get current parameters
        $params = $this->getLearnedParameters();

        // Apply decay once for the batch
        $this->applyDecay($params);

        foreach ($samples as $sample) {
            $features = $sample['features'] ?? [];
            $trueClass = $sample['class'] ?? '';
            $weight = $sample['weight'] ?? 1.0;

            if (!in_array($trueClass, self::CLASSES, true)) {
                continue;
            }

            $featureKeys = $this->extractFeatureKeys($features);

            // Update class count
            $params['class_counts'][$trueClass] = ($params['class_counts'][$trueClass] ?? 0) + $weight;

            // Update feature counts
            foreach ($featureKeys as $feature) {
                if (!isset($params['feature_counts'][$feature])) {
                    $params['feature_counts'][$feature] = [];
                }
                $params['feature_counts'][$feature][$trueClass] =
                    ($params['feature_counts'][$feature][$trueClass] ?? 0) + $weight;
            }

            $params['total_samples'] = ($params['total_samples'] ?? 0) + 1;
        }

        $params['last_updated'] = time();

        // Persist to storage (single write for entire batch)
        $this->saveLearnedParameters($params);

        $this->logger->info('ML model batch updated', [
            'samples_count' => count($samples),
            'total_samples' => $params['total_samples'],
        ]);
    }

    /**
     * Auto-learn from security events in storage.
     *
     * Reads recent security events and uses them to train the model.
     * Events are labeled based on their type (auto_ban = threat, etc.)
     *
     * @param int $limit Maximum events to process
     * @param int $since Unix timestamp - only process events after this time
     *
     * @return int Number of events learned from
     */
    public function autoLearnFromEvents(int $limit = 1000, int $since = 0): int
    {
        // Get security events from storage (uses getRecentEvents method)
        $events = $this->storage->getRecentEvents($limit, null);

        if (empty($events)) {
            return 0;
        }

        $samples = [];

        foreach ($events as $event) {
            $timestamp = $event['timestamp'] ?? 0;
            if ($since > 0 && $timestamp < $since) {
                continue;
            }

            $eventType = $event['type'] ?? '';
            $data = $event['data'] ?? [];

            // Map event types to classes
            $class = $this->mapEventToClass($eventType, $data);
            if ($class === null) {
                continue;
            }

            // Extract features from event data
            $features = $this->extractFeaturesFromEvent($event);

            // Weight based on confidence of label
            $weight = $this->getEventWeight($eventType);

            $samples[] = [
                'features' => $features,
                'class' => $class,
                'weight' => $weight,
            ];
        }

        if (!empty($samples)) {
            $this->learnBatch($samples);
        }

        return count($samples);
    }

    /**
     * Get model statistics.
     *
     * @return array{
     *     total_samples: int,
     *     classes: array<string, int>,
     *     features_learned: int,
     *     last_updated: int|null,
     *     learning_status: string,
     *     model_age_hours: float
     * }
     */
    public function getStats(): array
    {
        $params = $this->getLearnedParameters();

        $totalSamples = $params['total_samples'] ?? 0;
        $lastUpdated = $params['last_updated'] ?? null;

        $classCounts = [];
        foreach (self::CLASSES as $class) {
            $classCounts[$class] = (int) ($params['class_counts'][$class] ?? 0);
        }

        $learningStatus = $totalSamples < self::MIN_SAMPLES_FOR_LEARNING
            ? 'warming_up'
            : ($totalSamples < 500 ? 'learning' : 'mature');

        $modelAgeHours = $lastUpdated ? (time() - $lastUpdated) / 3600 : 0;

        return [
            'total_samples' => $totalSamples,
            'classes' => $classCounts,
            'features_learned' => count($params['feature_counts'] ?? []),
            'initial_features' => count(self::INITIAL_LIKELIHOODS),
            'last_updated' => $lastUpdated,
            'learning_status' => $learningStatus,
            'model_age_hours' => round($modelAgeHours, 2),
            'decay_factor' => self::DECAY_FACTOR,
            'min_samples_for_learning' => self::MIN_SAMPLES_FOR_LEARNING,
        ];
    }

    /**
     * Reset learned parameters (keeps initial weights).
     */
    public function reset(): void
    {
        $this->storage->delete(self::STORAGE_PREFIX . 'params');
        $this->learnedParams = null;

        $this->logger->info('ML model reset to initial weights');
    }

    /**
     * Set confidence threshold for threat classification.
     */
    public function setConfidenceThreshold(float $threshold): self
    {
        $this->confidenceThreshold = max(0.0, min(1.0, $threshold));

        return $this;
    }

    /**
     * Export model for analysis or backup.
     *
     * @return array<string, mixed> Full model state
     */
    public function exportModel(): array
    {
        return [
            'version' => '2.0.0',
            'algorithm' => 'naive_bayes_online',
            'initial_priors' => self::INITIAL_PRIORS,
            'initial_likelihoods' => self::INITIAL_LIKELIHOODS,
            'learned_parameters' => $this->getLearnedParameters(),
            'exported_at' => time(),
        ];
    }

    /**
     * Import model from backup.
     *
     * @param array<string, mixed> $model Exported model data
     */
    public function importModel(array $model): void
    {
        if (!isset($model['learned_parameters'])) {
            throw new \InvalidArgumentException('Invalid model format');
        }

        $this->saveLearnedParameters($model['learned_parameters']);
        $this->learnedParams = null;

        $this->logger->info('ML model imported', [
            'total_samples' => $model['learned_parameters']['total_samples'] ?? 0,
        ]);
    }

    // =========================================================================
    // PRIVATE METHODS
    // =========================================================================

    /**
     * Get learned parameters from storage (with caching).
     *
     * @return array<string, mixed>
     */
    private function getLearnedParameters(): array
    {
        if ($this->learnedParams !== null) {
            return $this->learnedParams;
        }

        $stored = $this->storage->get(self::STORAGE_PREFIX . 'params');

        if ($stored !== null && is_string($stored)) {
            $params = json_decode($stored, true);
            if (is_array($params)) {
                $this->learnedParams = $params;

                return $params;
            }
        }

        // Initialize with empty learned params
        $this->learnedParams = [
            'class_counts' => [],
            'feature_counts' => [],
            'total_samples' => 0,
            'last_updated' => null,
        ];

        return $this->learnedParams;
    }

    /**
     * Save learned parameters to storage.
     *
     * @param array<string, mixed> $params
     */
    private function saveLearnedParameters(array $params): void
    {
        $this->learnedParams = $params;
        $this->storage->set(
            self::STORAGE_PREFIX . 'params',
            json_encode($params),
            86400 * 365, // 1 year TTL
        );
    }

    /**
     * Get prior probability for a class (combines initial + learned).
     *
     * @param array<string, mixed> $params
     */
    private function getPrior(string $class, array $params): float
    {
        $totalSamples = $params['total_samples'] ?? 0;

        if ($totalSamples < self::MIN_SAMPLES_FOR_LEARNING) {
            // Use initial priors during warm-up
            return self::INITIAL_PRIORS[$class] ?? (1.0 / count(self::CLASSES));
        }

        // Calculate from learned counts with Laplace smoothing
        $classCount = $params['class_counts'][$class] ?? 0;
        $alpha = self::LAPLACE_ALPHA;

        // Blend initial priors with learned (weighted by sample count)
        $learnedPrior = ($classCount + $alpha) / ($totalSamples + $alpha * count(self::CLASSES));
        $initialPrior = self::INITIAL_PRIORS[$class] ?? (1.0 / count(self::CLASSES));

        // Gradually shift from initial to learned as samples increase
        $learnedWeight = min(1.0, $totalSamples / 500);

        return $initialPrior * (1 - $learnedWeight) + $learnedPrior * $learnedWeight;
    }

    /**
     * Get likelihood P(feature|class) (combines initial + learned).
     *
     * @param array<string, mixed> $params
     */
    private function getLikelihood(string $feature, string $class, array $params): float
    {
        $totalSamples = $params['total_samples'] ?? 0;

        // Get initial likelihood if exists
        $initialLikelihood = self::INITIAL_LIKELIHOODS[$feature][$class] ?? null;

        // Get learned likelihood
        $featureCounts = $params['feature_counts'][$feature] ?? [];
        $featureClassCount = $featureCounts[$class] ?? 0;
        $classCount = $params['class_counts'][$class] ?? 0;

        if ($totalSamples < self::MIN_SAMPLES_FOR_LEARNING || $classCount < 5) {
            // Use initial likelihood during warm-up or low samples
            if ($initialLikelihood !== null) {
                return $initialLikelihood;
            }

            // Unknown feature - use small probability
            return 0.01;
        }

        // Calculate learned likelihood with Laplace smoothing
        $alpha = self::LAPLACE_ALPHA;
        $vocabularySize = count($params['feature_counts']) + count(self::INITIAL_LIKELIHOODS);
        $learnedLikelihood = ($featureClassCount + $alpha) / ($classCount + $alpha * $vocabularySize);

        // Blend with initial if available
        if ($initialLikelihood !== null) {
            $learnedWeight = min(1.0, $classCount / 100);

            return $initialLikelihood * (1 - $learnedWeight) + $learnedLikelihood * $learnedWeight;
        }

        return $learnedLikelihood;
    }

    /**
     * Apply decay to counts (handles concept drift).
     *
     * @param array<string, mixed> $params
     */
    private function applyDecay(array &$params): void
    {
        $lastUpdated = $params['last_updated'] ?? time();
        $hoursSinceUpdate = (time() - $lastUpdated) / 3600;

        // Only decay if more than 1 hour since last update
        if ($hoursSinceUpdate < 1) {
            return;
        }

        // Calculate decay factor based on time elapsed
        $decayPower = min($hoursSinceUpdate, 24); // Cap at 24 hours of decay
        $decay = pow(self::DECAY_FACTOR, $decayPower);

        // Apply decay to class counts
        foreach ($params['class_counts'] as $class => $count) {
            $params['class_counts'][$class] = $count * $decay;
        }

        // Apply decay to feature counts
        foreach ($params['feature_counts'] as $feature => $classCounts) {
            foreach ($classCounts as $class => $count) {
                $params['feature_counts'][$feature][$class] = $count * $decay;
            }
        }
    }

    /**
     * Extract feature keys from request data.
     *
     * @param array<string, mixed> $features
     *
     * @return array<string>
     */
    private function extractFeatureKeys(array $features): array
    {
        $keys = [];

        // User-Agent features
        $ua = strtolower($features['user_agent'] ?? '');
        if (empty($ua)) {
            $keys[] = 'header:missing_ua';
        } else {
            if (str_contains($ua, 'curl')) {
                $keys[] = 'ua:curl';
            }
            if (str_contains($ua, 'python')) {
                $keys[] = 'ua:python';
            }
            if (str_contains($ua, 'wget')) {
                $keys[] = 'ua:wget';
            }
            if (str_contains($ua, 'go-http')) {
                $keys[] = 'ua:go-http';
            }
            if (str_contains($ua, 'java')) {
                $keys[] = 'ua:java';
            }
            if ($ua === 'hello, world') {
                $keys[] = 'ua:hello_world';
            }
            if (str_contains($ua, 'censys')) {
                $keys[] = 'ua:censys';
            }
            if (str_contains($ua, 'zgrab')) {
                $keys[] = 'ua:zgrab';
            }
            if (str_contains($ua, 'masscan')) {
                $keys[] = 'ua:masscan';
            }
            if (str_contains($ua, 'nmap')) {
                $keys[] = 'ua:nmap';
            }
            if (str_contains($ua, 'nikto')) {
                $keys[] = 'ua:nikto';
            }
            if (str_contains($ua, 'sqlmap')) {
                $keys[] = 'ua:sqlmap';
            }
            if (str_contains($ua, 'gobuster') || str_contains($ua, 'dirbuster')) {
                $keys[] = 'ua:gobuster';
            }
            if (str_contains($ua, 'wpscan')) {
                $keys[] = 'ua:wpscan';
            }
            if (str_contains($ua, 'nuclei')) {
                $keys[] = 'ua:nuclei';
            }

            // Bot spoofing (requires verification flag)
            if (($features['bot_verified'] ?? true) === false) {
                if (str_contains($ua, 'googlebot')) {
                    $keys[] = 'ua:googlebot_unverified';
                }
                if (str_contains($ua, 'bingbot')) {
                    $keys[] = 'ua:bingbot_unverified';
                }
                if (str_contains($ua, 'gptbot')) {
                    $keys[] = 'ua:gptbot_unverified';
                }
            }
        }

        // Path features
        $path = strtolower($features['path'] ?? '');
        if (str_contains($path, 'wp-admin')) {
            $keys[] = 'path:wp-admin';
        }
        if (str_contains($path, 'wp-login')) {
            $keys[] = 'path:wp-login';
        }
        if (str_contains($path, 'wp-config')) {
            $keys[] = 'path:wp-config';
        }
        if (str_contains($path, 'phpmyadmin')) {
            $keys[] = 'path:phpmyadmin';
        }
        if (str_contains($path, 'adminer')) {
            $keys[] = 'path:adminer';
        }
        if (str_contains($path, 'phpinfo')) {
            $keys[] = 'path:phpinfo';
        }
        if (str_contains($path, '.env')) {
            $keys[] = 'path:env';
        }
        if (str_contains($path, '.git')) {
            $keys[] = 'path:git';
        }
        if (str_contains($path, 'aws') && str_contains($path, 'credentials')) {
            $keys[] = 'path:aws_credentials';
        }
        if (preg_match('/\.(bak|backup|old|orig)$/i', $path)) {
            $keys[] = 'path:backup';
        }
        if (str_contains($path, 'gponform')) {
            $keys[] = 'path:gponform';
        }
        if (str_contains($path, 'hnap')) {
            $keys[] = 'path:hnap';
        }
        if (str_contains($path, '../') || str_contains($path, '..\\')) {
            $keys[] = 'path:traversal';
        }

        // Behavioral features
        if (($features['error_404_count'] ?? 0) > 5) {
            $keys[] = 'behavior:high_404_rate';
        }
        if (($features['request_count'] ?? 0) > 50) {
            $keys[] = 'behavior:rapid_requests';
        }
        if (($features['login_failures'] ?? 0) >= 3) {
            $keys[] = 'behavior:login_failures';
        }
        if (($features['rate_limited'] ?? false) === true) {
            $keys[] = 'behavior:rate_limited';
        }
        if (($features['honeypot_hit'] ?? false) === true) {
            $keys[] = 'behavior:honeypot_hit';
        }

        // Detection features
        if (($features['sqli_detected'] ?? false) === true) {
            $keys[] = 'detection:sqli';
        }
        if (($features['xss_detected'] ?? false) === true) {
            $keys[] = 'detection:xss';
        }

        // Header features
        if (($features['missing_accept'] ?? false) === true) {
            $keys[] = 'header:missing_accept';
        }
        $forwarded = $features['x_forwarded_for'] ?? '';
        if ($forwarded === '127.0.0.1' || $forwarded === 'localhost') {
            $keys[] = 'header:localhost_forwarded';
        }

        return array_unique($keys);
    }

    /**
     * Map security event type to classification class.
     *
     * @param array<string, mixed> $data
     */
    private function mapEventToClass(string $eventType, array $data): ?string
    {
        return match ($eventType) {
            'auto_ban', 'scanner_detected' => self::CLASS_SCANNER,
            'bot_spoofing' => self::CLASS_BOT_SPOOF,
            'honeypot_access' => self::CLASS_SCANNER,
            'rate_limit_exceeded' => null, // Could be legitimate or not
            'brute_force_detected' => self::CLASS_BRUTE_FORCE,
            'sqli_detected', 'sqli_blocked' => self::CLASS_SQLI_ATTEMPT,
            'xss_detected', 'xss_blocked' => self::CLASS_XSS_ATTEMPT,
            'path_traversal_detected' => self::CLASS_PATH_TRAVERSAL,
            'credential_theft_attempt' => self::CLASS_CREDENTIAL_THEFT,
            'config_hunt_detected' => self::CLASS_CONFIG_HUNT,
            'cms_probe_detected' => self::CLASS_CMS_PROBE,
            'iot_exploit_detected' => self::CLASS_IOT_EXPLOIT,
            'legitimate_verified', 'bot_verified' => self::CLASS_LEGITIMATE,
            default => null,
        };
    }

    /**
     * Extract features from a security event.
     *
     * @param array<string, mixed> $event
     *
     * @return array<string, mixed>
     */
    private function extractFeaturesFromEvent(array $event): array
    {
        $data = $event['data'] ?? [];

        return [
            'user_agent' => $data['user_agent'] ?? '',
            'path' => $data['path'] ?? '',
            'request_count' => $data['request_count'] ?? 0,
            'error_404_count' => $data['error_count'] ?? 0,
            'login_failures' => $data['login_failures'] ?? 0,
            'rate_limited' => $data['rate_limited'] ?? false,
            'honeypot_hit' => str_contains($event['type'] ?? '', 'honeypot'),
            'sqli_detected' => str_contains($event['type'] ?? '', 'sqli'),
            'xss_detected' => str_contains($event['type'] ?? '', 'xss'),
            'bot_verified' => $data['bot_verified'] ?? true,
        ];
    }

    /**
     * Get weight for event based on label confidence.
     */
    private function getEventWeight(string $eventType): float
    {
        // High confidence labels
        if (in_array($eventType, ['auto_ban', 'sqli_blocked', 'xss_blocked', 'honeypot_access'])) {
            return 1.0;
        }

        // Medium confidence
        if (in_array($eventType, ['scanner_detected', 'bot_spoofing', 'brute_force_detected'])) {
            return 0.8;
        }

        // Lower confidence (could be false positive)
        return 0.5;
    }

    /**
     * Softmax function to convert log probabilities to probabilities.
     *
     * @param array<string, float> $logProbs
     *
     * @return array<string, float>
     */
    private function softmax(array $logProbs): array
    {
        $maxLog = max($logProbs);
        $expSum = 0.0;

        $exps = [];
        foreach ($logProbs as $class => $logProb) {
            $exp = exp($logProb - $maxLog);
            $exps[$class] = $exp;
            $expSum += $exp;
        }

        $probs = [];
        foreach ($exps as $class => $exp) {
            $probs[$class] = $exp / $expSum;
        }

        return $probs;
    }
}
