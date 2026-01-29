<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Tests\Unit\ML;

use AdosLabs\EnterpriseSecurityShield\Contracts\StorageInterface;
use AdosLabs\EnterpriseSecurityShield\ML\OnlineLearningClassifier;
use PHPUnit\Framework\TestCase;

/**
 * @covers \AdosLabs\EnterpriseSecurityShield\ML\OnlineLearningClassifier
 */
final class OnlineLearningClassifierTest extends TestCase
{
    private OnlineLearningClassifier $classifier;

    private StorageInterface $storage;

    protected function setUp(): void
    {
        $this->storage = $this->createMock(StorageInterface::class);
        $this->storage->method('get')->willReturn(null);
        $this->storage->method('set')->willReturn(true);

        $this->classifier = new OnlineLearningClassifier($this->storage);
    }

    public function testClassifyReturnsExpectedStructure(): void
    {
        $result = $this->classifier->classify([
            'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'path' => '/index.php',
        ]);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('classification', $result);
        $this->assertArrayHasKey('confidence', $result);
        $this->assertArrayHasKey('is_threat', $result);
        $this->assertArrayHasKey('probabilities', $result);
        $this->assertArrayHasKey('features_used', $result);
        $this->assertArrayHasKey('learning_status', $result);
        $this->assertArrayHasKey('total_samples_learned', $result);
    }

    public function testClassifyDetectsCurlScanner(): void
    {
        $result = $this->classifier->classify([
            'user_agent' => 'curl/8.7.1',
            'path' => '/admin/phpinfo.php',
        ]);

        $this->assertTrue($result['is_threat']);
        $this->assertContains($result['classification'], [
            OnlineLearningClassifier::CLASS_SCANNER,
            OnlineLearningClassifier::CLASS_CONFIG_HUNT,
        ]);
        $this->assertContains('ua:curl', $result['features_used']);
    }

    public function testClassifyDetectsGponExploit(): void
    {
        $result = $this->classifier->classify([
            'user_agent' => 'Hello, World',
            'path' => '/GponForm/diag_Form?images/',
        ]);

        $this->assertTrue($result['is_threat']);
        $this->assertContains('path:gponform', $result['features_used']);
    }

    public function testClassifyDetectsCensysScanner(): void
    {
        $result = $this->classifier->classify([
            'user_agent' => 'Mozilla/5.0 (compatible; CensysInspect/1.1)',
            'path' => '/',
        ]);

        $this->assertTrue($result['is_threat']);
        $this->assertEquals(OnlineLearningClassifier::CLASS_SCANNER, $result['classification']);
        $this->assertContains('ua:censys', $result['features_used']);
    }

    public function testClassifyAllowsLegitimateUser(): void
    {
        $result = $this->classifier->classify([
            'user_agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
            'path' => '/auth/login',
        ]);

        $this->assertFalse($result['is_threat']);
        $this->assertEquals(OnlineLearningClassifier::CLASS_LEGITIMATE, $result['classification']);
    }

    public function testConfidenceIsWithinValidRange(): void
    {
        $testCases = [
            ['user_agent' => 'curl/8.0', 'path' => '/admin'],
            ['user_agent' => 'Mozilla/5.0', 'path' => '/'],
            ['user_agent' => '', 'path' => '/api/test'],
        ];

        foreach ($testCases as $features) {
            $result = $this->classifier->classify($features);
            $this->assertGreaterThanOrEqual(0.0, $result['confidence']);
            $this->assertLessThanOrEqual(1.0, $result['confidence']);
        }
    }

    public function testLearnAddsToModel(): void
    {
        // Mock storage to capture set calls
        $storage = $this->createMock(StorageInterface::class);
        $storage->method('get')->willReturn(null);
        $storage->expects($this->atLeastOnce())
            ->method('set')
            ->willReturn(true);

        $classifier = new OnlineLearningClassifier($storage);

        $classifier->learn(
            ['user_agent' => 'curl/8.0', 'path' => '/admin'],
            OnlineLearningClassifier::CLASS_SCANNER,
            1.0,
        );

        // Stats should reflect the learned sample
        $stats = $classifier->getStats();
        $this->assertEquals(1, $stats['total_samples']);
    }

    public function testLearnBatchProcessesMultipleSamples(): void
    {
        $storage = $this->createMock(StorageInterface::class);
        $storage->method('get')->willReturn(null);
        $storage->method('set')->willReturn(true);

        $classifier = new OnlineLearningClassifier($storage);

        $samples = [
            [
                'features' => ['user_agent' => 'curl/8.0', 'path' => '/admin'],
                'class' => OnlineLearningClassifier::CLASS_SCANNER,
            ],
            [
                'features' => ['user_agent' => 'sqlmap/1.0', 'path' => '/login'],
                'class' => OnlineLearningClassifier::CLASS_SQLI_ATTEMPT,
            ],
            [
                'features' => ['user_agent' => 'Mozilla/5.0', 'path' => '/'],
                'class' => OnlineLearningClassifier::CLASS_LEGITIMATE,
            ],
        ];

        $classifier->learnBatch($samples);

        $stats = $classifier->getStats();
        $this->assertEquals(3, $stats['total_samples']);
    }

    public function testGetStatsReturnsExpectedKeys(): void
    {
        $stats = $this->classifier->getStats();

        $this->assertIsArray($stats);
        $this->assertArrayHasKey('total_samples', $stats);
        $this->assertArrayHasKey('classes', $stats);
        $this->assertArrayHasKey('features_learned', $stats);
        $this->assertArrayHasKey('initial_features', $stats);
        $this->assertArrayHasKey('learning_status', $stats);
        $this->assertArrayHasKey('decay_factor', $stats);
        $this->assertArrayHasKey('min_samples_for_learning', $stats);
    }

    public function testResetClearsLearnedData(): void
    {
        $storage = $this->createMock(StorageInterface::class);
        $storage->method('get')->willReturn(null);
        $storage->method('set')->willReturn(true);
        $storage->expects($this->atLeastOnce())
            ->method('delete')
            ->with($this->stringContains('ml:classifier:'))
            ->willReturn(true);

        $classifier = new OnlineLearningClassifier($storage);

        // Learn something
        $classifier->learn(
            ['user_agent' => 'curl/8.0', 'path' => '/admin'],
            OnlineLearningClassifier::CLASS_SCANNER,
        );

        // Reset
        $classifier->reset();

        $stats = $classifier->getStats();
        $this->assertEquals(0, $stats['total_samples']);
    }

    public function testSetConfidenceThreshold(): void
    {
        $this->classifier->setConfidenceThreshold(0.9);

        $result = $this->classifier->classify([
            'user_agent' => 'Mozilla/5.0',
            'path' => '/wp-login.php',
        ]);

        // With higher threshold, borderline threats should not be flagged
        $this->assertIsBool($result['is_threat']);
    }

    public function testExportModelReturnsValidFormat(): void
    {
        $exported = $this->classifier->exportModel();

        $this->assertIsArray($exported);
        $this->assertArrayHasKey('version', $exported);
        $this->assertArrayHasKey('algorithm', $exported);
        $this->assertArrayHasKey('initial_priors', $exported);
        $this->assertArrayHasKey('initial_likelihoods', $exported);
        $this->assertArrayHasKey('learned_parameters', $exported);
        $this->assertArrayHasKey('exported_at', $exported);
        $this->assertEquals('naive_bayes_online', $exported['algorithm']);
    }

    public function testImportModelRestoresState(): void
    {
        $learnedParams = [
            'class_counts' => [OnlineLearningClassifier::CLASS_SCANNER => 100],
            'feature_counts' => ['ua:curl' => [OnlineLearningClassifier::CLASS_SCANNER => 80]],
            'total_samples' => 100,
            'last_updated' => time(),
        ];

        // Use a real in-memory storage simulation
        $storedData = null;

        $storage = $this->createMock(StorageInterface::class);
        $storage->method('set')->willReturnCallback(function ($key, $value) use (&$storedData) {
            $storedData = $value;

            return true;
        });
        $storage->method('get')->willReturnCallback(function () use (&$storedData) {
            return $storedData;
        });

        $classifier = new OnlineLearningClassifier($storage);

        $model = [
            'version' => '2.0.0',
            'learned_parameters' => $learnedParams,
        ];

        $classifier->importModel($model);

        // After import, getStats should read from storage and find the imported data
        $stats = $classifier->getStats();
        $this->assertEquals(100, $stats['total_samples']);
    }

    public function testImportModelThrowsOnInvalidFormat(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->classifier->importModel(['invalid' => 'data']);
    }

    public function testLearningStatusProgression(): void
    {
        $storage = $this->createMock(StorageInterface::class);
        $storage->method('set')->willReturn(true);

        // Test warming_up status (< 50 samples)
        $storage->method('get')->willReturn(json_encode([
            'class_counts' => [],
            'feature_counts' => [],
            'total_samples' => 10,
            'last_updated' => time(),
        ]));

        $classifier = new OnlineLearningClassifier($storage);
        $result = $classifier->classify(['user_agent' => 'Mozilla/5.0', 'path' => '/']);
        $this->assertEquals('warming_up', $result['learning_status']);
    }

    public function testDetectsPathTraversal(): void
    {
        $result = $this->classifier->classify([
            'user_agent' => 'Mozilla/5.0',
            'path' => '/download?file=../../etc/passwd',
        ]);

        $this->assertContains('path:traversal', $result['features_used']);
    }

    public function testDetectsCredentialTheft(): void
    {
        $result = $this->classifier->classify([
            'user_agent' => 'curl/8.0',
            'path' => '/.env',
        ]);

        $this->assertTrue($result['is_threat']);
        $this->assertContains('path:env', $result['features_used']);
    }

    public function testDetectsBotSpoofing(): void
    {
        $result = $this->classifier->classify([
            'user_agent' => 'Googlebot/2.1',
            'path' => '/',
            'bot_verified' => false,
        ]);

        $this->assertContains('ua:googlebot_unverified', $result['features_used']);
    }

    public function testDetectsBehavioralPatterns(): void
    {
        $result = $this->classifier->classify([
            'user_agent' => 'Mozilla/5.0',
            'path' => '/',
            'error_404_count' => 50,
            'request_count' => 100,
            'rate_limited' => true,
        ]);

        $this->assertContains('behavior:high_404_rate', $result['features_used']);
        $this->assertContains('behavior:rapid_requests', $result['features_used']);
        $this->assertContains('behavior:rate_limited', $result['features_used']);
    }

    public function testDetectsMissingUserAgent(): void
    {
        $result = $this->classifier->classify([
            'user_agent' => '',
            'path' => '/',
        ]);

        $this->assertContains('header:missing_ua', $result['features_used']);
    }

    public function testDetectionFeatures(): void
    {
        $result = $this->classifier->classify([
            'user_agent' => 'Mozilla/5.0',
            'path' => '/search',
            'sqli_detected' => true,
            'xss_detected' => true,
        ]);

        $this->assertContains('detection:sqli', $result['features_used']);
        $this->assertContains('detection:xss', $result['features_used']);
    }

    public function testAllClassesAreDefined(): void
    {
        $expectedClasses = [
            'CLASS_SCANNER',
            'CLASS_BOT_SPOOF',
            'CLASS_CMS_PROBE',
            'CLASS_CONFIG_HUNT',
            'CLASS_PATH_TRAVERSAL',
            'CLASS_CREDENTIAL_THEFT',
            'CLASS_IOT_EXPLOIT',
            'CLASS_BRUTE_FORCE',
            'CLASS_SQLI_ATTEMPT',
            'CLASS_XSS_ATTEMPT',
            'CLASS_LEGITIMATE',
        ];

        $reflection = new \ReflectionClass(OnlineLearningClassifier::class);

        foreach ($expectedClasses as $class) {
            $this->assertTrue(
                $reflection->hasConstant($class),
                "Missing constant: {$class}",
            );
        }
    }

    public function testProbabilitiesSumToOne(): void
    {
        $result = $this->classifier->classify([
            'user_agent' => 'curl/8.0',
            'path' => '/admin',
        ]);

        $sum = array_sum($result['probabilities']);
        $this->assertEqualsWithDelta(1.0, $sum, 0.001);
    }

    public function testLearnIgnoresInvalidClass(): void
    {
        $storage = $this->createMock(StorageInterface::class);
        $storage->method('get')->willReturn(null);
        // set should NOT be called for invalid class
        $storage->expects($this->never())->method('set');

        $classifier = new OnlineLearningClassifier($storage);

        $classifier->learn(
            ['user_agent' => 'curl/8.0'],
            'INVALID_CLASS',
        );
    }
}
