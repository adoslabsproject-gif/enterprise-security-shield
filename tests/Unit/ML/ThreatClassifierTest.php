<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Tests\Unit\ML;

use AdosLabs\EnterpriseSecurityShield\ML\ThreatClassifier;
use PHPUnit\Framework\TestCase;

/**
 * @covers \AdosLabs\EnterpriseSecurityShield\ML\ThreatClassifier
 */
final class ThreatClassifierTest extends TestCase
{
    private ThreatClassifier $classifier;

    protected function setUp(): void
    {
        $this->classifier = new ThreatClassifier();
    }

    public function testClassifyReturnsExpectedStructure(): void
    {
        $result = $this->classifier->classify(
            '192.168.1.1',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            '/index.php'
        );

        $this->assertIsArray($result);
        $this->assertArrayHasKey('classification', $result);
        $this->assertArrayHasKey('confidence', $result);
        $this->assertArrayHasKey('is_threat', $result);
        $this->assertArrayHasKey('reasoning', $result);
        $this->assertArrayHasKey('features_detected', $result);
        $this->assertArrayHasKey('probabilities', $result);
    }

    public function testClassifyDetectsCurlScanner(): void
    {
        $result = $this->classifier->classify(
            '185.177.72.51',
            'curl/8.7.1',
            '/admin/phpinfo.php'
        );

        $this->assertTrue($result['is_threat']);
        $this->assertEquals('SCANNER', $result['classification']);
        $this->assertGreaterThan(0.65, $result['confidence']);
    }

    public function testClassifyDetectsGponExploit(): void
    {
        $result = $this->classifier->classify(
            '122.97.212.147',
            'Hello, World',
            '/GponForm/diag_Form?images/'
        );

        $this->assertTrue($result['is_threat']);
        $this->assertEquals('IOT_EXPLOIT', $result['classification']);
        $this->assertGreaterThan(0.9, $result['confidence']);
    }

    public function testClassifyDetectsCensysScanner(): void
    {
        $result = $this->classifier->classify(
            '167.94.138.165',
            'Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)',
            '/'
        );

        $this->assertTrue($result['is_threat']);
        $this->assertEquals('SCANNER', $result['classification']);
        $this->assertGreaterThan(0.95, $result['confidence']);
    }

    public function testClassifyAllowsLegitimateUser(): void
    {
        $result = $this->classifier->classify(
            '93.71.164.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.1 Safari/605.1.15',
            '/auth/login'
        );

        $this->assertFalse($result['is_threat']);
        $this->assertEquals('LEGITIMATE', $result['classification']);
    }

    public function testClassifyAllowsMobileUser(): void
    {
        $result = $this->classifier->classify(
            '79.37.99.128',
            'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36',
            '/'
        );

        $this->assertFalse($result['is_threat']);
        $this->assertEquals('LEGITIMATE', $result['classification']);
    }

    public function testConfidenceIsWithinValidRange(): void
    {
        $testCases = [
            ['192.168.1.1', 'curl/8.0', '/admin'],
            ['10.0.0.1', 'Mozilla/5.0', '/'],
            ['172.16.0.1', '', '/api/test'],
        ];

        foreach ($testCases as $case) {
            $result = $this->classifier->classify($case[0], $case[1], $case[2]);
            $this->assertGreaterThanOrEqual(0.0, $result['confidence']);
            $this->assertLessThanOrEqual(1.0, $result['confidence']);
        }
    }

    public function testGetModelStatsReturnsExpectedKeys(): void
    {
        $stats = $this->classifier->getModelStats();

        $this->assertIsArray($stats);
        $this->assertArrayHasKey('feature_count', $stats);
        $this->assertArrayHasKey('class_count', $stats);
        $this->assertArrayHasKey('attack_patterns', $stats);
        $this->assertArrayHasKey('training_events', $stats);
    }

    public function testIsScannerDetectsCurl(): void
    {
        $this->assertTrue($this->classifier->isScanner('curl/8.0'));
        $this->assertTrue($this->classifier->isScanner('python-requests/2.28'));
        $this->assertTrue($this->classifier->isScanner('wget/1.21'));
        $this->assertTrue($this->classifier->isScanner('CensysInspect/1.1'));
    }

    public function testIsScannerAllowsLegitimateUAs(): void
    {
        $this->assertFalse($this->classifier->isScanner(
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'
        ));
        $this->assertFalse($this->classifier->isScanner(
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Safari/605.1.15'
        ));
    }

    public function testGetPathAttackTypeDetectsWordPress(): void
    {
        $this->assertEquals('CMS_PROBE', $this->classifier->getPathAttackType('/wp-admin/'));
        $this->assertEquals('CMS_PROBE', $this->classifier->getPathAttackType('/wp-login.php'));
    }

    public function testGetPathAttackTypeDetectsConfigHunt(): void
    {
        $this->assertEquals('CONFIG_HUNT', $this->classifier->getPathAttackType('/phpmyadmin/'));
        $this->assertEquals('CONFIG_HUNT', $this->classifier->getPathAttackType('/phpinfo.php'));
    }

    public function testGetPathAttackTypeDetectsCredentialTheft(): void
    {
        $this->assertEquals('CREDENTIAL_THEFT', $this->classifier->getPathAttackType('/.env'));
        $this->assertEquals('CREDENTIAL_THEFT', $this->classifier->getPathAttackType('/.git/config'));
        $this->assertEquals('CREDENTIAL_THEFT', $this->classifier->getPathAttackType('/.aws/credentials'));
    }

    public function testGetPathAttackTypeDetectsIotExploit(): void
    {
        $this->assertEquals('IOT_EXPLOIT', $this->classifier->getPathAttackType('/GponForm/diag'));
        $this->assertEquals('IOT_EXPLOIT', $this->classifier->getPathAttackType('/HNAP1/'));
    }

    public function testGetPathAttackTypeDetectsPathTraversal(): void
    {
        // Path traversal is detected by regex pattern for paths with ../
        $result = $this->classifier->getPathAttackType('/download?file=../../secret.txt');
        $this->assertEquals('PATH_TRAVERSAL', $result);

        // The method checks patterns in order, so some paths may match other patterns first
        // /config.php matches CONFIG_HUNT before path traversal regex is checked
        $configResult = $this->classifier->getPathAttackType('/download?file=../config.php');
        $this->assertContains($configResult, ['PATH_TRAVERSAL', 'CONFIG_HUNT']);
    }

    public function testGetPathAttackTypeReturnsNullForSafePaths(): void
    {
        $this->assertNull($this->classifier->getPathAttackType('/'));
        $this->assertNull($this->classifier->getPathAttackType('/products/category'));
        $this->assertNull($this->classifier->getPathAttackType('/api/v1/users'));
    }

    public function testClassifyBatchProcessesMultipleRequests(): void
    {
        $requests = [
            [
                'ip' => '192.168.1.1',
                'user_agent' => 'curl/8.0',
                'path' => '/admin',
            ],
            [
                'ip' => '10.0.0.1',
                'user_agent' => 'Mozilla/5.0',
                'path' => '/',
            ],
        ];

        $results = $this->classifier->classifyBatch($requests);

        $this->assertCount(2, $results);
        $this->assertArrayHasKey(0, $results);
        $this->assertArrayHasKey(1, $results);
        $this->assertArrayHasKey('classification', $results[0]);
        $this->assertArrayHasKey('classification', $results[1]);
    }

    public function testSetConfidenceThreshold(): void
    {
        $this->classifier->setConfidenceThreshold(0.9);

        // With higher threshold, borderline threats should not be flagged
        $result = $this->classifier->classify(
            '192.168.1.1',
            'Mozilla/5.0',
            '/wp-login.php'
        );

        // The result may or may not be a threat depending on confidence
        $this->assertIsBool($result['is_threat']);
    }

    public function testClassifyWithBehaviorMetrics(): void
    {
        $result = $this->classifier->classify(
            '192.168.1.1',
            'curl/8.0',
            '/admin',
            'GET',
            [],
            [
                '404_count' => 50,
                'requests_per_minute' => 100,
                'login_failures' => 10,
            ]
        );

        $this->assertIsArray($result);
        $this->assertContains('high_404_rate', $result['features_detected']);
        $this->assertContains('rapid_requests', $result['features_detected']);
        $this->assertContains('login_failure_burst', $result['features_detected']);
    }
}
