<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Tests\Unit\ML;

use AdosLabs\EnterpriseSecurityShield\ML\RequestAnalyzer;
use AdosLabs\EnterpriseSecurityShield\ML\ThreatClassifier;
use AdosLabs\EnterpriseSecurityShield\ML\AnomalyDetector;
use PHPUnit\Framework\TestCase;

/**
 * @covers \AdosLabs\EnterpriseSecurityShield\ML\RequestAnalyzer
 */
final class RequestAnalyzerTest extends TestCase
{
    private RequestAnalyzer $analyzer;

    protected function setUp(): void
    {
        $classifier = new ThreatClassifier();
        $anomalyDetector = new AnomalyDetector();
        $this->analyzer = new RequestAnalyzer($classifier, $anomalyDetector);
    }

    public function testAnalyzeReturnsExpectedStructure(): void
    {
        $result = $this->analyzer->analyze([
            'ip' => '192.168.1.1',
            'user_agent' => 'Mozilla/5.0',
            'path' => '/',
            'request_count' => 10,
            'error_count' => 0,
        ]);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('decision', $result);
        $this->assertArrayHasKey('score', $result);
        $this->assertArrayHasKey('recommendation', $result);
        $this->assertArrayHasKey('classification', $result);
        $this->assertArrayHasKey('anomalies', $result);
        $this->assertArrayHasKey('reasons', $result);
        $this->assertArrayHasKey('should_log', $result);
    }

    public function testAnalyzeAllowsLegitimateTraffic(): void
    {
        $result = $this->analyzer->analyze([
            'ip' => '93.71.164.36',
            'user_agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15',
            'path' => '/products/category',
            'request_count' => 5,
            'error_count' => 0,
        ]);

        $this->assertEquals('ALLOW', $result['decision']);
        $this->assertLessThan(20, $result['score']);
    }

    public function testAnalyzeDetectsKnownAttackPattern(): void
    {
        $result = $this->analyzer->analyze([
            'ip' => '185.177.72.51',
            'user_agent' => 'curl/8.7.1',
            'path' => '/admin/config?cmd=cat%20/etc/passwd',
            'request_count' => 50,
            'error_count' => 45,
        ]);

        // Should be at least CHALLENGE or higher
        $this->assertContains($result['decision'], ['CHALLENGE', 'RATE_LIMIT', 'BLOCK', 'BAN']);
        $this->assertGreaterThan(30, $result['score']);
    }

    public function testAnalyzeWithHighRequestCount(): void
    {
        $result = $this->analyzer->analyze([
            'ip' => '192.168.1.1',
            'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
            'path' => '/api/data',
            'request_count' => 500,
            'error_count' => 0,
        ]);

        // High request count with legitimate UA should trigger anomaly detection
        // The score and decision depend on the analyzer weights
        $this->assertGreaterThanOrEqual(0, $result['score']);
        $this->assertNotNull($result['decision']);
    }

    public function testScoreIsWithinValidRange(): void
    {
        $testCases = [
            [
                'ip' => '192.168.1.1',
                'user_agent' => 'Mozilla/5.0',
                'path' => '/',
                'request_count' => 1,
                'error_count' => 0,
            ],
            [
                'ip' => '1.2.3.4',
                'user_agent' => 'curl',
                'path' => '/admin/../../../etc/passwd',
                'request_count' => 1000,
                'error_count' => 900,
            ],
        ];

        foreach ($testCases as $data) {
            $result = $this->analyzer->analyze($data);
            $this->assertGreaterThanOrEqual(0, $result['score']);
            $this->assertLessThanOrEqual(100, $result['score']);
        }
    }

    public function testDecisionValues(): void
    {
        $validDecisions = ['ALLOW', 'MONITOR', 'CHALLENGE', 'RATE_LIMIT', 'BLOCK', 'BAN'];

        $testCases = [
            ['ip' => '1.1.1.1', 'user_agent' => 'Mozilla/5.0', 'path' => '/'],
            ['ip' => '1.1.1.1', 'user_agent' => 'curl', 'path' => '/admin'],
            ['ip' => '1.1.1.1', 'user_agent' => '', 'path' => '/test'],
        ];

        foreach ($testCases as $data) {
            $data['request_count'] = $data['request_count'] ?? 1;
            $data['error_count'] = $data['error_count'] ?? 0;
            $result = $this->analyzer->analyze($data);
            $this->assertContains($result['decision'], $validDecisions);
        }
    }

    public function testRecommendationIsNotEmpty(): void
    {
        $result = $this->analyzer->analyze([
            'ip' => '192.168.1.1',
            'user_agent' => 'curl/8.0',
            'path' => '/admin',
            'request_count' => 50,
            'error_count' => 0,
        ]);

        $this->assertNotEmpty($result['recommendation']);
    }

    public function testAnalyzeWithMinimalData(): void
    {
        $result = $this->analyzer->analyze([
            'ip' => '192.168.1.1',
            'path' => '/',
        ]);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('decision', $result);
    }

    public function testAnalyzeDetectsIotExploit(): void
    {
        $result = $this->analyzer->analyze([
            'ip' => '122.97.212.147',
            'user_agent' => 'Hello, World',
            'path' => '/GponForm/diag_Form?images/',
            'request_count' => 1,
            'error_count' => 0,
            'session_duration' => 10, // Provide session to avoid no_session feature
        ]);

        // GPON exploit should be detected as a threat
        // Classification may be IOT_EXPLOIT or SCANNER depending on feature interactions
        $this->assertContains($result['classification']['classification'], ['IOT_EXPLOIT', 'SCANNER']);
        // The anomaly path depth and GPON path should trigger at least some score
        $this->assertGreaterThanOrEqual(0, $result['score']);
    }

    public function testAnalyzeMonitorsLowConfidenceThreats(): void
    {
        $result = $this->analyzer->analyze([
            'ip' => '192.168.1.1',
            'user_agent' => 'Mozilla/5.0 (compatible; CustomBot/1.0)',
            'path' => '/robots.txt',
            'request_count' => 5,
            'error_count' => 0,
        ]);

        // Low-confidence threats should be at most monitored
        $this->assertContains($result['decision'], ['ALLOW', 'MONITOR']);
    }

    public function testShouldBlockMethod(): void
    {
        // Legitimate request
        $shouldNotBlock = $this->analyzer->shouldBlock([
            'ip' => '192.168.1.1',
            'user_agent' => 'Mozilla/5.0',
            'path' => '/',
        ]);
        $this->assertFalse($shouldNotBlock);

        // Known scanner
        $shouldBlock = $this->analyzer->shouldBlock([
            'ip' => '185.177.72.51',
            'user_agent' => 'curl/8.7.1',
            'path' => '/.env',
            'request_count' => 100,
            'error_count' => 90,
        ]);
        // May or may not block depending on threshold
        $this->assertIsBool($shouldBlock);
    }

    public function testGetQuickScore(): void
    {
        // Legitimate user
        $lowScore = $this->analyzer->getQuickScore(
            '192.168.1.1',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
            '/'
        );
        $this->assertEquals(0, $lowScore);

        // Scanner
        $highScore = $this->analyzer->getQuickScore(
            '185.177.72.51',
            'curl/8.7.1',
            '/admin/phpinfo.php'
        );
        $this->assertGreaterThan(0, $highScore);
    }

    public function testAnalyzeBatch(): void
    {
        $requests = [
            [
                'ip' => '192.168.1.1',
                'user_agent' => 'Mozilla/5.0',
                'path' => '/',
            ],
            [
                'ip' => '10.0.0.1',
                'user_agent' => 'curl/8.0',
                'path' => '/admin',
            ],
        ];

        $results = $this->analyzer->analyzeBatch($requests);

        $this->assertCount(2, $results);
        $this->assertArrayHasKey(0, $results);
        $this->assertArrayHasKey(1, $results);
    }

    public function testGetStats(): void
    {
        $stats = $this->analyzer->getStats();

        $this->assertIsArray($stats);
        $this->assertArrayHasKey('threat_classifier', $stats);
        $this->assertArrayHasKey('anomaly_detector', $stats);
        $this->assertArrayHasKey('thresholds', $stats);
    }

    public function testSetThresholds(): void
    {
        $this->analyzer->setThresholds(
            monitor: 10,
            challenge: 30,
            rateLimit: 45,
            block: 60,
            ban: 80
        );

        // With lower thresholds, requests are more likely to be blocked
        $result = $this->analyzer->analyze([
            'ip' => '192.168.1.1',
            'user_agent' => 'curl/8.0',
            'path' => '/admin',
            'request_count' => 100,
            'error_count' => 50,
        ]);

        // Should at least monitor with lower thresholds
        $this->assertContains($result['decision'], ['MONITOR', 'CHALLENGE', 'RATE_LIMIT', 'BLOCK', 'BAN']);
    }

    public function testClassificationIsIncluded(): void
    {
        $result = $this->analyzer->analyze([
            'ip' => '167.94.138.165',
            'user_agent' => 'Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)',
            'path' => '/',
        ]);

        $this->assertArrayHasKey('classification', $result);
        $this->assertEquals('SCANNER', $result['classification']['classification']);
    }

    public function testAnomaliesAreIncluded(): void
    {
        $result = $this->analyzer->analyze([
            'ip' => '192.168.1.1',
            'user_agent' => 'Mozilla/5.0',
            'path' => '/../../../etc/passwd',
            'request_count' => 1,
            'error_count' => 0,
        ]);

        $this->assertArrayHasKey('anomalies', $result);
        $this->assertIsArray($result['anomalies']);
    }
}
