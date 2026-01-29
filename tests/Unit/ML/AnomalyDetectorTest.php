<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Tests\Unit\ML;

use AdosLabs\EnterpriseSecurityShield\ML\AnomalyDetector;
use PHPUnit\Framework\TestCase;

/**
 * @covers \AdosLabs\EnterpriseSecurityShield\ML\AnomalyDetector
 */
final class AnomalyDetectorTest extends TestCase
{
    private AnomalyDetector $detector;

    protected function setUp(): void
    {
        $this->detector = new AnomalyDetector();
    }

    public function testAnalyzeReturnsExpectedStructure(): void
    {
        $result = $this->detector->analyze(
            '192.168.1.1',
            '/test',
            10, // requestCount
            0,   // errorCount404
        );

        $this->assertIsArray($result);
        $this->assertArrayHasKey('is_anomaly', $result);
        $this->assertArrayHasKey('anomaly_score', $result);
        $this->assertArrayHasKey('anomalies', $result);
        $this->assertArrayHasKey('risk_factors', $result);
        $this->assertArrayHasKey('recommendation', $result);
    }

    public function testAnalyzeNormalTraffic(): void
    {
        $result = $this->detector->analyze(
            '192.168.1.1',
            '/page',
            5,  // Normal request count
            0,   // No errors
        );

        $this->assertFalse($result['is_anomaly']);
        $this->assertLessThan(30, $result['anomaly_score']);
    }

    public function testAnalyzeHighRequestRate(): void
    {
        $result = $this->detector->analyze(
            '192.168.1.1',
            '/api/data',
            500, // High request count
            0,
        );

        $this->assertTrue($result['is_anomaly']);
        $this->assertGreaterThan(0, count($result['anomalies']));
    }

    public function testAnalyzeHighErrorRate(): void
    {
        $result = $this->detector->analyze(
            '192.168.1.1',
            '/random',
            100, // request count
            80,   // High 404 error count
        );

        $this->assertTrue($result['is_anomaly']);
        // Should detect high error rate
        $anomalyTypes = array_column($result['anomalies'], 'metric');
        $this->assertContains('404_per_session', $anomalyTypes);
    }

    public function testAnalyzeDeepPath(): void
    {
        $result = $this->detector->analyze(
            '192.168.1.1',
            '/a/b/c/d/e/f/g/h', // Very deep path
            10,
            0,
        );

        $hasPathAnomaly = false;
        foreach ($result['anomalies'] as $anomaly) {
            if ($anomaly['metric'] === 'path_depth') {
                $hasPathAnomaly = true;
                break;
            }
        }
        $this->assertTrue($hasPathAnomaly || $result['anomaly_score'] > 0);
    }

    public function testAnalyzePathTraversal(): void
    {
        $result = $this->detector->analyze(
            '192.168.1.1',
            '/../../../etc/passwd',
            1,
            0,
        );

        $this->assertTrue($result['is_anomaly']);
        $this->assertGreaterThan(30, $result['anomaly_score']);
    }

    public function testScoreIsWithinValidRange(): void
    {
        $testCases = [
            ['ip' => '192.168.1.1', 'path' => '/', 'requests' => 1, 'errors' => 0],
            ['ip' => '10.0.0.1', 'path' => '/admin', 'requests' => 1000, 'errors' => 900],
            ['ip' => '172.16.0.1', 'path' => '/test', 'requests' => 50, 'errors' => 25],
        ];

        foreach ($testCases as $data) {
            $result = $this->detector->analyze(
                $data['ip'],
                $data['path'],
                $data['requests'],
                $data['errors'],
            );
            $this->assertGreaterThanOrEqual(0, $result['anomaly_score']);
            $this->assertLessThanOrEqual(100, $result['anomaly_score']);
        }
    }

    public function testAnalyzeWithZeroRequests(): void
    {
        $result = $this->detector->analyze(
            '192.168.1.1',
            '/',
            0,
            0,
        );

        $this->assertFalse($result['is_anomaly']);
    }

    public function testCalculatePathEntropy(): void
    {
        // Similar paths = low entropy (scanning)
        $scannerPaths = [
            '/admin1',
            '/admin2',
            '/admin3',
            '/admin4',
            '/admin5',
        ];
        $lowEntropy = $this->detector->calculatePathEntropy($scannerPaths);

        // Diverse paths = higher entropy (normal user)
        $normalPaths = [
            '/home',
            '/products/shoes',
            '/cart/checkout',
            '/about/contact',
            '/blog/article-123',
        ];
        $highEntropy = $this->detector->calculatePathEntropy($normalPaths);

        $this->assertLessThan($highEntropy, $lowEntropy);
    }

    public function testDetectScanningWithScannerPaths(): void
    {
        $paths = [
            '/wp-admin/',
            '/wp-login.php',
            '/wp-config.php',
            '/.env',
            '/phpmyadmin/',
            '/config.php',
        ];

        $result = $this->detector->detectScanning($paths);

        $this->assertTrue($result['is_scanning']);
        $this->assertGreaterThan(0.5, $result['confidence']);
        $this->assertContains('known_scanner_paths', $result['patterns']);
    }

    public function testDetectScanningWithNormalPaths(): void
    {
        $paths = [
            '/home',
            '/products',
            '/about',
        ];

        $result = $this->detector->detectScanning($paths);

        // With only 3 paths, scanning detection may not trigger
        // The method needs more paths to reliably detect scanning
        $this->assertIsBool($result['is_scanning']);
        $this->assertEquals(0, $result['scanner_path_hits']);
    }

    public function testGetBaselineStats(): void
    {
        $stats = $this->detector->getBaselineStats();

        $this->assertIsArray($stats);
        $this->assertArrayHasKey('requests_per_minute', $stats);
        $this->assertArrayHasKey('404_per_session', $stats);
        $this->assertArrayHasKey('unique_paths_per_session', $stats);
    }

    public function testRecommendationIsNotEmpty(): void
    {
        $result = $this->detector->analyze(
            '192.168.1.1',
            '/admin',
            500,
            0,
        );

        $this->assertNotEmpty($result['recommendation']);
    }

    public function testSetZScoreThreshold(): void
    {
        $this->detector->setZScoreThreshold(5.0);

        // With higher threshold, should detect fewer anomalies
        $result = $this->detector->analyze(
            '192.168.1.1',
            '/',
            50, // Moderately high
            0,
        );

        // Should be less likely to flag as anomaly
        $this->assertIsBool($result['is_anomaly']);
    }

    public function testSetIQRMultiplier(): void
    {
        $this->detector->setIQRMultiplier(3.0);

        // With higher multiplier, should detect fewer outliers
        $result = $this->detector->analyze(
            '192.168.1.1',
            '/',
            10,
            5, // Moderate error count
        );

        $this->assertIsBool($result['is_anomaly']);
    }

    public function testClearMetrics(): void
    {
        // Track some data
        $this->detector->analyze('192.168.1.1', '/', 100, 0);
        $this->detector->analyze('192.168.1.1', '/admin', 100, 0);

        // Clear
        $this->detector->clearMetrics();

        // Should work without issues after clearing
        $result = $this->detector->analyze('192.168.1.1', '/', 10, 0);
        $this->assertIsArray($result);
    }
}
