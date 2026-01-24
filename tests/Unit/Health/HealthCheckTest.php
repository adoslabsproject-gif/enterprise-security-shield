<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Unit\Health;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Health\CallableHealthCheck;
use Senza1dio\SecurityShield\Health\HealthCheck;
use Senza1dio\SecurityShield\Health\HealthStatus;

/**
 * Test Suite for HealthCheck.
 *
 * NOTE: CallableHealthCheck expects a callable that returns bool (true=healthy).
 * For more complex scenarios (degraded status, custom messages), implement
 * HealthCheckInterface directly or use addSimpleCheck().
 */
class HealthCheckTest extends TestCase
{
    public function testHealthyWhenAllChecksPass(): void
    {
        $healthCheck = new HealthCheck();

        // CallableHealthCheck expects bool return, true = healthy
        $healthCheck->addCheck('database', new CallableHealthCheck(fn () => true));
        $healthCheck->addCheck('cache', new CallableHealthCheck(fn () => true));

        $result = $healthCheck->readiness();

        $this->assertSame(HealthStatus::HEALTHY, $result->status);
        $this->assertTrue($result->isHealthy());
    }

    public function testUnhealthyWhenOneCheckFails(): void
    {
        $healthCheck = new HealthCheck();

        // false = unhealthy
        $healthCheck->addCheck('database', new CallableHealthCheck(fn () => false));
        $healthCheck->addCheck('cache', new CallableHealthCheck(fn () => true));

        $result = $healthCheck->readiness();

        $this->assertSame(HealthStatus::UNHEALTHY, $result->status);
        $this->assertFalse($result->isHealthy());
        $this->assertTrue($result->isUnhealthy());
    }

    public function testLivenessAlwaysHealthyByDefault(): void
    {
        $healthCheck = new HealthCheck();

        $result = $healthCheck->liveness();

        $this->assertSame(HealthStatus::HEALTHY, $result->status);
    }

    public function testComponentHealthIncluded(): void
    {
        $healthCheck = new HealthCheck();
        $healthCheck->addCheck('database', new CallableHealthCheck(fn () => true));

        $result = $healthCheck->readiness();

        $this->assertArrayHasKey('database', $result->components);
        $this->assertSame(HealthStatus::HEALTHY, $result->components['database']->status);
    }

    public function testExceptionHandling(): void
    {
        $healthCheck = new HealthCheck();
        $healthCheck->addCheck('unstable', new CallableHealthCheck(
            fn () => throw new \RuntimeException('Connection failed'),
        ));

        $result = $healthCheck->readiness();

        $this->assertSame(HealthStatus::UNHEALTHY, $result->status);
        $this->assertStringContainsString('Connection failed', $result->components['unstable']->message);
    }

    public function testResultToArray(): void
    {
        $healthCheck = new HealthCheck();
        $healthCheck->addCheck('test', new CallableHealthCheck(fn () => true));

        $result = $healthCheck->readiness();
        $array = $result->toArray();

        $this->assertArrayHasKey('status', $array);
        $this->assertArrayHasKey('timestamp', $array);
        $this->assertArrayHasKey('components', $array);
        $this->assertArrayHasKey('duration_ms', $array);
    }

    public function testToJson(): void
    {
        $healthCheck = new HealthCheck();
        $healthCheck->addCheck('test', new CallableHealthCheck(fn () => true));

        $result = $healthCheck->readiness();
        $json = $result->toJson();

        $decoded = json_decode($json, true);
        $this->assertIsArray($decoded);
        $this->assertSame('healthy', $decoded['status']);
    }

    public function testAddSimpleCheck(): void
    {
        $healthCheck = new HealthCheck();
        $healthCheck->addSimpleCheck('simple', fn () => true);

        $result = $healthCheck->readiness();

        $this->assertSame(HealthStatus::HEALTHY, $result->status);
    }

    public function testCaching(): void
    {
        $callCount = 0;
        $healthCheck = new HealthCheck();
        $healthCheck->enableCache(10); // 10 second cache
        $healthCheck->addSimpleCheck('counted', function () use (&$callCount) {
            $callCount++;

            return true;
        });

        // First call
        $healthCheck->readiness();
        $this->assertSame(1, $callCount);

        // Second call should use cache
        $healthCheck->readiness();
        $this->assertSame(1, $callCount);

        // Force refresh should bypass cache (check() method, not readiness())
        $healthCheck->check(true);
        $this->assertSame(2, $callCount);
    }

    public function testCriticalAndNonCriticalChecks(): void
    {
        $healthCheck = new HealthCheck();

        // Critical check fails - should make overall unhealthy
        $healthCheck->addCheck('critical', new CallableHealthCheck(fn () => false), critical: true);

        // Non-critical check passes
        $healthCheck->addCheck('optional', new CallableHealthCheck(fn () => true), critical: false);

        $result = $healthCheck->readiness();

        $this->assertSame(HealthStatus::UNHEALTHY, $result->status);
    }

    public function testGetCheckNames(): void
    {
        $healthCheck = new HealthCheck();
        $healthCheck->addCheck('db', new CallableHealthCheck(fn () => true));
        $healthCheck->addCheck('cache', new CallableHealthCheck(fn () => true));

        $names = $healthCheck->getCheckNames();

        $this->assertContains('db', $names);
        $this->assertContains('cache', $names);
    }

    public function testClearCache(): void
    {
        $callCount = 0;
        $healthCheck = new HealthCheck();
        $healthCheck->enableCache(10);
        $healthCheck->addSimpleCheck('counted', function () use (&$callCount) {
            $callCount++;

            return true;
        });

        // First call
        $healthCheck->readiness();
        $this->assertSame(1, $callCount);

        // Clear cache
        $healthCheck->clearCache();

        // Next call should execute check again
        $healthCheck->readiness();
        $this->assertSame(2, $callCount);
    }
}
