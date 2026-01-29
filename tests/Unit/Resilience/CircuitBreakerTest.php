<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Tests\Unit\Resilience;

use AdosLabs\EnterpriseSecurityShield\Resilience\CircuitBreaker;
use AdosLabs\EnterpriseSecurityShield\Resilience\CircuitOpenException;
use AdosLabs\EnterpriseSecurityShield\Tests\Fixtures\InMemoryStorage;
use PHPUnit\Framework\TestCase;

class CircuitBreakerTest extends TestCase
{
    private InMemoryStorage $storage;

    protected function setUp(): void
    {
        $this->storage = new InMemoryStorage();
    }

    public function testStartsInClosedState(): void
    {
        $breaker = new CircuitBreaker('test', $this->storage);

        $this->assertSame('closed', $breaker->getState());
    }

    public function testSuccessfulCallKeepsCircuitClosed(): void
    {
        $breaker = new CircuitBreaker('test', $this->storage);

        $result = $breaker->call(fn () => 'success');

        $this->assertSame('success', $result);
        $this->assertSame('closed', $breaker->getState());
    }

    public function testOpensAfterFailureThreshold(): void
    {
        $breaker = new CircuitBreaker('test', $this->storage, ['failure_threshold' => 3]);

        // First 2 failures - still closed
        for ($i = 0; $i < 2; $i++) {
            try {
                $breaker->call(fn () => throw new \RuntimeException('fail'));
            } catch (\RuntimeException) {
                // Expected
            }
        }

        $this->assertSame('closed', $breaker->getState());

        // Third failure - opens
        try {
            $breaker->call(fn () => throw new \RuntimeException('fail'));
        } catch (\RuntimeException) {
            // Expected
        }

        $this->assertSame('open', $breaker->getState());
    }

    public function testOpenCircuitThrowsException(): void
    {
        $breaker = new CircuitBreaker('test', $this->storage, ['failure_threshold' => 1]);

        // Trip the breaker
        try {
            $breaker->call(fn () => throw new \RuntimeException('fail'));
        } catch (\RuntimeException) {
            // Expected
        }

        $this->expectException(CircuitOpenException::class);
        $breaker->call(fn () => 'should not run');
    }

    public function testOpenCircuitUsesFallback(): void
    {
        $breaker = new CircuitBreaker('test', $this->storage, ['failure_threshold' => 1]);

        // Trip the breaker
        try {
            $breaker->call(fn () => throw new \RuntimeException('fail'));
        } catch (\RuntimeException) {
            // Expected
        }

        $result = $breaker->call(
            fn () => 'should not run',
            fn () => 'fallback value',
        );

        $this->assertSame('fallback value', $result);
    }

    public function testTransitionsToHalfOpenAfterRecoveryTimeout(): void
    {
        $breaker = new CircuitBreaker(
            'test',
            $this->storage,
            ['failure_threshold' => 1, 'recovery_timeout' => 1, 'success_threshold' => 1],
        );

        // Trip the breaker
        try {
            $breaker->call(fn () => throw new \RuntimeException('fail'));
        } catch (\RuntimeException) {
            // Expected
        }

        $this->assertSame('open', $breaker->getState());

        // Wait for recovery
        sleep(2);

        // Should transition to half-open on next call
        $result = $breaker->call(fn () => 'recovered');

        $this->assertSame('recovered', $result);
        $this->assertSame('closed', $breaker->getState());
    }

    public function testHalfOpenReopensOnFailure(): void
    {
        $breaker = new CircuitBreaker(
            'test',
            $this->storage,
            ['failure_threshold' => 1, 'recovery_timeout' => 1],
        );

        // Trip and wait
        try {
            $breaker->call(fn () => throw new \RuntimeException('fail'));
        } catch (\RuntimeException) {
            // Expected
        }

        sleep(2);

        // Fail again in half-open state
        try {
            $breaker->call(fn () => throw new \RuntimeException('still failing'));
        } catch (\RuntimeException) {
            // Expected
        }

        $this->assertSame('open', $breaker->getState());
    }

    public function testForceOpen(): void
    {
        $breaker = new CircuitBreaker('test', $this->storage);

        $breaker->forceOpen();

        $this->assertSame('open', $breaker->getState());
    }

    public function testForceClose(): void
    {
        $breaker = new CircuitBreaker('test', $this->storage, ['failure_threshold' => 1]);

        // Trip the breaker
        try {
            $breaker->call(fn () => throw new \RuntimeException('fail'));
        } catch (\RuntimeException) {
            // Expected
        }

        $breaker->forceClose();

        $this->assertSame('closed', $breaker->getState());
    }

    public function testReset(): void
    {
        $breaker = new CircuitBreaker('test', $this->storage, ['failure_threshold' => 1]);

        // Trip the breaker
        try {
            $breaker->call(fn () => throw new \RuntimeException('fail'));
        } catch (\RuntimeException) {
            // Expected
        }

        $breaker->forceClose();

        $this->assertSame('closed', $breaker->getState());
        $this->assertSame(0, $breaker->getFailureCount());
    }

    public function testGetStatistics(): void
    {
        $breaker = new CircuitBreaker('test', $this->storage, ['failure_threshold' => 5]);

        // Some successes
        $breaker->call(fn () => 'ok');
        $breaker->call(fn () => 'ok');

        // Some failures
        try {
            $breaker->call(fn () => throw new \RuntimeException('fail'));
        } catch (\RuntimeException) {
            // Expected
        }

        $stats = $breaker->getStatistics();

        $this->assertSame('closed', $stats['state']);
        $this->assertSame(1, $stats['failure_count']);
        $this->assertSame(5, $stats['failure_threshold']);
    }
}
