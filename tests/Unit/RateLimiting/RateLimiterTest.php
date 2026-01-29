<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Tests\Unit\RateLimiting;

use AdosLabs\EnterpriseSecurityShield\RateLimiting\RateLimiter;
use AdosLabs\EnterpriseSecurityShield\Tests\Fixtures\InMemoryStorage;
use PHPUnit\Framework\TestCase;

class RateLimiterTest extends TestCase
{
    private InMemoryStorage $storage;

    protected function setUp(): void
    {
        $this->storage = new InMemoryStorage();
    }

    public function testSlidingWindowAllowsWithinLimit(): void
    {
        $limiter = RateLimiter::slidingWindow($this->storage, 10, 60);

        for ($i = 0; $i < 10; $i++) {
            $result = $limiter->attempt('user:123');
            $this->assertTrue($result->allowed, "Request $i should be allowed");
        }
    }

    public function testSlidingWindowBlocksOverLimit(): void
    {
        $limiter = RateLimiter::slidingWindow($this->storage, 5, 60);

        for ($i = 0; $i < 5; $i++) {
            $limiter->attempt('user:123');
        }

        $result = $limiter->attempt('user:123');

        $this->assertFalse($result->allowed);
        $this->assertGreaterThan(0, $result->retryAfter);
    }

    public function testFixedWindowAllowsWithinLimit(): void
    {
        $limiter = RateLimiter::fixedWindow($this->storage, 10, 60);

        for ($i = 0; $i < 10; $i++) {
            $result = $limiter->attempt('user:123');
            $this->assertTrue($result->allowed);
        }

        $result = $limiter->attempt('user:123');
        $this->assertFalse($result->allowed);
    }

    public function testTokenBucketAllowsWithTokens(): void
    {
        $limiter = RateLimiter::tokenBucket($this->storage, 10, 1.0);

        for ($i = 0; $i < 10; $i++) {
            $result = $limiter->attempt('user:123');
            $this->assertTrue($result->allowed);
        }
    }

    public function testTokenBucketBlocksWhenEmpty(): void
    {
        $limiter = RateLimiter::tokenBucket($this->storage, 5, 1.0);

        for ($i = 0; $i < 5; $i++) {
            $limiter->attempt('user:123');
        }

        $result = $limiter->attempt('user:123');
        $this->assertFalse($result->allowed);
    }

    public function testTokenBucketRefillsOverTime(): void
    {
        $limiter = RateLimiter::tokenBucket($this->storage, 5, 5.0); // 5 tokens per second

        // Use all tokens
        for ($i = 0; $i < 5; $i++) {
            $limiter->attempt('user:123');
        }

        // Wait for refill
        usleep(500000); // 0.5 seconds = 2.5 tokens

        // Should have some tokens now
        $result = $limiter->attempt('user:123');
        $this->assertTrue($result->allowed);
    }

    public function testLeakyBucketAllowsWithinCapacity(): void
    {
        $limiter = RateLimiter::leakyBucket($this->storage, 10, 1.0);

        for ($i = 0; $i < 10; $i++) {
            $result = $limiter->attempt('user:123');
            $this->assertTrue($result->allowed);
        }
    }

    public function testLeakyBucketBlocksWhenFull(): void
    {
        // Bucket size 5, leak rate 1 req/sec - simple, deterministic test
        // We make requests faster than drain rate, so bucket will fill up
        $limiter = RateLimiter::leakyBucket($this->storage, 5, 1.0);

        // Make 10 rapid requests - first few should succeed, eventually blocked
        $allowedCount = 0;
        $blockedCount = 0;

        for ($i = 0; $i < 10; $i++) {
            $result = $limiter->attempt('user:123');
            if ($result->allowed) {
                $allowedCount++;
            } else {
                $blockedCount++;
            }
        }

        // Should have allowed some and blocked some
        $this->assertGreaterThan(0, $allowedCount, 'At least some requests should be allowed');
        $this->assertGreaterThan(0, $blockedCount, 'Eventually requests should be blocked when bucket is full');
        $this->assertLessThanOrEqual(5, $allowedCount, 'Should not allow more than bucket size');
    }

    public function testDifferentIdentifiersAreIndependent(): void
    {
        $limiter = RateLimiter::slidingWindow($this->storage, 2, 60);

        $limiter->attempt('user:1');
        $limiter->attempt('user:1');

        $result1 = $limiter->attempt('user:1');
        $result2 = $limiter->attempt('user:2');

        $this->assertFalse($result1->allowed, 'User 1 should be rate limited');
        $this->assertTrue($result2->allowed, 'User 2 should not be affected');
    }

    public function testCheckDoesNotConsumeToken(): void
    {
        $limiter = RateLimiter::slidingWindow($this->storage, 2, 60);

        $limiter->attempt('user:123');

        // Check should not consume
        $check = $limiter->check('user:123');
        $this->assertTrue($check->allowed);
        $this->assertSame(1, $check->remaining);

        // Still have 1 remaining
        $attempt = $limiter->attempt('user:123');
        $this->assertTrue($attempt->allowed);

        // Now exhausted
        $final = $limiter->attempt('user:123');
        $this->assertFalse($final->allowed);
    }

    public function testRemainingCount(): void
    {
        $limiter = RateLimiter::slidingWindow($this->storage, 5, 60);

        $result = $limiter->attempt('user:123');
        $this->assertSame(4, $result->remaining);

        $result = $limiter->attempt('user:123');
        $this->assertSame(3, $result->remaining);

        $result = $limiter->attempt('user:123');
        $this->assertSame(2, $result->remaining);
    }

    public function testReset(): void
    {
        $limiter = RateLimiter::slidingWindow($this->storage, 2, 60);

        $limiter->attempt('user:123');
        $limiter->attempt('user:123');

        $result = $limiter->attempt('user:123');
        $this->assertFalse($result->allowed);

        $limiter->reset('user:123');

        $result = $limiter->attempt('user:123');
        $this->assertTrue($result->allowed);
    }

    public function testCustomKeyPrefix(): void
    {
        $limiter = RateLimiter::slidingWindow($this->storage, 10, 60, 'custom:prefix:');

        $limiter->attempt('user:123');

        // Check storage has correct key prefix
        $keys = $this->storage->keys();
        $this->assertNotEmpty($keys);
        $this->assertStringStartsWith('custom:prefix:', $keys[0]);
    }
}
