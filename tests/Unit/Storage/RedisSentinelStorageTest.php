<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Tests\Unit\Storage;

use AdosLabs\EnterpriseSecurityShield\Storage\RedisSentinelStorage;
use PHPUnit\Framework\TestCase;

/**
 * @covers \AdosLabs\EnterpriseSecurityShield\Storage\RedisSentinelStorage
 */
final class RedisSentinelStorageTest extends TestCase
{
    // =========================================================================
    // CONSTRUCTOR TESTS
    // =========================================================================

    public function testThrowsExceptionWithoutSentinels(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('At least one Sentinel must be configured');

        new RedisSentinelStorage(['sentinels' => []]);
    }

    public function testAcceptsValidConfiguration(): void
    {
        // Note: This test only validates constructor logic, not actual connection
        $config = [
            'sentinels' => [
                ['host' => '127.0.0.1', 'port' => 26379],
                ['host' => '127.0.0.1', 'port' => 26380],
                ['host' => '127.0.0.1', 'port' => 26381],
            ],
            'master_name' => 'mymaster',
            'password' => 'secret',
            'database' => 1,
            'timeout' => 3.0,
            'read_timeout' => 3.0,
        ];

        $storage = new RedisSentinelStorage($config, 'test:', false);

        $this->assertEquals('test:', $storage->getKeyPrefix());
    }

    public function testDefaultConfiguration(): void
    {
        $config = [
            'sentinels' => [
                ['host' => 'sentinel1.local', 'port' => 26379],
            ],
        ];

        $storage = new RedisSentinelStorage($config);

        $this->assertEquals('security_shield:', $storage->getKeyPrefix());
    }

    // =========================================================================
    // FAIL MODE TESTS
    // =========================================================================

    public function testSetFailModeReturnsSelf(): void
    {
        $storage = new RedisSentinelStorage([
            'sentinels' => [['host' => 'localhost', 'port' => 26379]],
        ]);

        $result = $storage->setFailMode(true);

        $this->assertSame($storage, $result);
    }

    public function testSetMasterCacheTtlReturnsSelf(): void
    {
        $storage = new RedisSentinelStorage([
            'sentinels' => [['host' => 'localhost', 'port' => 26379]],
        ]);

        $result = $storage->setMasterCacheTtl(60);

        $this->assertSame($storage, $result);
    }

    public function testSetMasterCacheTtlMinimumOne(): void
    {
        $storage = new RedisSentinelStorage([
            'sentinels' => [['host' => 'localhost', 'port' => 26379]],
        ]);

        // Should not throw, even with negative value
        $result = $storage->setMasterCacheTtl(-10);

        $this->assertSame($storage, $result);
    }

    public function testSetMaxRetriesReturnsSelf(): void
    {
        $storage = new RedisSentinelStorage([
            'sentinels' => [['host' => 'localhost', 'port' => 26379]],
        ]);

        $result = $storage->setMaxRetries(5);

        $this->assertSame($storage, $result);
    }

    // =========================================================================
    // HEALTH CHECK TESTS (without actual Redis)
    // =========================================================================

    public function testGetHealthReturnsProperStructure(): void
    {
        $storage = new RedisSentinelStorage([
            'sentinels' => [
                ['host' => '127.0.0.1', 'port' => 26379],
                ['host' => '127.0.0.1', 'port' => 26380],
            ],
        ]);

        $health = $storage->getHealth();

        $this->assertArrayHasKey('healthy', $health);
        $this->assertArrayHasKey('sentinels_up', $health);
        $this->assertArrayHasKey('sentinels_total', $health);
        $this->assertArrayHasKey('master', $health);
        $this->assertArrayHasKey('slaves_count', $health);
        $this->assertArrayHasKey('quorum_met', $health);

        $this->assertIsBool($health['healthy']);
        $this->assertIsInt($health['sentinels_up']);
        $this->assertEquals(2, $health['sentinels_total']);
        $this->assertIsInt($health['slaves_count']);
        $this->assertIsBool($health['quorum_met']);
    }

    public function testGetCurrentMasterReturnsNullWhenCannotConnect(): void
    {
        $storage = new RedisSentinelStorage([
            'sentinels' => [
                ['host' => '127.0.0.1', 'port' => 26379],
            ],
        ]);

        // Without actual Sentinel, this should return null
        $master = $storage->getCurrentMaster();

        // Will be null because we can't connect to Sentinel
        $this->assertNull($master);
    }

    public function testGetSlavesReturnsEmptyArrayWhenCannotConnect(): void
    {
        $storage = new RedisSentinelStorage([
            'sentinels' => [
                ['host' => '127.0.0.1', 'port' => 26379],
            ],
        ]);

        $slaves = $storage->getSlaves();

        $this->assertIsArray($slaves);
        $this->assertEmpty($slaves);
    }

    public function testIsFailoverInProgressReturnsFalseWhenCannotConnect(): void
    {
        $storage = new RedisSentinelStorage([
            'sentinels' => [
                ['host' => '127.0.0.1', 'port' => 26379],
            ],
        ]);

        $inProgress = $storage->isFailoverInProgress();

        $this->assertFalse($inProgress);
    }

    // =========================================================================
    // FAIL-OPEN BEHAVIOR TESTS
    // =========================================================================

    public function testFailOpenModeReturnsDefaultsOnConnectionFailure(): void
    {
        $storage = new RedisSentinelStorage(
            ['sentinels' => [['host' => '127.0.0.1', 'port' => 26379]]],
            'test:',
            false // fail-open
        );

        // These should return safe defaults instead of throwing
        $this->assertNull($storage->getScore('1.2.3.4'));
        $this->assertFalse($storage->isBanned('1.2.3.4'));
        $this->assertEquals(0, $storage->incrementScore('1.2.3.4', 10, 3600));
        $this->assertEquals(1, $storage->incrementRequestCount('1.2.3.4', 60));
        $this->assertNull($storage->get('test_key'));
        $this->assertFalse($storage->setScore('1.2.3.4', 50, 3600));
        $this->assertEmpty($storage->getRecentEvents());
    }

    // =========================================================================
    // FAIL-CLOSED BEHAVIOR TESTS
    // =========================================================================

    public function testFailClosedModeThrowsOnConnectionFailure(): void
    {
        $storage = new RedisSentinelStorage(
            ['sentinels' => [['host' => '127.0.0.1', 'port' => 26379]]],
            'test:',
            true // fail-closed
        );

        $this->expectException(\RuntimeException::class);

        // This should throw because fail-closed mode
        $storage->getScore('1.2.3.4');
    }

    // =========================================================================
    // CLOSE TESTS
    // =========================================================================

    public function testCloseDoesNotThrow(): void
    {
        $storage = new RedisSentinelStorage([
            'sentinels' => [['host' => 'localhost', 'port' => 26379]],
        ]);

        // Should not throw even without active connection
        $storage->close();

        $this->assertTrue(true); // Assert we got here
    }

    public function testForceFailoverReturnsFalseWhenCannotConnect(): void
    {
        $storage = new RedisSentinelStorage([
            'sentinels' => [['host' => '127.0.0.1', 'port' => 26379]],
        ]);

        $result = $storage->forceFailover();

        $this->assertFalse($result);
    }
}
