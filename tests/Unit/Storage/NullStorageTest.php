<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Tests\Unit\Storage;

use PHPUnit\Framework\TestCase;
use AdosLabs\EnterpriseSecurityShield\Storage\NullStorage;

/**
 * Test Suite for NullStorage.
 *
 * NullStorage is an IN-MEMORY storage for testing and development.
 * Despite its name, it DOES store data (in memory, not persisted).
 *
 * IMPORTANT: This is NOT a "null object" pattern storage.
 * Data is stored in memory and functions correctly for testing.
 * Data is NOT persisted across requests.
 */
final class NullStorageTest extends TestCase
{
    private NullStorage $storage;

    protected function setUp(): void
    {
        $this->storage = new NullStorage();
    }

    // ==================== BASIC CACHE OPERATIONS ====================

    public function testGetReturnsNullForNonExistentKey(): void
    {
        $this->assertNull($this->storage->get('non_existent_key'));
    }

    public function testSetAndGetWorks(): void
    {
        $this->storage->set('key', 'value', 60);
        $this->assertSame('value', $this->storage->get('key'));
    }

    public function testDeleteRemovesKey(): void
    {
        $this->storage->set('key', 'value', 60);
        $this->storage->delete('key');
        $this->assertNull($this->storage->get('key'));
    }

    public function testExistsReturnsTrueForExistingKey(): void
    {
        $this->storage->set('key', 'value', 60);
        $this->assertTrue($this->storage->exists('key'));
    }

    public function testExistsReturnsFalseForNonExistentKey(): void
    {
        $this->assertFalse($this->storage->exists('non_existent'));
    }

    // ==================== INCREMENT OPERATIONS ====================

    public function testIncrementCreatesNewKey(): void
    {
        $result = $this->storage->increment('counter', 5, 60);
        $this->assertSame(5, $result);
    }

    public function testIncrementAddsToExistingValue(): void
    {
        $this->storage->set('counter', '10', 60);
        $result = $this->storage->increment('counter', 5, 60);
        $this->assertSame(15, $result);
    }

    public function testIncrementWithNegativeDelta(): void
    {
        $this->storage->set('counter', '10', 60);
        $result = $this->storage->increment('counter', -3, 60);
        $this->assertSame(7, $result);
    }

    public function testIncrementNeverGoesBelowZero(): void
    {
        $this->storage->set('counter', '5', 60);
        $result = $this->storage->increment('counter', -10, 60);
        $this->assertSame(0, $result);
    }

    // ==================== SCORE OPERATIONS ====================

    public function testSetAndGetScore(): void
    {
        $this->storage->setScore('1.2.3.4', 50, 3600);
        $this->assertSame(50, $this->storage->getScore('1.2.3.4'));
    }

    public function testGetScoreReturnsNullForUnknownIP(): void
    {
        $this->assertNull($this->storage->getScore('unknown'));
    }

    public function testIncrementScore(): void
    {
        $this->storage->setScore('1.2.3.4', 10, 3600);
        $newScore = $this->storage->incrementScore('1.2.3.4', 15, 3600);
        $this->assertSame(25, $newScore);
    }

    public function testIncrementScoreCreatesNewIfNotExists(): void
    {
        $newScore = $this->storage->incrementScore('new_ip', 20, 3600);
        $this->assertSame(20, $newScore);
    }

    // ==================== BAN OPERATIONS ====================

    public function testBanAndCheckIP(): void
    {
        $this->storage->banIP('1.2.3.4', 3600, 'test ban');
        $this->assertTrue($this->storage->isBanned('1.2.3.4'));
    }

    public function testUnbannedIPReturnsFalse(): void
    {
        $this->assertFalse($this->storage->isBanned('1.2.3.4'));
    }

    public function testUnbanIP(): void
    {
        $this->storage->banIP('1.2.3.4', 3600, 'test ban');
        $this->storage->unbanIP('1.2.3.4');
        $this->assertFalse($this->storage->isBanned('1.2.3.4'));
    }

    public function testIsIpBannedCachedSameAsIsBanned(): void
    {
        $this->storage->banIP('1.2.3.4', 3600, 'test');
        $this->assertTrue($this->storage->isIpBannedCached('1.2.3.4'));
        $this->assertFalse($this->storage->isIpBannedCached('5.6.7.8'));
    }

    // ==================== REQUEST COUNT (RATE LIMITING) ====================

    public function testIncrementRequestCountStartsAtOne(): void
    {
        $count = $this->storage->incrementRequestCount('1.2.3.4', 60);
        $this->assertSame(1, $count);
    }

    public function testIncrementRequestCountAccumulates(): void
    {
        $this->storage->incrementRequestCount('1.2.3.4', 60);
        $this->storage->incrementRequestCount('1.2.3.4', 60);
        $count = $this->storage->incrementRequestCount('1.2.3.4', 60);
        $this->assertSame(3, $count);
    }

    public function testGetRequestCountReturnsStoredCount(): void
    {
        $this->storage->incrementRequestCount('1.2.3.4', 60);
        $this->storage->incrementRequestCount('1.2.3.4', 60);
        $count = $this->storage->getRequestCount('1.2.3.4', 60);
        $this->assertSame(2, $count);
    }

    public function testGetRequestCountReturnsZeroForUnknownIP(): void
    {
        $count = $this->storage->getRequestCount('unknown', 60);
        $this->assertSame(0, $count);
    }

    public function testRequestCountWithDifferentActions(): void
    {
        $this->storage->incrementRequestCount('1.2.3.4', 60, 'login');
        $this->storage->incrementRequestCount('1.2.3.4', 60, 'login');
        $this->storage->incrementRequestCount('1.2.3.4', 60, 'checkout');

        $this->assertSame(2, $this->storage->getRequestCount('1.2.3.4', 60, 'login'));
        $this->assertSame(1, $this->storage->getRequestCount('1.2.3.4', 60, 'checkout'));
    }

    // ==================== BOT VERIFICATION CACHE ====================

    public function testCacheBotVerification(): void
    {
        $metadata = ['hostname' => 'crawl-66-249-66-1.googlebot.com'];
        $this->storage->cacheBotVerification('66.249.66.1', true, $metadata, 3600);

        $cached = $this->storage->getCachedBotVerification('66.249.66.1');
        $this->assertNotNull($cached);
        $this->assertTrue($cached['verified']);
        $this->assertSame($metadata, $cached['metadata']);
    }

    public function testGetCachedBotVerificationReturnsNullIfNotCached(): void
    {
        $this->assertNull($this->storage->getCachedBotVerification('unknown'));
    }

    // ==================== SECURITY EVENTS ====================

    public function testLogSecurityEvent(): void
    {
        $result = $this->storage->logSecurityEvent('scan', '1.2.3.4', ['path' => '/.env']);
        $this->assertTrue($result);
    }

    public function testGetRecentEvents(): void
    {
        $this->storage->logSecurityEvent('scan', '1.2.3.4', ['path' => '/.env']);
        $this->storage->logSecurityEvent('ban', '5.6.7.8', ['reason' => 'test']);

        $events = $this->storage->getRecentEvents(10);
        $this->assertCount(2, $events);
    }

    public function testGetRecentEventsFilteredByType(): void
    {
        $this->storage->logSecurityEvent('scan', '1.2.3.4', ['path' => '/.env']);
        $this->storage->logSecurityEvent('ban', '5.6.7.8', ['reason' => 'test']);

        $events = $this->storage->getRecentEvents(10, 'scan');
        $this->assertCount(1, $events);
        $this->assertSame('scan', $events[0]['type']);
    }

    // ==================== CLEAR ====================

    public function testClearRemovesAllData(): void
    {
        $this->storage->set('key', 'value', 60);
        $this->storage->setScore('1.2.3.4', 50, 60);
        $this->storage->banIP('5.6.7.8', 60, 'test');

        $this->storage->clear();

        $this->assertNull($this->storage->get('key'));
        $this->assertNull($this->storage->getScore('1.2.3.4'));
        $this->assertFalse($this->storage->isBanned('5.6.7.8'));
    }

    // ==================== GET ALL DATA (TEST HELPER) ====================

    public function testGetAllDataReturnsAllInternalData(): void
    {
        $this->storage->set('key', 'value', 60);
        $this->storage->setScore('1.2.3.4', 50, 60);

        $data = $this->storage->getAllData();

        $this->assertArrayHasKey('cache', $data);
        $this->assertArrayHasKey('scores', $data);
        $this->assertArrayHasKey('bans', $data);
        $this->assertArrayHasKey('bot_cache', $data);
        $this->assertArrayHasKey('events', $data);
        $this->assertArrayHasKey('rate_limits', $data);
    }

    // ==================== CONTRACT COMPLIANCE ====================

    public function testImplementsStorageInterface(): void
    {
        $this->assertInstanceOf(
            \AdosLabs\EnterpriseSecurityShield\Contracts\StorageInterface::class,
            $this->storage,
        );
    }
}
