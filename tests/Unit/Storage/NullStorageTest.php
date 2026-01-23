<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Unit\Storage;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Storage\NullStorage;

/**
 * Test Suite for NullStorage
 *
 * Coverage:
 * - Null storage behavior (no actual storage)
 * - get/set/delete operations
 * - incrementRequestCount
 * - getRequestCount
 * - Verifica che nulla venga memorizzato
 *
 * @package Senza1dio\SecurityShield\Tests\Unit\Storage
 */
final class NullStorageTest extends TestCase
{
    private NullStorage $storage;

    protected function setUp(): void
    {
        $this->storage = new NullStorage();
    }

    // ==================== BASIC OPERATIONS ====================

    public function testGetAlwaysReturnsNull(): void
    {
        $value = $this->storage->get('any_key');

        $this->assertNull($value);
    }

    public function testGetAfterSetReturnsNull(): void
    {
        $this->storage->set('key', 'value', 60);

        $value = $this->storage->get('key');

        $this->assertNull($value, 'NullStorage should always return null');
    }

    public function testSetDoesNotStoreData(): void
    {
        $this->storage->set('key1', 'value1', 60);
        $this->storage->set('key2', 'value2', 60);

        $this->assertNull($this->storage->get('key1'));
        $this->assertNull($this->storage->get('key2'));
    }

    public function testDeleteDoesNothing(): void
    {
        // Non dovrebbe lanciare eccezioni
        $this->storage->delete('non_existent_key');

        $this->assertTrue(true);
    }

    public function testDeleteAfterSetDoesNothing(): void
    {
        $this->storage->set('key', 'value', 60);
        $this->storage->delete('key');

        // Dovrebbe comunque tornare null
        $this->assertNull($this->storage->get('key'));
    }

    // ==================== REQUEST COUNT ====================

    public function testIncrementRequestCountReturnsOne(): void
    {
        $count = $this->storage->incrementRequestCount('1.2.3.4', 60);

        $this->assertEquals(1, $count, 'NullStorage should always return 1 on increment');
    }

    public function testIncrementRequestCountAlwaysReturnsOne(): void
    {
        $ip = '1.2.3.4';
        $window = 60;

        $count1 = $this->storage->incrementRequestCount($ip, $window);
        $count2 = $this->storage->incrementRequestCount($ip, $window);
        $count3 = $this->storage->incrementRequestCount($ip, $window);

        $this->assertEquals(1, $count1);
        $this->assertEquals(1, $count2);
        $this->assertEquals(1, $count3);
    }

    public function testGetRequestCountReturnsZero(): void
    {
        $count = $this->storage->getRequestCount('1.2.3.4', 60);

        $this->assertEquals(0, $count, 'NullStorage should always return 0 on getRequestCount');
    }

    public function testGetRequestCountAfterIncrementReturnsZero(): void
    {
        $ip = '1.2.3.4';
        $window = 60;

        $this->storage->incrementRequestCount($ip, $window);

        $count = $this->storage->getRequestCount($ip, $window);

        $this->assertEquals(0, $count);
    }

    public function testMultipleIncrementsDoNotAccumulate(): void
    {
        $ip = '1.2.3.4';
        $window = 60;

        for ($i = 0; $i < 100; $i++) {
            $count = $this->storage->incrementRequestCount($ip, $window);
            $this->assertEquals(1, $count);
        }

        $finalCount = $this->storage->getRequestCount($ip, $window);
        $this->assertEquals(0, $finalCount);
    }

    // ==================== TTL BEHAVIOR ====================

    public function testTTLIsIgnored(): void
    {
        $this->storage->set('key', 'value', 1); // TTL 1 secondo

        // Non aspettiamo, verifichiamo subito
        $this->assertNull($this->storage->get('key'));

        // Aspettiamo comunque per sicurezza
        sleep(2);

        $this->assertNull($this->storage->get('key'));
    }

    public function testZeroTTLIsIgnored(): void
    {
        $this->storage->set('key', 'value', 0);

        $this->assertNull($this->storage->get('key'));
    }

    public function testNegativeTTLIsIgnored(): void
    {
        $this->storage->set('key', 'value', -1);

        $this->assertNull($this->storage->get('key'));
    }

    // ==================== EDGE CASES ====================

    public function testGetWithEmptyKey(): void
    {
        $value = $this->storage->get('');

        $this->assertNull($value);
    }

    public function testSetWithEmptyKey(): void
    {
        $this->storage->set('', 'value', 60);

        $this->assertNull($this->storage->get(''));
    }

    public function testSetWithEmptyValue(): void
    {
        $this->storage->set('key', '', 60);

        $this->assertNull($this->storage->get('key'));
    }

    public function testSetWithNullValue(): void
    {
        $this->storage->set('key', null, 60);

        $this->assertNull($this->storage->get('key'));
    }

    public function testSetWithNumericValue(): void
    {
        $this->storage->set('key', '12345', 60);

        $this->assertNull($this->storage->get('key'));
    }

    public function testSetWithVeryLongValue(): void
    {
        $longValue = str_repeat('a', 1000000); // 1MB string
        $this->storage->set('key', $longValue, 60);

        $this->assertNull($this->storage->get('key'));
    }

    public function testIncrementWithEmptyIP(): void
    {
        $count = $this->storage->incrementRequestCount('', 60);

        $this->assertEquals(1, $count);
    }

    public function testIncrementWithInvalidIP(): void
    {
        $count = $this->storage->incrementRequestCount('not-an-ip', 60);

        $this->assertEquals(1, $count);
    }

    public function testIncrementWithIPv6(): void
    {
        $count = $this->storage->incrementRequestCount('2001:db8::1', 60);

        $this->assertEquals(1, $count);
    }

    public function testIncrementWithZeroWindow(): void
    {
        $count = $this->storage->incrementRequestCount('1.2.3.4', 0);

        $this->assertEquals(1, $count);
    }

    public function testIncrementWithNegativeWindow(): void
    {
        $count = $this->storage->incrementRequestCount('1.2.3.4', -1);

        $this->assertEquals(1, $count);
    }

    // ==================== CONSISTENCY TESTS ====================

    public function testMultipleInstancesDoNotShareState(): void
    {
        $storage1 = new NullStorage();
        $storage2 = new NullStorage();

        $storage1->set('key', 'value1', 60);
        $storage2->set('key', 'value2', 60);

        $this->assertNull($storage1->get('key'));
        $this->assertNull($storage2->get('key'));
    }

    public function testMultipleKeysDontInterfere(): void
    {
        $this->storage->set('key1', 'value1', 60);
        $this->storage->set('key2', 'value2', 60);
        $this->storage->set('key3', 'value3', 60);

        $this->assertNull($this->storage->get('key1'));
        $this->assertNull($this->storage->get('key2'));
        $this->assertNull($this->storage->get('key3'));
    }

    // ==================== PERFORMANCE TESTS ====================

    public function testMultipleSetOperationsAreFast(): void
    {
        $start = microtime(true);

        for ($i = 0; $i < 10000; $i++) {
            $this->storage->set("key{$i}", "value{$i}", 60);
        }

        $duration = microtime(true) - $start;

        // Dovrebbe essere MOLTO veloce (no actual storage)
        $this->assertLessThan(0.1, $duration);
    }

    public function testMultipleGetOperationsAreFast(): void
    {
        $start = microtime(true);

        for ($i = 0; $i < 10000; $i++) {
            $this->storage->get("key{$i}");
        }

        $duration = microtime(true) - $start;

        // Dovrebbe essere MOLTO veloce
        $this->assertLessThan(0.1, $duration);
    }

    public function testMultipleIncrementOperationsAreFast(): void
    {
        $start = microtime(true);

        for ($i = 0; $i < 10000; $i++) {
            $this->storage->incrementRequestCount('1.2.3.4', 60);
        }

        $duration = microtime(true) - $start;

        // Dovrebbe essere MOLTO veloce
        $this->assertLessThan(0.1, $duration);
    }

    // ==================== USE CASE TESTS ====================

    public function testNullStorageForDevelopment(): void
    {
        // In sviluppo, NullStorage permette di testare senza Redis

        // Simula WAF che usa NullStorage
        $this->storage->set('banned:1.2.3.4', '1', 86400);

        // WAF controlla se IP è bannato
        $isBanned = $this->storage->get('banned:1.2.3.4') === '1';

        // Con NullStorage, nessun IP è bannato
        $this->assertFalse($isBanned);
    }

    public function testNullStorageForRateLimiting(): void
    {
        // Simula rate limiting con NullStorage
        $ip = '1.2.3.4';
        $window = 60;
        $limit = 100;

        // Simula 150 richieste
        for ($i = 0; $i < 150; $i++) {
            $count = $this->storage->incrementRequestCount($ip, $window);

            // Con NullStorage, rate limiting è sempre permesso
            $this->assertLessThan($limit, $count);
        }
    }

    public function testNullStorageForCaching(): void
    {
        // Simula caching con NullStorage
        $cacheKey = 'bot_verify:66.249.66.1';

        // Tenta di leggere dalla cache
        $cached = $this->storage->get($cacheKey);

        // Cache miss (sempre con NullStorage)
        $this->assertNull($cached);

        // Esegui verifica (simulata)
        $result = true;

        // Salva in cache
        $this->storage->set($cacheKey, (string)$result, 3600);

        // Prossima lettura da cache (sempre miss)
        $cached = $this->storage->get($cacheKey);
        $this->assertNull($cached);
    }

    // ==================== CONTRACT COMPLIANCE ====================

    public function testImplementsStorageInterface(): void
    {
        $this->assertInstanceOf(
            \Senza1dio\SecurityShield\Contracts\StorageInterface::class,
            $this->storage
        );
    }

    public function testHasGetMethod(): void
    {
        $this->assertTrue(method_exists($this->storage, 'get'));
    }

    public function testHasSetMethod(): void
    {
        $this->assertTrue(method_exists($this->storage, 'set'));
    }

    public function testHasDeleteMethod(): void
    {
        $this->assertTrue(method_exists($this->storage, 'delete'));
    }

    public function testHasIncrementRequestCountMethod(): void
    {
        $this->assertTrue(method_exists($this->storage, 'incrementRequestCount'));
    }

    public function testHasGetRequestCountMethod(): void
    {
        $this->assertTrue(method_exists($this->storage, 'getRequestCount'));
    }

    // ==================== THREAD SAFETY ====================

    public function testConcurrentAccessIsSafe(): void
    {
        // NullStorage non mantiene stato, quindi è thread-safe per design

        // Simula accessi concorrenti
        $results = [];
        for ($i = 0; $i < 100; $i++) {
            $this->storage->set("key{$i}", "value{$i}", 60);
            $results[] = $this->storage->get("key{$i}");
        }

        // Tutti i risultati dovrebbero essere null
        foreach ($results as $result) {
            $this->assertNull($result);
        }
    }
}
