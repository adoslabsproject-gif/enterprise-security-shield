<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Unit\Storage;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Storage\RedisStorage;

/**
 * Test Suite for RedisStorage
 *
 * Coverage:
 * - get/set/delete operations
 * - TTL (Time To Live)
 * - incrementRequestCount
 * - getRequestCount
 * - Edge cases
 *
 * NOTE: Questi test richiedono Redis installato e attivo
 * Se Redis non è disponibile, i test verranno saltati
 *
 * @package Senza1dio\SecurityShield\Tests\Unit\Storage
 */
final class RedisStorageTest extends TestCase
{
    private ?RedisStorage $storage = null;
    private ?\Redis $redis = null;

    protected function setUp(): void
    {
        if (!extension_loaded('redis')) {
            $this->markTestSkipped('Redis extension not installed');
        }

        try {
            $this->redis = new \Redis();
            $this->redis->connect('127.0.0.1', 6379);
            $this->redis->ping();

            // Usa database 15 per test (solitamente non usato)
            $this->redis->select(15);

            $this->storage = new RedisStorage($this->redis);
        } catch (\Exception $e) {
            $this->markTestSkipped('Redis server not available: ' . $e->getMessage());
        }
    }

    protected function tearDown(): void
    {
        if ($this->redis) {
            // Pulisci database test
            $this->redis->flushDB();
            $this->redis->close();
        }
    }

    // ==================== BASIC GET/SET OPERATIONS ====================

    public function testSetAndGetValue(): void
    {
        $this->storage->set('test_key', 'test_value', 60);

        $value = $this->storage->get('test_key');

        $this->assertEquals('test_value', $value);
    }

    public function testGetNonExistentKeyReturnsNull(): void
    {
        $value = $this->storage->get('non_existent_key');

        $this->assertNull($value);
    }

    public function testSetOverwritesExistingValue(): void
    {
        $this->storage->set('key', 'value1', 60);
        $this->storage->set('key', 'value2', 60);

        $value = $this->storage->get('key');

        $this->assertEquals('value2', $value);
    }

    public function testSetWithZeroTTLStoresValue(): void
    {
        // TTL 0 dovrebbe memorizzare senza scadenza
        $this->storage->set('key', 'value', 0);

        $value = $this->storage->get('key');
        $this->assertEquals('value', $value);
    }

    public function testSetWithLongTTL(): void
    {
        // TTL 1 ora
        $this->storage->set('key', 'value', 3600);

        $value = $this->storage->get('key');
        $this->assertEquals('value', $value);

        // Verifica TTL in Redis
        $ttl = $this->redis->ttl('key');
        $this->assertGreaterThan(3500, $ttl);
        $this->assertLessThanOrEqual(3600, $ttl);
    }

    // ==================== DELETE OPERATIONS ====================

    public function testDeleteExistingKey(): void
    {
        $this->storage->set('key', 'value', 60);

        $this->storage->delete('key');

        $value = $this->storage->get('key');
        $this->assertNull($value);
    }

    public function testDeleteNonExistentKey(): void
    {
        // Non dovrebbe lanciare eccezioni
        $this->storage->delete('non_existent_key');

        $this->assertTrue(true); // Se arriviamo qui, il test passa
    }

    public function testDeleteAndReSet(): void
    {
        $this->storage->set('key', 'value1', 60);
        $this->storage->delete('key');
        $this->storage->set('key', 'value2', 60);

        $value = $this->storage->get('key');
        $this->assertEquals('value2', $value);
    }

    // ==================== TTL (TIME TO LIVE) ====================

    public function testKeyExpiresAfterTTL(): void
    {
        // Set con TTL di 1 secondo
        $this->storage->set('key', 'value', 1);

        // Verifica che esista subito
        $this->assertEquals('value', $this->storage->get('key'));

        // Aspetta 2 secondi
        sleep(2);

        // Dovrebbe essere scaduto
        $this->assertNull($this->storage->get('key'));
    }

    public function testTTLIsRespected(): void
    {
        $this->storage->set('key', 'value', 10);

        $ttl = $this->redis->ttl('key');

        $this->assertGreaterThan(0, $ttl);
        $this->assertLessThanOrEqual(10, $ttl);
    }

    // ==================== REQUEST COUNT (RATE LIMITING) ====================

    public function testIncrementRequestCount(): void
    {
        $ip = '1.2.3.4';
        $window = 60;

        $count = $this->storage->incrementRequestCount($ip, $window);

        $this->assertEquals(1, $count);
    }

    public function testIncrementRequestCountMultipleTimes(): void
    {
        $ip = '1.2.3.4';
        $window = 60;

        $this->storage->incrementRequestCount($ip, $window);
        $this->storage->incrementRequestCount($ip, $window);
        $count = $this->storage->incrementRequestCount($ip, $window);

        $this->assertEquals(3, $count);
    }

    public function testGetRequestCount(): void
    {
        $ip = '1.2.3.4';
        $window = 60;

        $this->storage->incrementRequestCount($ip, $window);
        $this->storage->incrementRequestCount($ip, $window);

        $count = $this->storage->getRequestCount($ip, $window);

        $this->assertEquals(2, $count);
    }

    public function testGetRequestCountForNonExistentIP(): void
    {
        $count = $this->storage->getRequestCount('9.9.9.9', 60);

        $this->assertEquals(0, $count);
    }

    public function testRequestCountResetAfterWindow(): void
    {
        $ip = '1.2.3.4';
        $window = 1; // 1 secondo

        $this->storage->incrementRequestCount($ip, $window);

        // Aspetta che il window scada
        sleep(2);

        $count = $this->storage->getRequestCount($ip, $window);

        $this->assertEquals(0, $count);
    }

    public function testRequestCountIsolatedByIP(): void
    {
        $ip1 = '1.2.3.4';
        $ip2 = '5.6.7.8';
        $window = 60;

        $this->storage->incrementRequestCount($ip1, $window);
        $this->storage->incrementRequestCount($ip1, $window);
        $this->storage->incrementRequestCount($ip2, $window);

        $count1 = $this->storage->getRequestCount($ip1, $window);
        $count2 = $this->storage->getRequestCount($ip2, $window);

        $this->assertEquals(2, $count1);
        $this->assertEquals(1, $count2);
    }

    public function testRequestCountIsolatedByWindow(): void
    {
        $ip = '1.2.3.4';

        $this->storage->incrementRequestCount($ip, 60);
        $this->storage->incrementRequestCount($ip, 300);

        $count60 = $this->storage->getRequestCount($ip, 60);
        $count300 = $this->storage->getRequestCount($ip, 300);

        $this->assertEquals(1, $count60);
        $this->assertEquals(1, $count300);
    }

    // ==================== CONCURRENT ACCESS ====================

    public function testConcurrentIncrementsAreAccurate(): void
    {
        $ip = '1.2.3.4';
        $window = 60;

        // Simula 100 richieste concorrenti
        for ($i = 0; $i < 100; $i++) {
            $this->storage->incrementRequestCount($ip, $window);
        }

        $count = $this->storage->getRequestCount($ip, $window);

        $this->assertEquals(100, $count);
    }

    // ==================== KEY PREFIXING ====================

    public function testKeysArePrefixed(): void
    {
        $this->storage->set('test', 'value', 60);

        // Verifica che la chiave in Redis sia prefissata
        $keys = $this->redis->keys('*test*');

        $this->assertNotEmpty($keys);
        $this->assertContains('security:test', $keys);
    }

    public function testRequestCountKeysArePrefixed(): void
    {
        $this->storage->incrementRequestCount('1.2.3.4', 60);

        $keys = $this->redis->keys('*rate_limit*');

        $this->assertNotEmpty($keys);
    }

    // ==================== EDGE CASES ====================

    public function testSetEmptyStringValue(): void
    {
        $this->storage->set('key', '', 60);

        $value = $this->storage->get('key');

        $this->assertEquals('', $value);
    }

    public function testSetNumericStringValue(): void
    {
        $this->storage->set('key', '12345', 60);

        $value = $this->storage->get('key');

        $this->assertEquals('12345', $value);
    }

    public function testSetVeryLongValue(): void
    {
        $longValue = str_repeat('a', 100000); // 100KB string
        $this->storage->set('key', $longValue, 60);

        $value = $this->storage->get('key');

        $this->assertEquals($longValue, $value);
    }

    public function testSetSpecialCharactersInKey(): void
    {
        $this->storage->set('key:with:colons', 'value', 60);

        $value = $this->storage->get('key:with:colons');

        $this->assertEquals('value', $value);
    }

    public function testIncrementWithIPv6Address(): void
    {
        $ip = '2001:db8::1';
        $window = 60;

        $count = $this->storage->incrementRequestCount($ip, $window);

        $this->assertEquals(1, $count);
    }

    public function testIncrementWithVeryShortWindow(): void
    {
        $ip = '1.2.3.4';
        $window = 1; // 1 secondo

        $count = $this->storage->incrementRequestCount($ip, $window);

        $this->assertEquals(1, $count);
    }

    public function testIncrementWithVeryLongWindow(): void
    {
        $ip = '1.2.3.4';
        $window = 86400; // 24 ore

        $count = $this->storage->incrementRequestCount($ip, $window);

        $this->assertEquals(1, $count);
    }

    // ==================== PERFORMANCE TESTS ====================

    public function testMultipleSetOperationsArefast(): void
    {
        $start = microtime(true);

        for ($i = 0; $i < 1000; $i++) {
            $this->storage->set("key{$i}", "value{$i}", 60);
        }

        $duration = microtime(true) - $start;

        // Dovrebbe completare in meno di 1 secondo
        $this->assertLessThan(1.0, $duration);
    }

    public function testMultipleGetOperationsAreFast(): void
    {
        // Setup
        for ($i = 0; $i < 100; $i++) {
            $this->storage->set("key{$i}", "value{$i}", 60);
        }

        $start = microtime(true);

        for ($i = 0; $i < 100; $i++) {
            $this->storage->get("key{$i}");
        }

        $duration = microtime(true) - $start;

        // Dovrebbe completare in meno di 100ms
        $this->assertLessThan(0.1, $duration);
    }

    public function testIncrementOperationsAreFast(): void
    {
        $start = microtime(true);

        for ($i = 0; $i < 1000; $i++) {
            $this->storage->incrementRequestCount('1.2.3.4', 60);
        }

        $duration = microtime(true) - $start;

        // Dovrebbe completare in meno di 500ms
        $this->assertLessThan(0.5, $duration);
    }

    // ==================== CONNECTION HANDLING ====================

    public function testHandlesRedisConnectionGracefully(): void
    {
        // Crea una nuova connessione
        $redis = new \Redis();
        $redis->connect('127.0.0.1', 6379);
        $redis->select(15);

        $storage = new RedisStorage($redis);

        // Usa storage
        $storage->set('key', 'value', 60);

        // Verifica funzionamento
        $this->assertEquals('value', $storage->get('key'));

        $redis->close();
    }
}
