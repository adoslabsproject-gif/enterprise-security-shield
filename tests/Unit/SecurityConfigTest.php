<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Config\SecurityConfig;

/**
 * Test Suite for SecurityConfig
 *
 * Coverage:
 * - Fluent API builder pattern
 * - Default values
 * - Configuration validation
 * - Getter methods
 * - Edge cases
 *
 * @package Senza1dio\SecurityShield\Tests\Unit
 */
final class SecurityConfigTest extends TestCase
{
    // ==================== BASIC CREATION ====================

    public function testCreateReturnsNewInstance(): void
    {
        $config = SecurityConfig::create();

        $this->assertInstanceOf(SecurityConfig::class, $config);
    }

    public function testCreateReturnsNewInstanceEachTime(): void
    {
        $config1 = SecurityConfig::create();
        $config2 = SecurityConfig::create();

        $this->assertNotSame($config1, $config2);
    }

    // ==================== DEFAULT VALUES ====================

    public function testDefaultWAFEnabled(): void
    {
        $config = SecurityConfig::create();

        $this->assertTrue($config->isWAFEnabled());
    }

    public function testDefaultHoneypotEnabled(): void
    {
        $config = SecurityConfig::create();

        $this->assertTrue($config->isHoneypotEnabled());
    }

    public function testDefaultBotProtectionEnabled(): void
    {
        $config = SecurityConfig::create();

        $this->assertTrue($config->isBotProtectionEnabled());
    }

    public function testDefaultRateLimitIs100(): void
    {
        $config = SecurityConfig::create();

        $this->assertEquals(100, $config->getRateLimitPerMinute());
    }

    public function testDefaultSQLInjectionDetectionEnabled(): void
    {
        $config = SecurityConfig::create();

        $this->assertTrue($config->isSQLInjectionDetectionEnabled());
    }

    public function testDefaultXSSDetectionEnabled(): void
    {
        $config = SecurityConfig::create();

        $this->assertTrue($config->isXSSDetectionEnabled());
    }

    public function testDefaultWhitelistedIPsEmpty(): void
    {
        $config = SecurityConfig::create();

        $this->assertEquals([], $config->getWhitelistedIPs());
    }

    public function testDefaultBlacklistedIPsEmpty(): void
    {
        $config = SecurityConfig::create();

        $this->assertEquals([], $config->getBlacklistedIPs());
    }

    public function testDefaultHoneypotEndpointsProvided(): void
    {
        $config = SecurityConfig::create();

        $endpoints = $config->getHoneypotEndpoints();

        $this->assertIsArray($endpoints);
        $this->assertNotEmpty($endpoints);
        $this->assertContains('/admin', $endpoints);
        $this->assertContains('/wp-admin', $endpoints);
    }

    // ==================== FLUENT API (CHAINING) ====================

    public function testFluentAPIReturnsInstance(): void
    {
        $config = SecurityConfig::create();

        $result = $config->enableWAF(true);

        $this->assertSame($config, $result);
    }

    public function testFluentAPIChaining(): void
    {
        $config = SecurityConfig::create()
            ->enableWAF(true)
            ->enableHoneypot(false)
            ->enableBotProtection(true)
            ->setRateLimitPerMinute(50);

        $this->assertInstanceOf(SecurityConfig::class, $config);
        $this->assertTrue($config->isWAFEnabled());
        $this->assertFalse($config->isHoneypotEnabled());
        $this->assertTrue($config->isBotProtectionEnabled());
        $this->assertEquals(50, $config->getRateLimitPerMinute());
    }

    public function testComplexFluentAPIChaining(): void
    {
        $config = SecurityConfig::create()
            ->enableWAF(true)
            ->enableHoneypot(true)
            ->enableBotProtection(false)
            ->setRateLimitPerMinute(200)
            ->enableSQLInjectionDetection(false)
            ->enableXSSDetection(false)
            ->setWhitelistedIPs(['1.2.3.4', '5.6.7.8'])
            ->setBlacklistedIPs(['9.10.11.12'])
            ->setHoneypotEndpoints(['/secret', '/backup']);

        $this->assertTrue($config->isWAFEnabled());
        $this->assertTrue($config->isHoneypotEnabled());
        $this->assertFalse($config->isBotProtectionEnabled());
        $this->assertEquals(200, $config->getRateLimitPerMinute());
        $this->assertFalse($config->isSQLInjectionDetectionEnabled());
        $this->assertFalse($config->isXSSDetectionEnabled());
        $this->assertEquals(['1.2.3.4', '5.6.7.8'], $config->getWhitelistedIPs());
        $this->assertEquals(['9.10.11.12'], $config->getBlacklistedIPs());
        $this->assertEquals(['/secret', '/backup'], $config->getHoneypotEndpoints());
    }

    // ==================== WAF CONFIGURATION ====================

    public function testEnableWAF(): void
    {
        $config = SecurityConfig::create()->enableWAF(true);

        $this->assertTrue($config->isWAFEnabled());
    }

    public function testDisableWAF(): void
    {
        $config = SecurityConfig::create()->enableWAF(false);

        $this->assertFalse($config->isWAFEnabled());
    }

    public function testToggleWAF(): void
    {
        $config = SecurityConfig::create()
            ->enableWAF(true)
            ->enableWAF(false)
            ->enableWAF(true);

        $this->assertTrue($config->isWAFEnabled());
    }

    // ==================== HONEYPOT CONFIGURATION ====================

    public function testEnableHoneypot(): void
    {
        $config = SecurityConfig::create()->enableHoneypot(true);

        $this->assertTrue($config->isHoneypotEnabled());
    }

    public function testDisableHoneypot(): void
    {
        $config = SecurityConfig::create()->enableHoneypot(false);

        $this->assertFalse($config->isHoneypotEnabled());
    }

    public function testSetHoneypotEndpoints(): void
    {
        $endpoints = ['/trap1', '/trap2', '/trap3'];
        $config = SecurityConfig::create()->setHoneypotEndpoints($endpoints);

        $this->assertEquals($endpoints, $config->getHoneypotEndpoints());
    }

    public function testSetEmptyHoneypotEndpoints(): void
    {
        $config = SecurityConfig::create()->setHoneypotEndpoints([]);

        $this->assertEquals([], $config->getHoneypotEndpoints());
    }

    // ==================== BOT PROTECTION CONFIGURATION ====================

    public function testEnableBotProtection(): void
    {
        $config = SecurityConfig::create()->enableBotProtection(true);

        $this->assertTrue($config->isBotProtectionEnabled());
    }

    public function testDisableBotProtection(): void
    {
        $config = SecurityConfig::create()->enableBotProtection(false);

        $this->assertFalse($config->isBotProtectionEnabled());
    }

    // ==================== RATE LIMITING CONFIGURATION ====================

    public function testSetRateLimitPerMinute(): void
    {
        $config = SecurityConfig::create()->setRateLimitPerMinute(50);

        $this->assertEquals(50, $config->getRateLimitPerMinute());
    }

    public function testSetHighRateLimit(): void
    {
        $config = SecurityConfig::create()->setRateLimitPerMinute(1000);

        $this->assertEquals(1000, $config->getRateLimitPerMinute());
    }

    public function testSetLowRateLimit(): void
    {
        $config = SecurityConfig::create()->setRateLimitPerMinute(1);

        $this->assertEquals(1, $config->getRateLimitPerMinute());
    }

    public function testSetZeroRateLimit(): void
    {
        // Rate limit 0 dovrebbe disabilitare il limiting
        $config = SecurityConfig::create()->setRateLimitPerMinute(0);

        $this->assertEquals(0, $config->getRateLimitPerMinute());
    }

    // ==================== SQL INJECTION DETECTION ====================

    public function testEnableSQLInjectionDetection(): void
    {
        $config = SecurityConfig::create()->enableSQLInjectionDetection(true);

        $this->assertTrue($config->isSQLInjectionDetectionEnabled());
    }

    public function testDisableSQLInjectionDetection(): void
    {
        $config = SecurityConfig::create()->enableSQLInjectionDetection(false);

        $this->assertFalse($config->isSQLInjectionDetectionEnabled());
    }

    // ==================== XSS DETECTION ====================

    public function testEnableXSSDetection(): void
    {
        $config = SecurityConfig::create()->enableXSSDetection(true);

        $this->assertTrue($config->isXSSDetectionEnabled());
    }

    public function testDisableXSSDetection(): void
    {
        $config = SecurityConfig::create()->enableXSSDetection(false);

        $this->assertFalse($config->isXSSDetectionEnabled());
    }

    // ==================== WHITELIST CONFIGURATION ====================

    public function testSetWhitelistedIPs(): void
    {
        $ips = ['1.2.3.4', '5.6.7.8'];
        $config = SecurityConfig::create()->setWhitelistedIPs($ips);

        $this->assertEquals($ips, $config->getWhitelistedIPs());
    }

    public function testSetEmptyWhitelistedIPs(): void
    {
        $config = SecurityConfig::create()->setWhitelistedIPs([]);

        $this->assertEquals([], $config->getWhitelistedIPs());
    }

    public function testSetSingleWhitelistedIP(): void
    {
        $config = SecurityConfig::create()->setWhitelistedIPs(['1.2.3.4']);

        $this->assertEquals(['1.2.3.4'], $config->getWhitelistedIPs());
    }

    public function testWhitelistedIPsPreserveOrder(): void
    {
        $ips = ['9.9.9.9', '1.1.1.1', '5.5.5.5'];
        $config = SecurityConfig::create()->setWhitelistedIPs($ips);

        $this->assertEquals($ips, $config->getWhitelistedIPs());
    }

    // ==================== BLACKLIST CONFIGURATION ====================

    public function testSetBlacklistedIPs(): void
    {
        $ips = ['1.2.3.4', '5.6.7.8'];
        $config = SecurityConfig::create()->setBlacklistedIPs($ips);

        $this->assertEquals($ips, $config->getBlacklistedIPs());
    }

    public function testSetEmptyBlacklistedIPs(): void
    {
        $config = SecurityConfig::create()->setBlacklistedIPs([]);

        $this->assertEquals([], $config->getBlacklistedIPs());
    }

    public function testSetSingleBlacklistedIP(): void
    {
        $config = SecurityConfig::create()->setBlacklistedIPs(['1.2.3.4']);

        $this->assertEquals(['1.2.3.4'], $config->getBlacklistedIPs());
    }

    // ==================== CONFIGURATION VALIDATION ====================

    public function testCannotSetNegativeRateLimit(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        SecurityConfig::create()->setRateLimitPerMinute(-1);
    }

    public function testCannotSetInvalidWhitelistedIP(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        SecurityConfig::create()->setWhitelistedIPs(['not-an-ip']);
    }

    public function testCannotSetInvalidBlacklistedIP(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        SecurityConfig::create()->setBlacklistedIPs(['not-an-ip']);
    }

    public function testAcceptsValidIPv4Addresses(): void
    {
        $validIPs = [
            '0.0.0.0',
            '127.0.0.1',
            '192.168.1.1',
            '255.255.255.255',
            '8.8.8.8',
        ];

        $config = SecurityConfig::create()->setWhitelistedIPs($validIPs);

        $this->assertEquals($validIPs, $config->getWhitelistedIPs());
    }

    // ==================== IMMUTABILITY TESTS ====================

    public function testConfigurationChangesDoNotAffectOriginal(): void
    {
        $config1 = SecurityConfig::create()->setRateLimitPerMinute(50);
        $config2 = SecurityConfig::create()->setRateLimitPerMinute(100);

        $this->assertEquals(50, $config1->getRateLimitPerMinute());
        $this->assertEquals(100, $config2->getRateLimitPerMinute());
    }

    // ==================== EDGE CASES ====================

    public function testSetHoneypotEndpointsWithDuplicates(): void
    {
        $endpoints = ['/admin', '/admin', '/login'];
        $config = SecurityConfig::create()->setHoneypotEndpoints($endpoints);

        // Dovrebbe preservare duplicati (o rimuoverli, dipende dall'implementazione)
        $result = $config->getHoneypotEndpoints();
        $this->assertIsArray($result);
    }

    public function testSetWhitelistedIPsWithDuplicates(): void
    {
        $ips = ['1.2.3.4', '1.2.3.4', '5.6.7.8'];
        $config = SecurityConfig::create()->setWhitelistedIPs($ips);

        $result = $config->getWhitelistedIPs();
        $this->assertIsArray($result);
    }

    public function testSetVeryHighRateLimit(): void
    {
        $config = SecurityConfig::create()->setRateLimitPerMinute(999999);

        $this->assertEquals(999999, $config->getRateLimitPerMinute());
    }

    public function testSetManyWhitelistedIPs(): void
    {
        $ips = [];
        for ($i = 1; $i <= 255; $i++) {
            $ips[] = "192.168.1.{$i}";
        }

        $config = SecurityConfig::create()->setWhitelistedIPs($ips);

        $this->assertCount(255, $config->getWhitelistedIPs());
    }

    public function testSetManyHoneypotEndpoints(): void
    {
        $endpoints = [];
        for ($i = 1; $i <= 100; $i++) {
            $endpoints[] = "/trap{$i}";
        }

        $config = SecurityConfig::create()->setHoneypotEndpoints($endpoints);

        $this->assertCount(100, $config->getHoneypotEndpoints());
    }

    // ==================== CONFIGURATION PRESETS ====================

    public function testProductionPreset(): void
    {
        // Configurazione tipica produzione
        $config = SecurityConfig::create()
            ->enableWAF(true)
            ->enableHoneypot(true)
            ->enableBotProtection(true)
            ->setRateLimitPerMinute(100)
            ->enableSQLInjectionDetection(true)
            ->enableXSSDetection(true);

        $this->assertTrue($config->isWAFEnabled());
        $this->assertTrue($config->isHoneypotEnabled());
        $this->assertTrue($config->isBotProtectionEnabled());
        $this->assertEquals(100, $config->getRateLimitPerMinute());
        $this->assertTrue($config->isSQLInjectionDetectionEnabled());
        $this->assertTrue($config->isXSSDetectionEnabled());
    }

    public function testDevelopmentPreset(): void
    {
        // Configurazione tipica sviluppo (tutto disabilitato)
        $config = SecurityConfig::create()
            ->enableWAF(false)
            ->enableHoneypot(false)
            ->enableBotProtection(false)
            ->setRateLimitPerMinute(0);

        $this->assertFalse($config->isWAFEnabled());
        $this->assertFalse($config->isHoneypotEnabled());
        $this->assertFalse($config->isBotProtectionEnabled());
        $this->assertEquals(0, $config->getRateLimitPerMinute());
    }

    public function testAggressiveProtectionPreset(): void
    {
        // Protezione aggressiva con rate limit basso
        $config = SecurityConfig::create()
            ->enableWAF(true)
            ->enableHoneypot(true)
            ->enableBotProtection(true)
            ->setRateLimitPerMinute(10)
            ->enableSQLInjectionDetection(true)
            ->enableXSSDetection(true);

        $this->assertTrue($config->isWAFEnabled());
        $this->assertTrue($config->isHoneypotEnabled());
        $this->assertTrue($config->isBotProtectionEnabled());
        $this->assertEquals(10, $config->getRateLimitPerMinute());
    }

    // ==================== SERIALIZATION TESTS ====================

    public function testConfigurationCanBeSerialized(): void
    {
        $config = SecurityConfig::create()
            ->enableWAF(true)
            ->setRateLimitPerMinute(50)
            ->setWhitelistedIPs(['1.2.3.4']);

        $serialized = serialize($config);
        $unserialized = unserialize($serialized);

        $this->assertInstanceOf(SecurityConfig::class, $unserialized);
        $this->assertTrue($unserialized->isWAFEnabled());
        $this->assertEquals(50, $unserialized->getRateLimitPerMinute());
        $this->assertEquals(['1.2.3.4'], $unserialized->getWhitelistedIPs());
    }

    // ==================== TYPE SAFETY TESTS ====================

    public function testGettersReturnCorrectTypes(): void
    {
        $config = SecurityConfig::create();

        $this->assertIsBool($config->isWAFEnabled());
        $this->assertIsBool($config->isHoneypotEnabled());
        $this->assertIsBool($config->isBotProtectionEnabled());
        $this->assertIsInt($config->getRateLimitPerMinute());
        $this->assertIsBool($config->isSQLInjectionDetectionEnabled());
        $this->assertIsBool($config->isXSSDetectionEnabled());
        $this->assertIsArray($config->getWhitelistedIPs());
        $this->assertIsArray($config->getBlacklistedIPs());
        $this->assertIsArray($config->getHoneypotEndpoints());
    }
}
