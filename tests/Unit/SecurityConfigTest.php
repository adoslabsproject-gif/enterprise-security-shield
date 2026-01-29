<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Tests\Unit;

use AdosLabs\EnterpriseSecurityShield\Config\SecurityConfig;
use PHPUnit\Framework\TestCase;

/**
 * Test Suite for SecurityConfig.
 *
 * Tests the fluent builder API and configuration methods.
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

    public function testDefaultScoreThreshold(): void
    {
        $config = SecurityConfig::create();
        $this->assertEquals(50, $config->getScoreThreshold());
    }

    public function testDefaultBanDuration(): void
    {
        $config = SecurityConfig::create();
        $this->assertEquals(86400, $config->getBanDuration()); // 24h
    }

    public function testDefaultHoneypotEnabled(): void
    {
        $config = SecurityConfig::create();
        $this->assertTrue($config->isHoneypotEnabled());
    }

    public function testDefaultBotVerificationEnabled(): void
    {
        $config = SecurityConfig::create();
        $this->assertTrue($config->isBotVerificationEnabled());
    }

    public function testDefaultRateLimitMax(): void
    {
        $config = SecurityConfig::create();
        $this->assertEquals(100, $config->getRateLimitMax());
    }

    public function testDefaultRateLimitWindow(): void
    {
        $config = SecurityConfig::create();
        $this->assertEquals(60, $config->getRateLimitWindow());
    }

    public function testDefaultIPWhitelistEmpty(): void
    {
        $config = SecurityConfig::create();
        $this->assertEquals([], $config->getIPWhitelist());
    }

    public function testDefaultIPBlacklistEmpty(): void
    {
        $config = SecurityConfig::create();
        $this->assertEquals([], $config->getIPBlacklist());
    }

    public function testDefaultEnvironment(): void
    {
        $config = SecurityConfig::create();
        $this->assertEquals('production', $config->getEnvironment());
    }

    public function testDefaultFailClosedDisabled(): void
    {
        $config = SecurityConfig::create();
        $this->assertFalse($config->isFailClosedEnabled());
    }

    // ==================== FLUENT API ====================

    public function testFluentAPIReturnsInstance(): void
    {
        $config = SecurityConfig::create();
        $result = $config->enableHoneypot(true);
        $this->assertSame($config, $result);
    }

    public function testFluentAPIChaining(): void
    {
        $config = SecurityConfig::create()
            ->enableHoneypot(false)
            ->enableBotVerification(true)
            ->setRateLimitMax(50);

        $this->assertFalse($config->isHoneypotEnabled());
        $this->assertTrue($config->isBotVerificationEnabled());
        $this->assertEquals(50, $config->getRateLimitMax());
    }

    public function testComplexFluentAPIChaining(): void
    {
        $config = SecurityConfig::create()
            ->setScoreThreshold(100)
            ->setBanDuration(3600)
            ->enableHoneypot(true)
            ->enableBotVerification(false)
            ->setRateLimitMax(200)
            ->setRateLimitWindow(120)
            ->setIPWhitelist(['1.2.3.4', '5.6.7.8'])
            ->setIPBlacklist(['9.10.11.12'])
            ->setEnvironment('staging');

        $this->assertEquals(100, $config->getScoreThreshold());
        $this->assertEquals(3600, $config->getBanDuration());
        $this->assertTrue($config->isHoneypotEnabled());
        $this->assertFalse($config->isBotVerificationEnabled());
        $this->assertEquals(200, $config->getRateLimitMax());
        $this->assertEquals(120, $config->getRateLimitWindow());
        $this->assertEquals(['1.2.3.4', '5.6.7.8'], $config->getIPWhitelist());
        $this->assertEquals(['9.10.11.12'], $config->getIPBlacklist());
        $this->assertEquals('staging', $config->getEnvironment());
    }

    // ==================== SCORE THRESHOLD ====================

    public function testSetScoreThreshold(): void
    {
        $config = SecurityConfig::create()->setScoreThreshold(75);
        $this->assertEquals(75, $config->getScoreThreshold());
    }

    public function testScoreThresholdMinValue(): void
    {
        $config = SecurityConfig::create()->setScoreThreshold(1);
        $this->assertEquals(1, $config->getScoreThreshold());
    }

    public function testScoreThresholdMaxValue(): void
    {
        $config = SecurityConfig::create()->setScoreThreshold(1000);
        $this->assertEquals(1000, $config->getScoreThreshold());
    }

    public function testScoreThresholdBelowMinThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        SecurityConfig::create()->setScoreThreshold(0);
    }

    public function testScoreThresholdAboveMaxThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        SecurityConfig::create()->setScoreThreshold(1001);
    }

    // ==================== BAN DURATION ====================

    public function testSetBanDuration(): void
    {
        $config = SecurityConfig::create()->setBanDuration(3600);
        $this->assertEquals(3600, $config->getBanDuration());
    }

    public function testBanDurationMinValue(): void
    {
        $config = SecurityConfig::create()->setBanDuration(60);
        $this->assertEquals(60, $config->getBanDuration());
    }

    public function testBanDurationMaxValue(): void
    {
        $config = SecurityConfig::create()->setBanDuration(2592000); // 30 days
        $this->assertEquals(2592000, $config->getBanDuration());
    }

    public function testBanDurationBelowMinThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        SecurityConfig::create()->setBanDuration(59);
    }

    public function testBanDurationAboveMaxThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        SecurityConfig::create()->setBanDuration(2592001);
    }

    // ==================== HONEYPOT ====================

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

    public function testToggleHoneypot(): void
    {
        $config = SecurityConfig::create()
            ->enableHoneypot(true)
            ->enableHoneypot(false)
            ->enableHoneypot(true);
        $this->assertTrue($config->isHoneypotEnabled());
    }

    // ==================== BOT VERIFICATION ====================

    public function testEnableBotVerification(): void
    {
        $config = SecurityConfig::create()->enableBotVerification(true);
        $this->assertTrue($config->isBotVerificationEnabled());
    }

    public function testDisableBotVerification(): void
    {
        $config = SecurityConfig::create()->enableBotVerification(false);
        $this->assertFalse($config->isBotVerificationEnabled());
    }

    // ==================== RATE LIMITING ====================

    public function testSetRateLimitMax(): void
    {
        $config = SecurityConfig::create()->setRateLimitMax(50);
        $this->assertEquals(50, $config->getRateLimitMax());
    }

    public function testSetRateLimitWindow(): void
    {
        $config = SecurityConfig::create()->setRateLimitWindow(300);
        $this->assertEquals(300, $config->getRateLimitWindow());
    }

    public function testRateLimitMaxMinValue(): void
    {
        $config = SecurityConfig::create()->setRateLimitMax(1);
        $this->assertEquals(1, $config->getRateLimitMax());
    }

    public function testRateLimitMaxMaxValue(): void
    {
        $config = SecurityConfig::create()->setRateLimitMax(10000);
        $this->assertEquals(10000, $config->getRateLimitMax());
    }

    public function testRateLimitMaxBelowMinThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        SecurityConfig::create()->setRateLimitMax(0);
    }

    public function testRateLimitMaxAboveMaxThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        SecurityConfig::create()->setRateLimitMax(10001);
    }

    public function testRateLimitWindowMinValue(): void
    {
        $config = SecurityConfig::create()->setRateLimitWindow(10);
        $this->assertEquals(10, $config->getRateLimitWindow());
    }

    public function testRateLimitWindowMaxValue(): void
    {
        $config = SecurityConfig::create()->setRateLimitWindow(3600);
        $this->assertEquals(3600, $config->getRateLimitWindow());
    }

    // ==================== IP WHITELIST ====================

    public function testSetIPWhitelist(): void
    {
        $ips = ['1.2.3.4', '5.6.7.8'];
        $config = SecurityConfig::create()->setIPWhitelist($ips);
        $this->assertEquals($ips, $config->getIPWhitelist());
    }

    public function testSetEmptyIPWhitelist(): void
    {
        $config = SecurityConfig::create()->setIPWhitelist([]);
        $this->assertEquals([], $config->getIPWhitelist());
    }

    public function testAddIPWhitelist(): void
    {
        $config = SecurityConfig::create()
            ->addIPWhitelist('1.2.3.4')
            ->addIPWhitelist('5.6.7.8');
        $this->assertEquals(['1.2.3.4', '5.6.7.8'], $config->getIPWhitelist());
    }

    public function testAddIPWhitelistArray(): void
    {
        $config = SecurityConfig::create()
            ->addIPWhitelist(['1.2.3.4', '5.6.7.8']);
        $this->assertEquals(['1.2.3.4', '5.6.7.8'], $config->getIPWhitelist());
    }

    public function testIPWhitelistWithCIDR(): void
    {
        $config = SecurityConfig::create()
            ->addIPWhitelist('192.168.1.0/24');
        $this->assertEquals(['192.168.1.0/24'], $config->getIPWhitelist());
    }

    public function testInvalidIPWhitelistThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        SecurityConfig::create()->setIPWhitelist(['not-an-ip']);
    }

    // ==================== IP BLACKLIST ====================

    public function testSetIPBlacklist(): void
    {
        $ips = ['1.2.3.4', '5.6.7.8'];
        $config = SecurityConfig::create()->setIPBlacklist($ips);
        $this->assertEquals($ips, $config->getIPBlacklist());
    }

    public function testAddIPBlacklist(): void
    {
        $config = SecurityConfig::create()
            ->addIPBlacklist('1.2.3.4')
            ->addIPBlacklist('5.6.7.8');
        $this->assertEquals(['1.2.3.4', '5.6.7.8'], $config->getIPBlacklist());
    }

    public function testIPBlacklistWithCIDR(): void
    {
        $config = SecurityConfig::create()
            ->addIPBlacklist('10.0.0.0/8');
        $this->assertEquals(['10.0.0.0/8'], $config->getIPBlacklist());
    }

    public function testInvalidIPBlacklistThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        SecurityConfig::create()->setIPBlacklist(['invalid']);
    }

    // ==================== ENVIRONMENT ====================

    public function testSetEnvironmentProduction(): void
    {
        $config = SecurityConfig::create()->setEnvironment('production');
        $this->assertEquals('production', $config->getEnvironment());
    }

    public function testSetEnvironmentStaging(): void
    {
        $config = SecurityConfig::create()->setEnvironment('staging');
        $this->assertEquals('staging', $config->getEnvironment());
    }

    public function testSetEnvironmentDevelopment(): void
    {
        $config = SecurityConfig::create()->setEnvironment('development');
        $this->assertEquals('development', $config->getEnvironment());
    }

    public function testInvalidEnvironmentThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        SecurityConfig::create()->setEnvironment('invalid');
    }

    // ==================== TRUSTED PROXIES ====================

    public function testSetTrustedProxies(): void
    {
        $proxies = ['127.0.0.1', '10.0.0.0/8'];
        $config = SecurityConfig::create()->setTrustedProxies($proxies);
        $this->assertEquals($proxies, $config->getTrustedProxies());
    }

    public function testInvalidTrustedProxyThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        SecurityConfig::create()->setTrustedProxies(['not-valid']);
    }

    // ==================== GEOIP ====================

    public function testEnableGeoIP(): void
    {
        $config = SecurityConfig::create()->enableGeoIP(true);
        $this->assertTrue($config->isGeoIPEnabled());
    }

    public function testSetBlockedCountries(): void
    {
        $config = SecurityConfig::create()->setBlockedCountries(['CN', 'RU']);
        $this->assertEquals(['CN', 'RU'], $config->getBlockedCountries());
    }

    public function testInvalidCountryCodeThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        SecurityConfig::create()->setBlockedCountries(['INVALID']);
    }

    // ==================== FAIL CLOSED ====================

    public function testSetFailClosed(): void
    {
        $config = SecurityConfig::create()->setFailClosed(true);
        $this->assertTrue($config->isFailClosedEnabled());
    }

    // ==================== ALERTS ====================

    public function testEnableAlerts(): void
    {
        $config = SecurityConfig::create()->enableAlerts(true);
        $this->assertTrue($config->isAlertsEnabled());
    }

    public function testEnableAlertsWithWebhook(): void
    {
        $config = SecurityConfig::create()->enableAlerts(true, 'https://example.com/webhook');
        $this->assertTrue($config->isAlertsEnabled());
        $this->assertEquals('https://example.com/webhook', $config->getAlertWebhook());
    }

    public function testInvalidWebhookUrlThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        SecurityConfig::create()->enableAlerts(true, 'not-a-url');
    }

    // ==================== CUSTOM PATTERNS ====================

    public function testAddThreatPattern(): void
    {
        $config = SecurityConfig::create()
            ->addThreatPattern('/union\s+select/i', 50, 'SQL Injection');

        $patterns = $config->getCustomPatterns();
        $this->assertCount(1, $patterns);
        $this->assertEquals('/union\s+select/i', $patterns[0]['pattern']);
        $this->assertEquals(50, $patterns[0]['score']);
        $this->assertEquals('SQL Injection', $patterns[0]['description']);
    }

    public function testAddMultipleThreatPatterns(): void
    {
        $config = SecurityConfig::create()
            ->addThreatPattern('/pattern1/', 10, 'Test 1')
            ->addThreatPattern('/pattern2/', 20, 'Test 2');

        $this->assertCount(2, $config->getCustomPatterns());
    }

    public function testInvalidPatternScoreThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        SecurityConfig::create()->addThreatPattern('/test/', 0, 'Invalid');
    }

    // ==================== FROM ARRAY ====================

    public function testFromArray(): void
    {
        $config = SecurityConfig::fromArray([
            'score_threshold' => 75,
            'ban_duration' => 7200,
            'honeypot_enabled' => false,
            'bot_verification_enabled' => true,
            'environment' => 'staging',
        ]);

        $this->assertEquals(75, $config->getScoreThreshold());
        $this->assertEquals(7200, $config->getBanDuration());
        $this->assertFalse($config->isHoneypotEnabled());
        $this->assertTrue($config->isBotVerificationEnabled());
        $this->assertEquals('staging', $config->getEnvironment());
    }

    // ==================== TYPE SAFETY ====================

    public function testGettersReturnCorrectTypes(): void
    {
        $config = SecurityConfig::create();

        $this->assertIsInt($config->getScoreThreshold());
        $this->assertIsInt($config->getBanDuration());
        $this->assertIsInt($config->getTrackingWindow());
        $this->assertIsBool($config->isHoneypotEnabled());
        $this->assertIsBool($config->isBotVerificationEnabled());
        $this->assertIsInt($config->getRateLimitMax());
        $this->assertIsInt($config->getRateLimitWindow());
        $this->assertIsArray($config->getIPWhitelist());
        $this->assertIsArray($config->getIPBlacklist());
        $this->assertIsString($config->getEnvironment());
        $this->assertIsBool($config->isGeoIPEnabled());
        $this->assertIsBool($config->isFailClosedEnabled());
        $this->assertIsBool($config->isAlertsEnabled());
    }
}
