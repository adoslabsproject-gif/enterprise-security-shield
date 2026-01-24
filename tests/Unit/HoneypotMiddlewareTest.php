<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Config\SecurityConfig;
use Senza1dio\SecurityShield\Middleware\HoneypotMiddleware;
use Senza1dio\SecurityShield\Tests\Fixtures\InMemoryStorage;

/**
 * Test Suite for HoneypotMiddleware
 */
final class HoneypotMiddlewareTest extends TestCase
{
    private SecurityConfig $config;
    private InMemoryStorage $storage;

    protected function setUp(): void
    {
        $this->storage = new InMemoryStorage();
        $this->config = SecurityConfig::create()
            ->setStorage($this->storage)
            ->enableHoneypot(true);
    }

    // ==================== BASIC INSTANTIATION ====================

    public function testCanBeInstantiated(): void
    {
        $honeypot = new HoneypotMiddleware($this->config);
        $this->assertInstanceOf(HoneypotMiddleware::class, $honeypot);
    }

    public function testCanBeInstantiatedWithCustomPaths(): void
    {
        $customPaths = ['/trap1', '/trap2'];
        $honeypot = new HoneypotMiddleware($this->config, $customPaths);
        $this->assertInstanceOf(HoneypotMiddleware::class, $honeypot);
    }

    // ==================== PATH DETECTION ====================

    public function testDetectsDefaultHoneypotPaths(): void
    {
        $honeypot = new HoneypotMiddleware($this->config);

        // These are known default honeypot paths
        $this->assertTrue($honeypot->isHoneypotPath('/.env'));
        $this->assertTrue($honeypot->isHoneypotPath('/phpinfo.php'));
        $this->assertTrue($honeypot->isHoneypotPath('/wp-admin'));
        $this->assertTrue($honeypot->isHoneypotPath('/wp-login.php'));
    }

    public function testDoesNotFlagLegitimateURIs(): void
    {
        $honeypot = new HoneypotMiddleware($this->config);

        $this->assertFalse($honeypot->isHoneypotPath('/'));
        $this->assertFalse($honeypot->isHoneypotPath('/about'));
        $this->assertFalse($honeypot->isHoneypotPath('/products'));
        $this->assertFalse($honeypot->isHoneypotPath('/api/users'));
    }

    public function testDetectsCustomHoneypotPaths(): void
    {
        $customPaths = ['/secret-trap', '/hidden-endpoint'];
        $honeypot = new HoneypotMiddleware($this->config, $customPaths);

        $this->assertTrue($honeypot->isHoneypotPath('/secret-trap'));
        $this->assertTrue($honeypot->isHoneypotPath('/hidden-endpoint'));
    }

    public function testPathDetectionIsCaseInsensitive(): void
    {
        $honeypot = new HoneypotMiddleware($this->config);

        // Should match regardless of case
        $this->assertTrue($honeypot->isHoneypotPath('/.ENV'));
        $this->assertTrue($honeypot->isHoneypotPath('/PHPINFO.PHP'));
    }

    public function testPathDetectionWithQueryString(): void
    {
        $honeypot = new HoneypotMiddleware($this->config);

        // Should detect path even with query string
        $this->assertTrue($honeypot->isHoneypotPath('/.env?foo=bar'));
        $this->assertTrue($honeypot->isHoneypotPath('/phpinfo.php?test=1'));
    }

    // ==================== HONEYPOT DISABLED ====================

    public function testHoneypotDisabledReturnsEarly(): void
    {
        $disabledConfig = SecurityConfig::create()
            ->setStorage($this->storage)
            ->enableHoneypot(false);

        $honeypot = new HoneypotMiddleware($disabledConfig);

        // When disabled, isHoneypotPath should return false
        $this->assertFalse($honeypot->isHoneypotPath('/.env'));
    }

    // ==================== COMMON ATTACK PATHS ====================

    public function testDetectsEnvFiles(): void
    {
        $honeypot = new HoneypotMiddleware($this->config);

        $this->assertTrue($honeypot->isHoneypotPath('/.env'));
        $this->assertTrue($honeypot->isHoneypotPath('/.env.local'));
        $this->assertTrue($honeypot->isHoneypotPath('/.env.production'));
    }

    public function testDetectsGitPaths(): void
    {
        $honeypot = new HoneypotMiddleware($this->config);

        $this->assertTrue($honeypot->isHoneypotPath('/.git/config'));
        $this->assertTrue($honeypot->isHoneypotPath('/.git/HEAD'));
    }

    public function testDetectsWordPressPaths(): void
    {
        $honeypot = new HoneypotMiddleware($this->config);

        $this->assertTrue($honeypot->isHoneypotPath('/wp-admin'));
        $this->assertTrue($honeypot->isHoneypotPath('/wp-login.php'));
        $this->assertTrue($honeypot->isHoneypotPath('/wp-config.php'));
    }

    public function testDetectsBackupFiles(): void
    {
        $honeypot = new HoneypotMiddleware($this->config);

        $this->assertTrue($honeypot->isHoneypotPath('/backup.sql'));
        $this->assertTrue($honeypot->isHoneypotPath('/dump.sql'));
        $this->assertTrue($honeypot->isHoneypotPath('/database.sql'));
    }

    public function testDetectsCredentialFiles(): void
    {
        $honeypot = new HoneypotMiddleware($this->config);

        $this->assertTrue($honeypot->isHoneypotPath('/.aws/credentials'));
        $this->assertTrue($honeypot->isHoneypotPath('/.ssh/id_rsa'));
    }

    // ==================== EDGE CASES ====================

    public function testEmptyPathReturnsFalse(): void
    {
        $honeypot = new HoneypotMiddleware($this->config);

        $this->assertFalse($honeypot->isHoneypotPath(''));
    }

    public function testRootPathReturnsFalse(): void
    {
        $honeypot = new HoneypotMiddleware($this->config);

        $this->assertFalse($honeypot->isHoneypotPath('/'));
    }

    public function testPathWithSpecialCharacters(): void
    {
        $honeypot = new HoneypotMiddleware($this->config);

        // Should handle URL encoded paths
        $this->assertTrue($honeypot->isHoneypotPath('/%2Eenv'));
    }

}
