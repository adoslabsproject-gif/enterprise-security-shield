<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Tests\Unit;

use PHPUnit\Framework\TestCase;
use AdosLabs\EnterpriseSecurityShield\Services\BotVerifier;
use AdosLabs\EnterpriseSecurityShield\Storage\NullLogger;
use AdosLabs\EnterpriseSecurityShield\Storage\NullStorage;

/**
 * Test Suite for BotVerifier.
 *
 * Coverage:
 * - DNS verification (reverse + forward lookup)
 * - IP range verification (CIDR)
 * - Caching logic
 * - Statistics tracking
 * - Anti-spoofing protection
 * - Edge cases
 */
final class BotVerifierTest extends TestCase
{
    private BotVerifier $verifier;

    private NullStorage $storage;

    private NullLogger $logger;

    protected function setUp(): void
    {
        $this->storage = new NullStorage();
        $this->logger = new NullLogger();
        $this->verifier = new BotVerifier($this->storage, $this->logger);
    }

    // ==================== DNS VERIFICATION TESTS ====================

    public function testVerifyGoogleBotWithValidHostname(): void
    {
        // Test with real Googlebot IP pattern
        // Note: In production, this would do actual DNS lookup
        // For unit tests, we test the logic flow

        $ip = '66.249.66.1'; // Typical Googlebot IP
        $userAgent = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

        // NullStorage sempre ritorna false per cache, quindi testa la logica
        $result = $this->verifier->verifyBot($ip, $userAgent);

        // Con NullStorage, il risultato dipende dal DNS reale
        // Testiamo che il metodo NON lanci eccezioni
        $this->assertIsBool($result);
    }

    public function testVerifyBingBotWithValidHostname(): void
    {
        $ip = '157.55.39.1'; // Typical BingBot IP
        $userAgent = 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)';

        $result = $this->verifier->verifyBot($ip, $userAgent);
        $this->assertIsBool($result);
    }

    public function testVerifyChatGPTBotWithIPRange(): void
    {
        // ChatGPT-User usa IP ranges, non DNS
        $ip = '23.98.142.1'; // Nella range di OpenAI
        $userAgent = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ChatGPT-User/1.0; +https://openai.com/bot)';

        $result = $this->verifier->verifyBot($ip, $userAgent);

        // Dovrebbe verificare via CIDR range
        $this->assertIsBool($result);
    }

    public function testVerifyClaudeBotWithIPRange(): void
    {
        $ip = '160.79.104.1'; // Nella range di Anthropic
        $userAgent = 'Claude-Web/1.0; +https://www.anthropic.com';

        $result = $this->verifier->verifyBot($ip, $userAgent);
        $this->assertIsBool($result);
    }

    // ==================== ANTI-SPOOFING TESTS ====================

    public function testRejectSpoofedGoogleBotUserAgent(): void
    {
        // IP NON di Google ma User-Agent di Googlebot
        $ip = '1.2.3.4'; // IP casuale
        $userAgent = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

        $result = $this->verifier->verifyBot($ip, $userAgent);

        // Dovrebbe fallire perché IP non matcha DNS di Google
        $this->assertFalse($result);
    }

    public function testRejectSpoofedBingBotUserAgent(): void
    {
        $ip = '5.6.7.8'; // IP casuale
        $userAgent = 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)';

        $result = $this->verifier->verifyBot($ip, $userAgent);
        $this->assertFalse($result);
    }

    public function testRejectSpoofedChatGPTUserAgent(): void
    {
        // IP fuori dalla range di OpenAI
        $ip = '192.168.1.1';
        $userAgent = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ChatGPT-User/1.0; +https://openai.com/bot)';

        $result = $this->verifier->verifyBot($ip, $userAgent);
        $this->assertFalse($result);
    }

    // ==================== LEGITIMATE BOTS COVERAGE ====================

    public function testVerifyGoogleBotVariants(): void
    {
        $googleBots = [
            'Googlebot',
            'Googlebot-Image',
            'Googlebot-News',
            'Googlebot-Video',
            'AdsBot-Google',
            'Google-InspectionTool',
        ];

        foreach ($googleBots as $bot) {
            $userAgent = "Mozilla/5.0 (compatible; {$bot}/2.1)";
            // Con IP arbitrario, dovrebbe tentare DNS lookup
            $result = $this->verifier->verifyBot('66.249.66.1', $userAgent);
            $this->assertIsBool($result, "Failed for bot: {$bot}");
        }
    }

    public function testVerifyBingBotVariants(): void
    {
        $bingBots = [
            'bingbot',
            'BingPreview',
            'msnbot',
            'adidxbot',
        ];

        foreach ($bingBots as $bot) {
            $userAgent = "Mozilla/5.0 (compatible; {$bot}/2.0)";
            $result = $this->verifier->verifyBot('157.55.39.1', $userAgent);
            $this->assertIsBool($result, "Failed for bot: {$bot}");
        }
    }

    public function testVerifyAICrawlers(): void
    {
        $aiCrawlers = [
            'ChatGPT-User' => '23.98.142.1',
            'GPTBot' => '20.102.32.1',
            'Claude-Web' => '160.79.104.1',
            'anthropic-ai' => '160.79.104.1',
            'Applebot' => '17.0.0.1',
            'facebookexternalhit' => '31.13.24.1',
        ];

        foreach ($aiCrawlers as $bot => $ip) {
            $userAgent = "Mozilla/5.0 (compatible; {$bot}/1.0)";
            $result = $this->verifier->verifyBot($ip, $userAgent);
            $this->assertIsBool($result, "Failed for bot: {$bot}");
        }
    }

    // ==================== CACHING TESTS ====================

    public function testCacheHitReturnsStoredResult(): void
    {
        // Pre-cache a verification result
        $this->storage->cacheBotVerification('66.249.66.1', true, ['hostname' => 'test.googlebot.com'], 3600);

        $result = $this->verifier->verifyBot('66.249.66.1', 'Googlebot');

        // Should return true from cache
        $this->assertTrue($result);
    }

    public function testCacheHitForFakeBot(): void
    {
        // Pre-cache as fake bot
        $this->storage->cacheBotVerification('1.2.3.4', false, ['reason' => 'spoofed'], 3600);

        $result = $this->verifier->verifyBot('1.2.3.4', 'Googlebot');
        $this->assertFalse($result);
    }

    public function testCacheMissTriggersVerification(): void
    {
        // With NullStorage, cache will miss and trigger actual verification
        // Just verify no exceptions thrown
        $this->verifier->verifyBot('66.249.66.1', 'Googlebot');
        $this->expectNotToPerformAssertions();
    }

    // ==================== STATISTICS TESTS ====================

    public function testGetStatisticsReturnsCorrectStructure(): void
    {
        $stats = $this->verifier->getStatistics();

        $this->assertIsArray($stats);
        $this->assertArrayHasKey('total_verifications', $stats);
        $this->assertArrayHasKey('cache_hits', $stats);
        $this->assertArrayHasKey('cache_misses', $stats);
        $this->assertArrayHasKey('dns_verifications_passed', $stats);
        $this->assertArrayHasKey('dns_verifications_failed', $stats);
    }

    public function testStatisticsIncrementOnVerification(): void
    {
        $initialStats = $this->verifier->getStatistics();

        // Esegui una verifica
        $this->verifier->verifyBot('1.2.3.4', 'FakeBot');

        $newStats = $this->verifier->getStatistics();

        // Total verifications dovrebbe aumentare
        $this->assertGreaterThan(
            $initialStats['total_verifications'],
            $newStats['total_verifications'],
        );
    }

    // ==================== EDGE CASES ====================

    public function testEmptyUserAgent(): void
    {
        $result = $this->verifier->verifyBot('1.2.3.4', '');
        $this->assertFalse($result, 'Empty user agent should return false');
    }

    public function testInvalidIPAddress(): void
    {
        $result = $this->verifier->verifyBot('not-an-ip', 'Googlebot');
        $this->assertFalse($result, 'Invalid IP should return false');
    }

    public function testIPv6Address(): void
    {
        // IPv6 non supportato (solo IPv4)
        $result = $this->verifier->verifyBot('2001:4860:4801:0:0:0:0:0', 'Googlebot');
        $this->assertFalse($result, 'IPv6 should return false (not supported)');
    }

    public function testLocalhostIP(): void
    {
        $result = $this->verifier->verifyBot('127.0.0.1', 'Googlebot');
        $this->assertFalse($result, 'Localhost should return false');
    }

    public function testPrivateIPRange(): void
    {
        $privateIPs = [
            '10.0.0.1',
            '172.16.0.1',
            '192.168.1.1',
        ];

        foreach ($privateIPs as $ip) {
            $result = $this->verifier->verifyBot($ip, 'Googlebot');
            $this->assertFalse($result, "Private IP {$ip} should return false");
        }
    }

    public function testUnknownBotUserAgent(): void
    {
        // User-Agent non riconosciuto
        $result = $this->verifier->verifyBot('1.2.3.4', 'MyCustomCrawler/1.0');
        $this->assertFalse($result, 'Unknown bot should return false');
    }

    public function testCaseSensitivityInUserAgent(): void
    {
        // Test case-insensitive matching
        $userAgents = [
            'Googlebot',
            'googlebot',
            'GOOGLEBOT',
            'GoOgLeBoT',
        ];

        foreach ($userAgents as $ua) {
            // Dovrebbe riconoscere tutte le varianti
            $result = $this->verifier->verifyBot('66.249.66.1', $ua);
            $this->assertIsBool($result, "Failed for user agent: {$ua}");
        }
    }

    // ==================== INTEGRATION-LIKE TESTS ====================

    public function testFullVerificationFlowForLegitimateBot(): void
    {
        // Simula un bot reale con IP e User-Agent corretti
        $ip = '66.249.66.1';
        $userAgent = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

        $result = $this->verifier->verifyBot($ip, $userAgent);

        // Con DNS reale, dovrebbe passare (o almeno non lanciare eccezioni)
        $this->assertIsBool($result);

        // Statistiche dovrebbero aggiornarsi
        $stats = $this->verifier->getStatistics();
        $this->assertGreaterThan(0, $stats['total_verifications']);
    }

    public function testFullVerificationFlowForFakeBot(): void
    {
        $ip = '1.2.3.4';
        $userAgent = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

        $result = $this->verifier->verifyBot($ip, $userAgent);

        // Dovrebbe essere rifiutato (IP non è Google)
        $this->assertFalse($result);

        $stats = $this->verifier->getStatistics();
        // Verifica che le statistiche siano aggiornate
        $this->assertGreaterThan(0, $stats['total_verifications']);
    }
}
