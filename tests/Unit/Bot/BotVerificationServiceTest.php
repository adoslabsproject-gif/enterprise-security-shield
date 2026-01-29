<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Tests\Unit\Bot;

use AdosLabs\EnterpriseSecurityShield\Bot\BotVerificationService;
use PHPUnit\Framework\TestCase;

/**
 * @covers \AdosLabs\EnterpriseSecurityShield\Bot\BotVerificationService
 */
final class BotVerificationServiceTest extends TestCase
{
    private BotVerificationService $service;

    protected function setUp(): void
    {
        $this->service = new BotVerificationService();
        // Disable DNS verification for faster tests
        $this->service->enableDNSVerification(false);
    }

    public function testVerifyReturnsExpectedStructure(): void
    {
        $result = $this->service->verify(
            '192.168.1.1',
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        );

        $this->assertIsArray($result);
        $this->assertArrayHasKey('is_bot', $result);
        $this->assertArrayHasKey('is_verified', $result);
        $this->assertArrayHasKey('bot_id', $result);
        $this->assertArrayHasKey('bot_name', $result);
        $this->assertArrayHasKey('category', $result);
        $this->assertArrayHasKey('verification_method', $result);
        $this->assertArrayHasKey('respect_robots', $result);
        $this->assertArrayHasKey('confidence', $result);
        $this->assertArrayHasKey('details', $result);
    }

    public function testIdentifiesGooglebotUA(): void
    {
        $result = $this->service->verify(
            '66.249.66.1',
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        );

        $this->assertTrue($result['is_bot']);
        $this->assertEquals('googlebot', $result['bot_id']);
        $this->assertEquals('Googlebot', $result['bot_name']);
        $this->assertEquals('search_engine', $result['category']);
    }

    public function testIdentifiesBingbotUA(): void
    {
        $result = $this->service->verify(
            '157.55.39.1',
            'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
        );

        $this->assertTrue($result['is_bot']);
        $this->assertEquals('bingbot', $result['bot_id']);
        $this->assertEquals('Bingbot', $result['bot_name']);
        $this->assertEquals('search_engine', $result['category']);
    }

    public function testIdentifiesFacebookBotByIP(): void
    {
        // Facebook bot in known IP range
        $result = $this->service->verify(
            '69.171.224.1', // Meta IP range
            'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
        );

        $this->assertTrue($result['is_bot']);
        $this->assertEquals('facebookbot', $result['bot_id']);
        $this->assertEquals('Facebook Bot', $result['bot_name']);
        $this->assertEquals('social_media', $result['category']);
        $this->assertTrue($result['is_verified']); // Verified by IP range
        $this->assertEquals('ip_range', $result['verification_method']);
    }

    public function testIdentifiesTwitterbotByIP(): void
    {
        $result = $this->service->verify(
            '199.16.156.1', // Twitter IP range
            'Twitterbot/1.0',
        );

        $this->assertTrue($result['is_bot']);
        $this->assertEquals('twitterbot', $result['bot_id']);
        $this->assertEquals('Twitterbot', $result['bot_name']);
        $this->assertEquals('social_media', $result['category']);
        $this->assertTrue($result['is_verified']);
    }

    public function testIdentifiesGPTBotUA(): void
    {
        $result = $this->service->verify(
            '192.168.1.1',
            'GPTBot/1.0',
        );

        $this->assertTrue($result['is_bot']);
        $this->assertEquals('gptbot', $result['bot_id']);
        $this->assertEquals('GPTBot (OpenAI)', $result['bot_name']);
        $this->assertEquals('ai', $result['category']);
    }

    public function testIdentifiesClaudeBotUA(): void
    {
        $result = $this->service->verify(
            '192.168.1.1',
            'ClaudeBot/1.0',
        );

        $this->assertTrue($result['is_bot']);
        $this->assertEquals('claudebot', $result['bot_id']);
        $this->assertEquals('ClaudeBot (Anthropic)', $result['bot_name']);
        $this->assertEquals('ai', $result['category']);
    }

    public function testIdentifiesNonBot(): void
    {
        $result = $this->service->verify(
            '192.168.1.1',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
        );

        $this->assertFalse($result['is_bot']);
        $this->assertNull($result['bot_id']);
        $this->assertNull($result['bot_name']);
        $this->assertNull($result['category']);
    }

    public function testIdentifiesAhrefsBotUA(): void
    {
        $result = $this->service->verify(
            '54.36.148.1', // Ahrefs IP range
            'AhrefsBot/7.0',
        );

        $this->assertTrue($result['is_bot']);
        $this->assertEquals('ahrefsbot', $result['bot_id']);
        $this->assertEquals('AhrefsBot', $result['bot_name']);
        $this->assertEquals('seo', $result['category']);
    }

    public function testIdentifiesSemrushBotUA(): void
    {
        $result = $this->service->verify(
            '192.168.1.1',
            'SemrushBot/7~bl',
        );

        $this->assertTrue($result['is_bot']);
        $this->assertEquals('semrushbot', $result['bot_id']);
        $this->assertEquals('SemrushBot', $result['bot_name']);
        $this->assertEquals('seo', $result['category']);
    }

    public function testIdentifiesUptimeRobotByIP(): void
    {
        $result = $this->service->verify(
            '69.162.124.226', // UptimeRobot IP range
            'UptimeRobot/2.0',
        );

        $this->assertTrue($result['is_bot']);
        $this->assertEquals('uptimerobot', $result['bot_id']);
        $this->assertEquals('UptimeRobot', $result['bot_name']);
        $this->assertEquals('monitoring', $result['category']);
        $this->assertFalse($result['respect_robots']); // UptimeRobot ignores robots.txt
    }

    public function testIdentifiesPingdomUA(): void
    {
        $result = $this->service->verify(
            '192.168.1.1',
            'Pingdom.com_bot_version_1.4_(http://www.pingdom.com/)',
        );

        $this->assertTrue($result['is_bot']);
        $this->assertEquals('pingdom', $result['bot_id']);
        $this->assertEquals('Pingdom', $result['bot_name']);
        $this->assertEquals('monitoring', $result['category']);
    }

    public function testGetSupportedBots(): void
    {
        $bots = $this->service->getSupportedBots();

        $this->assertIsArray($bots);
        $this->assertGreaterThan(10, count($bots));

        // Check some expected bots
        $this->assertArrayHasKey('googlebot', $bots);
        $this->assertArrayHasKey('bingbot', $bots);
        $this->assertArrayHasKey('facebookbot', $bots);
        $this->assertArrayHasKey('gptbot', $bots);
    }

    public function testGetBotsByCategory(): void
    {
        $searchBots = $this->service->getBotsByCategory('search_engine');
        $aiBots = $this->service->getBotsByCategory('ai');

        $this->assertContains('Googlebot', $searchBots);
        $this->assertContains('Bingbot', $searchBots);

        $this->assertContains('GPTBot (OpenAI)', $aiBots);
        $this->assertContains('ClaudeBot (Anthropic)', $aiBots);
    }

    public function testIsClaimedBot(): void
    {
        $this->assertTrue($this->service->isClaimedBot('Googlebot/2.1'));
        $this->assertTrue($this->service->isClaimedBot('bingbot/2.0'));
        $this->assertTrue($this->service->isClaimedBot('GPTBot/1.0'));
        $this->assertFalse($this->service->isClaimedBot('Mozilla/5.0 Chrome/120.0'));
    }

    public function testIsKnownBotIP(): void
    {
        // Facebook IP
        $result = $this->service->isKnownBotIP('69.171.224.1');
        $this->assertIsArray($result);
        $this->assertEquals('facebookbot', $result['bot_id']);

        // Twitter IP
        $result = $this->service->isKnownBotIP('199.16.156.1');
        $this->assertIsArray($result);
        $this->assertEquals('twitterbot', $result['bot_id']);

        // Unknown IP
        $result = $this->service->isKnownBotIP('192.168.1.1');
        $this->assertNull($result);
    }

    public function testEmptyUserAgent(): void
    {
        $result = $this->service->verify('192.168.1.1', '');

        $this->assertFalse($result['is_bot']);
    }

    public function testIdentifiesYandexBotUA(): void
    {
        $result = $this->service->verify(
            '192.168.1.1',
            'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
        );

        $this->assertTrue($result['is_bot']);
        $this->assertEquals('yandexbot', $result['bot_id']);
        $this->assertEquals('YandexBot', $result['bot_name']);
        $this->assertEquals('search_engine', $result['category']);
    }

    public function testIdentifiesBaiduspiderUA(): void
    {
        $result = $this->service->verify(
            '192.168.1.1',
            'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
        );

        $this->assertTrue($result['is_bot']);
        $this->assertEquals('baiduspider', $result['bot_id']);
        $this->assertEquals('Baiduspider', $result['bot_name']);
        $this->assertEquals('search_engine', $result['category']);
    }

    public function testIdentifiesSlackbotUA(): void
    {
        $result = $this->service->verify(
            '192.168.1.1',
            'Slackbot 1.0 (+https://api.slack.com/robots)',
        );

        $this->assertTrue($result['is_bot']);
        $this->assertEquals('slackbot', $result['bot_id']);
        $this->assertEquals('Slackbot', $result['bot_name']);
        $this->assertEquals('messaging', $result['category']);
    }

    public function testIdentifiesTelegramBotByIP(): void
    {
        $result = $this->service->verify(
            '91.108.4.1', // Telegram IP range
            'TelegramBot/1.0',
        );

        $this->assertTrue($result['is_bot']);
        $this->assertEquals('telegrambot', $result['bot_id']);
        $this->assertEquals('TelegramBot', $result['bot_name']);
        $this->assertEquals('messaging', $result['category']);
        $this->assertTrue($result['is_verified']);
    }

    public function testClearCache(): void
    {
        // Make a request to populate cache
        $this->service->verify('192.168.1.1', 'Googlebot/2.1');

        // Clear cache
        $this->service->clearCache();

        // Should still work
        $result = $this->service->verify('192.168.1.1', 'Googlebot/2.1');
        $this->assertTrue($result['is_bot']);
    }

    public function testRespectRobotsProperty(): void
    {
        // Search engines respect robots.txt
        $google = $this->service->verify('192.168.1.1', 'Googlebot/2.1');
        $this->assertTrue($google['respect_robots']);

        // UptimeRobot does NOT respect robots.txt
        $uptime = $this->service->verify('69.162.124.226', 'UptimeRobot/2.0');
        $this->assertFalse($uptime['respect_robots']);
    }
}
