<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Tests\Unit\Privacy;

use AdosLabs\EnterpriseSecurityShield\Privacy\GDPRCompliance;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\DataProvider;

class GDPRComplianceTest extends TestCase
{
    #[Test]
    public function maskIPv4SingleOctet(): void
    {
        $gdpr = new GDPRCompliance(['method' => 'mask', 'octets' => 1]);

        $this->assertSame('192.168.1.0', $gdpr->anonymizeIP('192.168.1.100'));
        $this->assertSame('10.0.0.0', $gdpr->anonymizeIP('10.0.0.1'));
        $this->assertSame('255.255.255.0', $gdpr->anonymizeIP('255.255.255.255'));
    }

    #[Test]
    public function maskIPv4TwoOctets(): void
    {
        $gdpr = new GDPRCompliance(['method' => 'mask', 'octets' => 2]);

        $this->assertSame('192.168.0.0', $gdpr->anonymizeIP('192.168.1.100'));
        $this->assertSame('10.0.0.0', $gdpr->anonymizeIP('10.0.0.1'));
    }

    #[Test]
    public function maskIPv4ThreeOctets(): void
    {
        $gdpr = new GDPRCompliance(['method' => 'mask', 'octets' => 3]);

        $this->assertSame('192.0.0.0', $gdpr->anonymizeIP('192.168.1.100'));
        $this->assertSame('10.0.0.0', $gdpr->anonymizeIP('10.0.0.1'));
    }

    #[Test]
    public function truncateIPv4(): void
    {
        $gdpr = new GDPRCompliance(['method' => 'truncate', 'octets' => 1]);

        $this->assertSame('192.168.1.x', $gdpr->anonymizeIP('192.168.1.100'));
    }

    #[Test]
    public function truncateIPv4TwoOctets(): void
    {
        $gdpr = new GDPRCompliance(['method' => 'truncate', 'octets' => 2]);

        $this->assertSame('192.168.x.x', $gdpr->anonymizeIP('192.168.1.100'));
    }

    #[Test]
    public function hashIPProducesDifferentResultsForDifferentIPs(): void
    {
        $gdpr = new GDPRCompliance(['method' => 'hash']);

        $hash1 = $gdpr->anonymizeIP('192.168.1.1');
        $hash2 = $gdpr->anonymizeIP('192.168.1.2');

        $this->assertNotSame($hash1, $hash2);
        $this->assertStringStartsWith('0.', $hash1);
        $this->assertStringStartsWith('0.', $hash2);
    }

    #[Test]
    public function hashIPIsDeterministicWithinSameDay(): void
    {
        $gdpr = new GDPRCompliance(['method' => 'hash']);

        $hash1 = $gdpr->anonymizeIP('192.168.1.1');
        $hash2 = $gdpr->anonymizeIP('192.168.1.1');

        $this->assertSame($hash1, $hash2);
    }

    #[Test]
    public function tokenizeAndDetokenize(): void
    {
        $gdpr = new GDPRCompliance([
            'method' => 'tokenize',
            'tokenization_key' => 'test_secret_key_12345',
        ]);

        $ip = '192.168.1.100';
        $token = $gdpr->anonymizeIP($ip);

        $this->assertStringStartsWith('TOKEN:', $token);

        $recovered = $gdpr->detokenizeIP($token);
        $this->assertSame($ip, $recovered);
    }

    #[Test]
    public function detokenizeFailsWithWrongKey(): void
    {
        $gdpr1 = new GDPRCompliance([
            'method' => 'tokenize',
            'tokenization_key' => 'key_1',
        ]);
        $gdpr2 = new GDPRCompliance([
            'method' => 'tokenize',
            'tokenization_key' => 'key_2',
        ]);

        $token = $gdpr1->anonymizeIP('192.168.1.100');
        $this->assertNull($gdpr2->detokenizeIP($token));
    }

    #[Test]
    public function detokenizeFailsForNonToken(): void
    {
        $gdpr = new GDPRCompliance(['tokenization_key' => 'key']);

        $this->assertNull($gdpr->detokenizeIP('192.168.1.0'));
        $this->assertNull($gdpr->detokenizeIP('invalid'));
    }

    #[Test]
    public function invalidIPReturnsPlaceholder(): void
    {
        $gdpr = new GDPRCompliance();

        $this->assertSame('0.0.0.0', $gdpr->anonymizeIP('not-an-ip'));
        $this->assertSame('0.0.0.0', $gdpr->anonymizeIP(''));
        $this->assertSame('0.0.0.0', $gdpr->anonymizeIP('999.999.999.999'));
    }

    #[Test]
    public function maskIPv6(): void
    {
        $gdpr = new GDPRCompliance(['method' => 'mask', 'octets' => 1]);

        $result = $gdpr->anonymizeIP('2001:0db8:85a3:0000:0000:8a2e:0370:7334');

        // Should mask the last groups
        $this->assertNotSame($result, '2001:0db8:85a3:0000:0000:8a2e:0370:7334');
        $this->assertNotSame($result, '::');
    }

    #[Test]
    public function anonymizeLogEntry(): void
    {
        $gdpr = new GDPRCompliance(['method' => 'mask', 'octets' => 1]);

        $entry = [
            'ip' => '192.168.1.100',
            'client_ip' => '10.0.0.50',
            'message' => 'Test log',
            'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
            'referer' => 'https://example.com/page?query=test',
            'cookies' => 'session=abc123',
        ];

        $anonymized = $gdpr->anonymizeLogEntry($entry);

        $this->assertSame('192.168.1.0', $anonymized['ip']);
        $this->assertSame('10.0.0.0', $anonymized['client_ip']);
        $this->assertSame('Test log', $anonymized['message']);
        $this->assertSame('Chrome/Windows', $anonymized['user_agent']);
        $this->assertSame('example.com', $anonymized['referer']);
        $this->assertSame('[REDACTED]', $anonymized['cookies']);
    }

    #[Test]
    public function retentionCalculations(): void
    {
        $gdpr = new GDPRCompliance(['retention_days' => 30]);

        $now = time();
        $expiry = $gdpr->getRetentionExpiry();

        $this->assertGreaterThan($now, $expiry);
        $this->assertLessThanOrEqual($now + (31 * 86400), $expiry);

        // Created 31 days ago should be deleted
        $this->assertTrue($gdpr->shouldDelete($now - (31 * 86400)));

        // Created 29 days ago should NOT be deleted
        $this->assertFalse($gdpr->shouldDelete($now - (29 * 86400)));
    }

    #[Test]
    public function prepareAccessReport(): void
    {
        $gdpr = new GDPRCompliance();

        $userData = [
            ['event' => 'login', 'timestamp' => time()],
        ];

        $report = $gdpr->prepareAccessReport($userData);

        $this->assertArrayHasKey('report_generated', $report);
        $this->assertArrayHasKey('data_categories', $report);
        $this->assertArrayHasKey('retention_period', $report);
        $this->assertArrayHasKey('data', $report);
        $this->assertArrayHasKey('your_rights', $report);
        $this->assertSame($userData, $report['data']);
    }

    #[Test]
    public function exportData(): void
    {
        $gdpr = new GDPRCompliance();

        $userData = [
            ['event' => 'login', 'ip' => '192.168.1.1'],
        ];

        $json = $gdpr->exportData($userData);

        $this->assertJson($json);

        $decoded = json_decode($json, true);
        $this->assertSame('GDPR Data Export', $decoded['format']);
        $this->assertSame('1.0', $decoded['version']);
        $this->assertSame($userData, $decoded['data']);
    }

    #[Test]
    public function strictPreset(): void
    {
        $gdpr = GDPRCompliance::strict();

        // Strict uses hash method
        $result = $gdpr->anonymizeIP('192.168.1.100');
        $this->assertStringStartsWith('0.', $result);
    }

    #[Test]
    public function balancedPreset(): void
    {
        $gdpr = GDPRCompliance::balanced();

        // Balanced uses mask with 1 octet
        $result = $gdpr->anonymizeIP('192.168.1.100');
        $this->assertSame('192.168.1.0', $result);
    }

    #[Test]
    public function legitimateInterestPreset(): void
    {
        $gdpr = GDPRCompliance::legitimateInterest('my_secret_key');

        $ip = '192.168.1.100';
        $token = $gdpr->anonymizeIP($ip);

        $this->assertStringStartsWith('TOKEN:', $token);

        $recovered = $gdpr->detokenizeIP($token);
        $this->assertSame($ip, $recovered);
    }

    #[Test]
    public function fluentConfiguration(): void
    {
        $gdpr = (new GDPRCompliance())
            ->setMethod('truncate')
            ->setOctets(2)
            ->setRetentionDays(60);

        $result = $gdpr->anonymizeIP('192.168.1.100');
        $this->assertSame('192.168.x.x', $result);
    }

    #[Test]
    public function userAgentMinimization(): void
    {
        $gdpr = new GDPRCompliance();

        // Test various user agents
        $testCases = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120' => 'Chrome/Windows',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) Safari/605' => 'Safari/Mac',
            'Mozilla/5.0 (X11; Linux x86_64) Firefox/120' => 'Firefox/Linux',
            'Googlebot/2.1 (+http://www.google.com/bot.html)' => 'Bot/Unknown',
            'curl/7.68.0' => 'Bot/Unknown',
        ];

        foreach ($testCases as $ua => $expected) {
            $entry = $gdpr->anonymizeLogEntry(['user_agent' => $ua]);
            $this->assertSame($expected, $entry['user_agent'], "Failed for: $ua");
        }
    }
}
