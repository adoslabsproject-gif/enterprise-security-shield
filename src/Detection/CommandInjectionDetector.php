<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Detection;

/**
 * Command Injection Detector.
 *
 * Detects OS command injection attempts in user input.
 * Uses tokenization and pattern analysis, not just regex.
 *
 * DETECTS:
 * - Shell metacharacters (;, |, &, `, $())
 * - Command chaining (&&, ||)
 * - Command substitution (backticks, $())
 * - Newline injection
 * - Null byte injection
 * - Environment variable access
 * - Common dangerous commands (wget, curl, nc, bash, etc.)
 *
 * @version 1.0.0
 */
final class CommandInjectionDetector
{
    public const RISK_NONE = 'NONE';

    public const RISK_LOW = 'LOW';

    public const RISK_MEDIUM = 'MEDIUM';

    public const RISK_HIGH = 'HIGH';

    public const RISK_CRITICAL = 'CRITICAL';

    /**
     * Shell metacharacters that can be used for injection.
     */
    private const SHELL_METACHARACTERS = [
        ';' => 0.70,   // Command separator
        '|' => 0.75,   // Pipe
        '&' => 0.65,   // Background / AND
        '`' => 0.90,   // Command substitution
        '$' => 0.60,   // Variable / Command substitution
        '>' => 0.50,   // Output redirection
        '<' => 0.50,   // Input redirection
        "\n" => 0.80,  // Newline injection
        "\r" => 0.70,  // Carriage return
        "\x00" => 0.95, // Null byte
    ];

    /**
     * Command chaining operators.
     */
    private const CHAINING_OPERATORS = [
        '&&' => 0.85,  // AND
        '||' => 0.85,  // OR
        ';;' => 0.80,  // Double semicolon
        '|&' => 0.85,  // Pipe stderr
        '&|' => 0.80,
    ];

    /**
     * Command substitution patterns.
     */
    private const SUBSTITUTION_PATTERNS = [
        '/`[^`]+`/' => 0.95,           // Backtick substitution
        '/\$\([^)]+\)/' => 0.95,       // $() substitution
        '/\$\{[^}]+\}/' => 0.85,       // ${} variable expansion
        '/\$\w+/' => 0.60,             // $VAR
    ];

    /**
     * Dangerous commands (Linux/Unix).
     */
    private const DANGEROUS_COMMANDS = [
        // Network tools
        'wget' => 0.85,
        'curl' => 0.75,
        'nc' => 0.95,
        'netcat' => 0.95,
        'ncat' => 0.95,
        'telnet' => 0.80,
        'ssh' => 0.70,
        'scp' => 0.75,
        'ftp' => 0.70,
        'tftp' => 0.80,
        'rsync' => 0.70,

        // Shells
        'bash' => 0.85,
        'sh' => 0.80,
        'zsh' => 0.85,
        'csh' => 0.85,
        'ksh' => 0.85,
        'dash' => 0.85,
        'fish' => 0.80,
        'tcsh' => 0.85,

        // Code execution
        'python' => 0.70,
        'python3' => 0.70,
        'perl' => 0.75,
        'ruby' => 0.70,
        'php' => 0.80,
        'node' => 0.70,
        'lua' => 0.70,

        // System commands
        'eval' => 0.95,
        'exec' => 0.90,
        'source' => 0.80,

        // File operations
        'cat' => 0.50,
        'head' => 0.45,
        'tail' => 0.45,
        'less' => 0.45,
        'more' => 0.45,
        'vi' => 0.50,
        'vim' => 0.50,
        'nano' => 0.50,
        'rm' => 0.85,
        'rmdir' => 0.75,
        'mv' => 0.60,
        'cp' => 0.55,
        'chmod' => 0.80,
        'chown' => 0.80,
        'chgrp' => 0.75,
        'ln' => 0.60,
        'dd' => 0.85,

        // Process management
        'kill' => 0.75,
        'killall' => 0.80,
        'pkill' => 0.80,
        'ps' => 0.40,
        'top' => 0.35,
        'htop' => 0.35,
        'nohup' => 0.75,

        // User management
        'useradd' => 0.90,
        'userdel' => 0.90,
        'usermod' => 0.85,
        'passwd' => 0.85,
        'su' => 0.80,
        'sudo' => 0.85,

        // System info
        'uname' => 0.50,
        'id' => 0.55,
        'whoami' => 0.60,
        'hostname' => 0.50,
        'ifconfig' => 0.55,
        'ip' => 0.50,
        'netstat' => 0.55,
        'ss' => 0.50,
        'env' => 0.60,
        'printenv' => 0.60,

        // Dangerous utilities
        'xargs' => 0.70,
        'find' => 0.55,
        'locate' => 0.50,
        'grep' => 0.40,
        'awk' => 0.65,
        'sed' => 0.60,
        'cut' => 0.40,
        'sort' => 0.35,
        'uniq' => 0.35,
        'tr' => 0.50,
        'base64' => 0.70,
        'xxd' => 0.65,
        'od' => 0.55,

        // Compression
        'tar' => 0.60,
        'gzip' => 0.55,
        'gunzip' => 0.55,
        'zip' => 0.55,
        'unzip' => 0.55,

        // Cron
        'crontab' => 0.85,
        'at' => 0.75,
    ];

    /**
     * Windows dangerous commands.
     */
    private const WINDOWS_COMMANDS = [
        'cmd' => 0.85,
        'cmd.exe' => 0.85,
        'powershell' => 0.90,
        'powershell.exe' => 0.90,
        'pwsh' => 0.90,
        'wscript' => 0.85,
        'cscript' => 0.85,
        'mshta' => 0.90,
        'regsvr32' => 0.85,
        'rundll32' => 0.85,
        'certutil' => 0.80,
        'bitsadmin' => 0.80,
        'net' => 0.70,
        'net.exe' => 0.70,
        'netsh' => 0.75,
        'sc' => 0.75,
        'taskkill' => 0.70,
        'tasklist' => 0.50,
        'reg' => 0.75,
        'icacls' => 0.70,
        'takeown' => 0.75,
        'attrib' => 0.60,
        'copy' => 0.55,
        'xcopy' => 0.60,
        'del' => 0.75,
        'erase' => 0.75,
        'type' => 0.45,
        'more' => 0.40,
        'echo' => 0.40,
        'set' => 0.50,
        'setx' => 0.60,
        'wmic' => 0.80,
        'schtasks' => 0.80,
    ];

    private float $threshold;

    public function __construct(float $threshold = 0.5)
    {
        $this->threshold = $threshold;
    }

    /**
     * Detect command injection.
     *
     * @param string $input User input to analyze
     *
     * @return array{
     *     detected: bool,
     *     confidence: float,
     *     risk_level: string,
     *     evidence: array<string>,
     *     dangerous_patterns: array<string>,
     *     commands_found: array<string>
     * }
     */
    public function detect(string $input): array
    {
        $evidence = [];
        $patterns = [];
        $commands = [];
        $maxConfidence = 0.0;

        // Decode input
        $decoded = $this->decodeInput($input);

        // Check shell metacharacters
        foreach (self::SHELL_METACHARACTERS as $char => $confidence) {
            if (str_contains($decoded, $char)) {
                $maxConfidence = max($maxConfidence, $confidence);
                $charName = $this->getCharName($char);
                $evidence[] = "Shell metacharacter found: {$charName}";
                $patterns[] = $charName;
            }
        }

        // Check chaining operators
        foreach (self::CHAINING_OPERATORS as $op => $confidence) {
            if (str_contains($decoded, $op)) {
                $maxConfidence = max($maxConfidence, $confidence);
                $evidence[] = "Command chaining operator: {$op}";
                $patterns[] = $op;
            }
        }

        // Check substitution patterns
        foreach (self::SUBSTITUTION_PATTERNS as $pattern => $confidence) {
            if (preg_match($pattern, $decoded, $matches)) {
                $maxConfidence = max($maxConfidence, $confidence);
                $evidence[] = 'Command substitution: ' . substr($matches[0], 0, 30);
                $patterns[] = 'substitution';
            }
        }

        // Check dangerous commands
        $decodedLower = strtolower($decoded);
        $allCommands = array_merge(self::DANGEROUS_COMMANDS, self::WINDOWS_COMMANDS);

        foreach ($allCommands as $cmd => $confidence) {
            // Check for command at word boundary
            if (preg_match('/(?:^|[\s;|&`$(\[{])' . preg_quote($cmd, '/') . '(?:$|[\s;|&`$)\]}]|\.exe)/i', $decoded)) {
                $maxConfidence = max($maxConfidence, $confidence);
                $evidence[] = "Dangerous command: {$cmd}";
                $commands[] = $cmd;
            }
        }

        // Check for redirection with sensitive files
        if (preg_match('/[<>]\s*[\/"\']*(?:\/etc\/passwd|\/etc\/shadow|\.htaccess|web\.config|\.env)/i', $decoded)) {
            $maxConfidence = max($maxConfidence, 0.95);
            $evidence[] = 'Redirection to/from sensitive file';
            $patterns[] = 'sensitive_file_redirect';
        }

        // Check for /dev/tcp (bash reverse shell)
        if (preg_match('/\/dev\/tcp\//i', $decoded)) {
            $maxConfidence = 0.99;
            $evidence[] = 'Bash /dev/tcp (reverse shell pattern)';
            $patterns[] = 'dev_tcp';
        }

        // Check for base64 decode piped to shell
        if (preg_match('/base64\s+(-d|--decode).*\|\s*(bash|sh|zsh)/i', $decoded)) {
            $maxConfidence = 0.98;
            $evidence[] = 'Base64 decode piped to shell';
            $patterns[] = 'b64_shell';
        }

        // Determine if detected
        $detected = $maxConfidence >= $this->threshold;

        // Determine risk level
        $riskLevel = match (true) {
            $maxConfidence >= 0.9 => self::RISK_CRITICAL,
            $maxConfidence >= 0.7 => self::RISK_HIGH,
            $maxConfidence >= 0.5 => self::RISK_MEDIUM,
            $maxConfidence >= 0.3 => self::RISK_LOW,
            default => self::RISK_NONE,
        };

        return [
            'detected' => $detected,
            'confidence' => round($maxConfidence * 100, 2),
            'risk_level' => $riskLevel,
            'evidence' => array_unique($evidence),
            'dangerous_patterns' => array_unique($patterns),
            'commands_found' => array_unique($commands),
        ];
    }

    /**
     * Quick check.
     */
    public function isInjection(string $input): bool
    {
        return $this->detect($input)['detected'];
    }

    /**
     * Decode input.
     */
    private function decodeInput(string $input): string
    {
        $decoded = $input;

        // URL decode
        for ($i = 0; $i < 3; $i++) {
            $newDecoded = urldecode($decoded);
            if ($newDecoded === $decoded) {
                break;
            }
            $decoded = $newDecoded;
        }

        // HTML entities
        $decoded = html_entity_decode($decoded, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        // Unicode escapes
        $decoded = preg_replace_callback(
            '/\\\\u([0-9a-fA-F]{4})/',
            fn ($m) => mb_chr((int) hexdec($m[1])),
            $decoded,
        ) ?? $decoded;

        // Hex escapes (\xNN)
        $decoded = preg_replace_callback(
            '/\\\\x([0-9a-fA-F]{2})/',
            fn ($m) => chr((int) hexdec($m[1])),
            $decoded,
        ) ?? $decoded;

        // Octal escapes (\NNN)
        $decoded = preg_replace_callback(
            '/\\\\([0-7]{1,3})/',
            fn ($m) => chr((int) octdec($m[1])),
            $decoded,
        ) ?? $decoded;

        return $decoded;
    }

    /**
     * Get readable character name.
     */
    private function getCharName(string $char): string
    {
        return match ($char) {
            ';' => 'semicolon',
            '|' => 'pipe',
            '&' => 'ampersand',
            '`' => 'backtick',
            '$' => 'dollar',
            '>' => 'redirect_out',
            '<' => 'redirect_in',
            "\n" => 'newline',
            "\r" => 'carriage_return',
            "\x00" => 'null_byte',
            default => 'char_' . ord($char),
        };
    }

    /**
     * Set threshold.
     */
    public function setThreshold(float $threshold): self
    {
        $this->threshold = max(0.0, min(1.0, $threshold));

        return $this;
    }
}
