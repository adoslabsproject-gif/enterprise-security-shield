<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\ML;

use AdosLabs\EnterprisePSR3Logger\LoggerFacade as Logger;

/**
 * Security Log Parser.
 *
 * Parses security logs to extract attack patterns for model training.
 * Compatible with PSR-3 style security log format.
 *
 * LOG FORMAT SUPPORTED:
 * [YYYY-MM-DD HH:MM:SS] LEVEL.SEVERITY: MESSAGE {json_context}
 *
 * Example:
 * [2026-01-24 04:59:37] SECURITY.CRITICAL: ANTI-SCAN: BOT SPOOFING DETECTED {"ip":"34.126.179.187",...}
 *
 * EXTRACTED PATTERNS:
 * - Attack IPs with associated behaviors
 * - User-Agent signatures
 * - Path patterns (attack vs normal)
 * - Timing patterns
 * - Score thresholds that triggered bans
 *
 * @version 1.0.0
 */
final class LogParser
{
    /**
     * Regular expression for parsing log lines.
     */
    private const LOG_PATTERN = '/^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] (\w+)\.(\w+): (.+)$/';

    /**
     * Pattern for extracting JSON context.
     */
    private const JSON_PATTERN = '/\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}/';

    /**
     * Event categories.
     */
    private const EVENT_CATEGORIES = [
        'ANTI-SCAN' => 'scanning',
        'BOT SPOOFING' => 'bot_spoofing',
        'CSRF' => 'csrf',
        'AUTH' => 'authentication',
        'RATE_LIMIT' => 'rate_limit',
        'REQUEST_THREAT' => 'threat',
        'EARLY_BLOCK' => 'blocked',
        'ADMIN' => 'admin_activity',
    ];

    /**
     * Parsed events storage.
     *
     * @var array<array>
     */
    private array $events = [];

    /**
     * Statistics.
     */
    private array $stats = [
        'total_lines' => 0,
        'parsed_events' => 0,
        'parse_errors' => 0,
        'attack_events' => 0,
        'legitimate_events' => 0,
    ];

    /**
     * Parse a log file.
     *
     * @param string $filePath Path to log file
     *
     * @return int Number of events parsed
     */
    public function parseFile(string $filePath): int
    {
        if (!file_exists($filePath)) {
            throw new \InvalidArgumentException("Log file not found: {$filePath}");
        }

        $handle = fopen($filePath, 'r');
        if ($handle === false) {
            throw new \RuntimeException("Cannot open file: {$filePath}");
        }

        $count = 0;
        while (($line = fgets($handle)) !== false) {
            $this->stats['total_lines']++;

            $event = $this->parseLine(trim($line));
            if ($event !== null) {
                $this->events[] = $event;
                $count++;
                $this->stats['parsed_events']++;

                if ($this->isAttackEvent($event)) {
                    $this->stats['attack_events']++;
                } else {
                    $this->stats['legitimate_events']++;
                }
            }
        }

        fclose($handle);

        return $count;
    }

    /**
     * Parse multiple log files.
     *
     * @param array<string> $filePaths
     *
     * @return int Total events parsed
     */
    public function parseFiles(array $filePaths): int
    {
        $total = 0;
        foreach ($filePaths as $filePath) {
            try {
                $total += $this->parseFile($filePath);
            } catch (\Throwable $e) {
                // Log error but continue with other files
                $this->stats['parse_errors']++;
                Logger::channel('security')->warning('LogParser: Failed to parse log file', [
                    'file_path' => $filePath,
                    'error' => $e->getMessage(),
                ]);
            }
        }

        return $total;
    }

    /**
     * Parse a single log line.
     */
    public function parseLine(string $line): ?array
    {
        // Skip empty lines
        if (empty($line)) {
            return null;
        }

        // Handle EARLY_BLOCK format (different structure)
        if (str_starts_with($line, '[') && str_contains($line, 'EARLY_BLOCK:')) {
            return $this->parseEarlyBlockLine($line);
        }

        // Handle JSON-only lines
        if (str_starts_with($line, '{')) {
            return $this->parseJsonLine($line);
        }

        // Standard log format
        if (!preg_match(self::LOG_PATTERN, $line, $matches)) {
            return null;
        }

        $timestamp = $matches[1];
        $channel = $matches[2];
        $level = $matches[3];
        $message = $matches[4];

        // Extract JSON context
        $context = [];
        if (preg_match(self::JSON_PATTERN, $message, $jsonMatch)) {
            $json = json_decode($jsonMatch[0], true);
            if (is_array($json)) {
                $context = $json;
            }
            // Remove JSON from message for cleaner text
            $message = trim(str_replace($jsonMatch[0], '', $message));
        }

        // Categorize event
        $category = $this->categorizeEvent($message);

        return [
            'timestamp' => $timestamp,
            'datetime' => \DateTime::createFromFormat('Y-m-d H:i:s', $timestamp),
            'channel' => $channel,
            'level' => $level,
            'message' => $message,
            'category' => $category,
            'context' => $context,
            'ip' => $context['ip'] ?? null,
            'user_agent' => $context['user_agent'] ?? null,
            'path' => $context['path'] ?? $context['uri'] ?? null,
            'score' => $context['total_score'] ?? null,
            'reasons' => $context['reasons'] ?? [],
            'is_attack' => $this->isAttackLevel($level) || $this->isAttackCategory($category),
        ];
    }

    /**
     * Parse EARLY_BLOCK format line.
     */
    private function parseEarlyBlockLine(string $line): ?array
    {
        // Format: [2026-01-24 07:12:01] EARLY_BLOCK: Banned IP blocked before bootstrap | IP: x.x.x.x | Path: /xxx | UA: xxx
        if (!preg_match('/^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] EARLY_BLOCK: (.+)$/', $line, $matches)) {
            return null;
        }

        $timestamp = $matches[1];
        $parts = $matches[2];

        // Parse pipe-separated values
        $ip = null;
        $path = null;
        $ua = null;

        if (preg_match('/IP:\s*([^\|]+)/', $parts, $m)) {
            $ip = trim($m[1]);
        }
        if (preg_match('/Path:\s*([^\|]+)/', $parts, $m)) {
            $path = trim($m[1]);
        }
        if (preg_match('/UA:\s*(.+)$/', $parts, $m)) {
            $ua = trim($m[1]);
        }

        return [
            'timestamp' => $timestamp,
            'datetime' => \DateTime::createFromFormat('Y-m-d H:i:s', $timestamp),
            'channel' => 'SECURITY',
            'level' => 'CRITICAL',
            'message' => 'EARLY_BLOCK: Banned IP blocked before bootstrap',
            'category' => 'blocked',
            'context' => [],
            'ip' => $ip,
            'user_agent' => $ua,
            'path' => $path,
            'score' => null,
            'reasons' => ['previously_banned'],
            'is_attack' => true,
        ];
    }

    /**
     * Parse JSON-only line.
     */
    private function parseJsonLine(string $line): ?array
    {
        $data = json_decode($line, true);
        if (!is_array($data)) {
            return null;
        }

        return [
            'timestamp' => $data['timestamp'] ?? date('Y-m-d H:i:s'),
            'datetime' => isset($data['timestamp']) ? new \DateTime($data['timestamp']) : new \DateTime(),
            'channel' => 'SECURITY',
            'level' => $data['severity'] ?? 'WARNING',
            'message' => $data['event'] ?? 'Unknown event',
            'category' => 'unknown',
            'context' => $data,
            'ip' => $data['ip'] ?? null,
            'user_agent' => $data['user_agent'] ?? null,
            'path' => $data['url'] ?? $data['path'] ?? null,
            'score' => null,
            'reasons' => [],
            'is_attack' => ($data['severity'] ?? '') === 'HIGH',
        ];
    }

    /**
     * Categorize event based on message content.
     */
    private function categorizeEvent(string $message): string
    {
        foreach (self::EVENT_CATEGORIES as $keyword => $category) {
            if (str_contains(strtoupper($message), $keyword)) {
                return $category;
            }
        }

        return 'unknown';
    }

    /**
     * Check if level indicates attack.
     */
    private function isAttackLevel(string $level): bool
    {
        return in_array(strtoupper($level), ['CRITICAL', 'ERROR'], true);
    }

    /**
     * Check if category indicates attack.
     */
    private function isAttackCategory(string $category): bool
    {
        return in_array($category, ['scanning', 'bot_spoofing', 'threat', 'blocked'], true);
    }

    /**
     * Check if event is an attack.
     */
    private function isAttackEvent(array $event): bool
    {
        return $event['is_attack'] ?? false;
    }

    /**
     * Get all parsed events.
     *
     * @return array<array>
     */
    public function getEvents(): array
    {
        return $this->events;
    }

    /**
     * Get attack events only.
     *
     * @return array<array>
     */
    public function getAttackEvents(): array
    {
        return array_filter($this->events, fn ($e) => $e['is_attack']);
    }

    /**
     * Get unique attacker IPs.
     *
     * @return array<string, array> IP => attack details
     */
    public function getAttackerIPs(): array
    {
        $ips = [];
        foreach ($this->getAttackEvents() as $event) {
            $ip = $event['ip'];
            if ($ip === null) {
                continue;
            }

            if (!isset($ips[$ip])) {
                $ips[$ip] = [
                    'ip' => $ip,
                    'attack_count' => 0,
                    'categories' => [],
                    'user_agents' => [],
                    'paths' => [],
                    'first_seen' => $event['timestamp'],
                    'last_seen' => $event['timestamp'],
                    'max_score' => 0,
                ];
            }

            $ips[$ip]['attack_count']++;
            $ips[$ip]['last_seen'] = $event['timestamp'];

            if ($event['category'] && !in_array($event['category'], $ips[$ip]['categories'], true)) {
                $ips[$ip]['categories'][] = $event['category'];
            }

            if ($event['user_agent'] && !in_array($event['user_agent'], $ips[$ip]['user_agents'], true)) {
                $ips[$ip]['user_agents'][] = $event['user_agent'];
            }

            if ($event['path'] && !in_array($event['path'], $ips[$ip]['paths'], true)) {
                $ips[$ip]['paths'][] = $event['path'];
            }

            if (($event['score'] ?? 0) > $ips[$ip]['max_score']) {
                $ips[$ip]['max_score'] = $event['score'];
            }
        }

        // Sort by attack count
        uasort($ips, fn ($a, $b) => $b['attack_count'] <=> $a['attack_count']);

        return $ips;
    }

    /**
     * Get path patterns from attacks.
     *
     * @return array<string, int> Path => count
     */
    public function getAttackPaths(): array
    {
        $paths = [];
        foreach ($this->getAttackEvents() as $event) {
            $path = $event['path'];
            if ($path === null) {
                continue;
            }

            // Normalize path
            $normalized = $this->normalizePath($path);

            if (!isset($paths[$normalized])) {
                $paths[$normalized] = 0;
            }
            $paths[$normalized]++;
        }

        arsort($paths);

        return $paths;
    }

    /**
     * Get User-Agent patterns from attacks.
     *
     * @return array<string, int> UA => count
     */
    public function getAttackUserAgents(): array
    {
        $uas = [];
        foreach ($this->getAttackEvents() as $event) {
            $ua = $event['user_agent'];
            if ($ua === null) {
                continue;
            }

            // Normalize UA
            $normalized = $this->normalizeUserAgent($ua);

            if (!isset($uas[$normalized])) {
                $uas[$normalized] = 0;
            }
            $uas[$normalized]++;
        }

        arsort($uas);

        return $uas;
    }

    /**
     * Get attack timing distribution.
     *
     * @return array<int, int> Hour => count
     */
    public function getAttackHourDistribution(): array
    {
        $hours = array_fill(0, 24, 0);

        foreach ($this->getAttackEvents() as $event) {
            if ($event['datetime'] instanceof \DateTime) {
                $hour = (int) $event['datetime']->format('G');
                $hours[$hour]++;
            }
        }

        return $hours;
    }

    /**
     * Generate training data for ML model.
     *
     * @return array{
     *     attack_paths: array<string, int>,
     *     attack_uas: array<string, int>,
     *     attack_ips: array<string, array>,
     *     hour_distribution: array<int, int>,
     *     categories: array<string, int>
     * }
     */
    public function generateTrainingData(): array
    {
        // Category distribution
        $categories = [];
        foreach ($this->getAttackEvents() as $event) {
            $cat = $event['category'] ?? 'unknown';
            if (!isset($categories[$cat])) {
                $categories[$cat] = 0;
            }
            $categories[$cat]++;
        }

        return [
            'attack_paths' => $this->getAttackPaths(),
            'attack_uas' => $this->getAttackUserAgents(),
            'attack_ips' => $this->getAttackerIPs(),
            'hour_distribution' => $this->getAttackHourDistribution(),
            'categories' => $categories,
            'stats' => $this->stats,
        ];
    }

    /**
     * Get statistics.
     */
    public function getStats(): array
    {
        return $this->stats;
    }

    /**
     * Clear parsed events.
     */
    public function clear(): void
    {
        $this->events = [];
        $this->stats = [
            'total_lines' => 0,
            'parsed_events' => 0,
            'parse_errors' => 0,
            'attack_events' => 0,
            'legitimate_events' => 0,
        ];
    }

    /**
     * Normalize path for pattern matching.
     */
    private function normalizePath(string $path): string
    {
        // Remove query string
        $path = strtok($path, '?');

        // Normalize to lowercase
        $path = strtolower($path);

        // Remove trailing slashes
        $path = rtrim($path, '/');

        // Replace numbers with placeholder
        $path = preg_replace('/\d+/', '#', $path);

        // Replace UUIDs with placeholder
        $path = preg_replace('/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/i', '{uuid}', $path);

        // Replace hashes with placeholder
        $path = preg_replace('/[a-f0-9]{32,}/i', '{hash}', $path);

        return $path ?: '/';
    }

    /**
     * Normalize User-Agent for pattern matching.
     */
    private function normalizeUserAgent(string $ua): string
    {
        // Lowercase
        $ua = strtolower($ua);

        // Extract main tool/browser
        if (preg_match('/^(curl|wget|python|go-http|java|libwww-perl)/', $ua, $m)) {
            return $m[1];
        }

        if (str_contains($ua, 'hello, world')) {
            return 'gpon_exploit';
        }

        if (str_contains($ua, 'googlebot')) {
            return 'googlebot';
        }

        if (str_contains($ua, 'facebookexternalhit') || str_contains($ua, 'facebot')) {
            return 'facebook_bot';
        }

        if (str_contains($ua, 'censys')) {
            return 'censys';
        }

        // Remove version numbers for grouping
        $ua = preg_replace('/\/[\d.]+/', '', $ua);

        // Truncate for storage
        return substr($ua, 0, 100);
    }
}
