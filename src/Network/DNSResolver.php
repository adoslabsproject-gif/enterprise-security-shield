<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Network;

use AdosLabs\EnterprisePSR3Logger\LoggerFacade as Logger;

/**
 * Enterprise DNS Resolver with Timeout Support.
 *
 * PHP's built-in DNS functions (gethostbyaddr, gethostbyname, checkdnsrr)
 * have no timeout option, which can cause request blocking under:
 * - DNS server overload
 * - Network issues
 * - Slow authoritative nameservers
 * - DDoS attacks targeting DNS infrastructure
 *
 * This resolver provides:
 * 1. Configurable timeouts for all DNS operations
 * 2. Process-based isolation (DNS lookups in child process)
 * 3. Multiple resolver strategies (native, socket, async)
 * 4. Built-in caching with TTL
 * 5. Fallback DNS servers
 * 6. Circuit breaker for failing DNS servers
 * 7. Statistics and monitoring
 *
 * STRATEGIES:
 * - Native: Uses PHP's built-in functions (no true timeout on most systems)
 * - Socket: Direct UDP socket to DNS server (true timeout)
 * - Process: Fork-based isolation (Unix only)
 *
 * @version 1.0.0
 */
final class DNSResolver
{
    /**
     * DNS query types.
     */
    public const TYPE_A = DNS_A;

    public const TYPE_AAAA = DNS_AAAA;

    public const TYPE_PTR = DNS_PTR;

    public const TYPE_MX = DNS_MX;

    public const TYPE_TXT = DNS_TXT;

    public const TYPE_NS = DNS_NS;

    public const TYPE_CNAME = DNS_CNAME;

    public const TYPE_SOA = DNS_SOA;

    /**
     * Resolver strategies.
     */
    public const STRATEGY_NATIVE = 'native';

    public const STRATEGY_SOCKET = 'socket';

    public const STRATEGY_PROCESS = 'process';

    /**
     * Default timeout in seconds.
     */
    private float $timeout = 3.0;

    /**
     * Retry count for failed lookups.
     */
    private int $retries = 2;

    /**
     * Custom DNS servers (IP addresses).
     *
     * @var array<string>
     */
    private array $nameservers = [
        '8.8.8.8',      // Google Public DNS
        '8.8.4.4',      // Google Public DNS Secondary
        '1.1.1.1',      // Cloudflare DNS
        '1.0.0.1',      // Cloudflare DNS Secondary
    ];

    /**
     * Resolver strategy.
     */
    private string $strategy = self::STRATEGY_SOCKET;

    /**
     * Local cache.
     *
     * @var array<string, array{result: mixed, expires: int}>
     */
    private array $cache = [];

    /**
     * Cache TTL in seconds.
     */
    private int $cacheTTL = 300;

    /**
     * Enable/disable caching.
     */
    private bool $cacheEnabled = true;

    /**
     * Circuit breaker state per nameserver.
     *
     * @var array<string, array{failures: int, last_failure: int, open: bool}>
     */
    private array $circuitBreaker = [];

    /**
     * Circuit breaker threshold.
     */
    private int $circuitBreakerThreshold = 5;

    /**
     * Circuit breaker recovery time in seconds.
     */
    private int $circuitBreakerRecovery = 60;

    /**
     * Statistics.
     *
     * @var array<string, int|float|string>
     */
    private array $stats = [
        'queries' => 0,
        'cache_hits' => 0,
        'cache_misses' => 0,
        'successes' => 0,
        'failures' => 0,
        'timeouts' => 0,
        'retries' => 0,
        'errors' => 0,
    ];

    public function __construct(array $config = [])
    {
        if (isset($config['timeout'])) {
            $this->timeout = (float) max(0.1, $config['timeout']);
        }
        if (isset($config['retries'])) {
            $this->retries = (int) max(0, $config['retries']);
        }
        if (isset($config['nameservers']) && is_array($config['nameservers'])) {
            $this->nameservers = $config['nameservers'];
        }
        if (isset($config['strategy'])) {
            $this->strategy = $config['strategy'];
        }
        if (isset($config['cache_ttl'])) {
            $this->cacheTTL = (int) $config['cache_ttl'];
        }
        if (isset($config['cache_enabled'])) {
            $this->cacheEnabled = (bool) $config['cache_enabled'];
        }
    }

    /**
     * Set timeout in seconds.
     */
    public function setTimeout(float $seconds): self
    {
        $this->timeout = max(0.1, $seconds);

        return $this;
    }

    /**
     * Get current timeout.
     */
    public function getTimeout(): float
    {
        return $this->timeout;
    }

    /**
     * Set custom nameservers.
     *
     * @param array<string> $servers IP addresses of DNS servers
     */
    public function setNameservers(array $servers): self
    {
        $this->nameservers = array_values(array_filter(
            $servers,
            fn (string $s): bool => filter_var($s, FILTER_VALIDATE_IP) !== false,
        ));

        return $this;
    }

    /**
     * Set resolver strategy.
     */
    public function setStrategy(string $strategy): self
    {
        if (in_array($strategy, [self::STRATEGY_NATIVE, self::STRATEGY_SOCKET, self::STRATEGY_PROCESS], true)) {
            $this->strategy = $strategy;
        }

        return $this;
    }

    /**
     * Enable/disable caching.
     */
    public function enableCache(bool $enable): self
    {
        $this->cacheEnabled = $enable;

        return $this;
    }

    /**
     * Set cache TTL.
     */
    public function setCacheTTL(int $seconds): self
    {
        $this->cacheTTL = max(1, $seconds);

        return $this;
    }

    /**
     * Resolve hostname to IP addresses (A/AAAA records).
     *
     * @return array<string>|null IP addresses or null on failure
     */
    public function resolve(string $hostname, bool $ipv6 = false): ?array
    {
        $type = $ipv6 ? self::TYPE_AAAA : self::TYPE_A;

        return $this->query($hostname, $type);
    }

    /**
     * Reverse DNS lookup (PTR record).
     *
     * @return string|null Hostname or null on failure
     */
    public function reverseLookup(string $ip): ?string
    {
        $this->stats['queries']++;

        // Check cache
        $cacheKey = "ptr:{$ip}";
        if ($this->cacheEnabled) {
            $cached = $this->getFromCache($cacheKey);
            if ($cached !== null) {
                $this->stats['cache_hits']++;

                return $cached;
            }
            $this->stats['cache_misses']++;
        }

        // Build PTR query name
        $ptrName = $this->buildPTRName($ip);
        if ($ptrName === null) {
            $this->stats['failures']++;

            return null;
        }

        // Execute query
        $result = $this->executeQuery($ptrName, self::TYPE_PTR);

        if ($result === null) {
            $this->stats['failures']++;

            return null;
        }

        // Extract hostname from result
        $hostname = null;
        if (is_array($result)) {
            foreach ($result as $record) {
                if (isset($record['target'])) {
                    $hostname = rtrim($record['target'], '.');
                    break;
                }
            }
        }

        if ($hostname !== null) {
            $this->stats['successes']++;
            if ($this->cacheEnabled) {
                $this->addToCache($cacheKey, $hostname);
            }
        } else {
            $this->stats['failures']++;
        }

        return $hostname;
    }

    /**
     * Forward DNS lookup with timeout.
     *
     * @return array<string>|null IP addresses
     */
    public function forwardLookup(string $hostname): ?array
    {
        return $this->resolve($hostname);
    }

    /**
     * Check if DNS record exists (checkdnsrr replacement).
     */
    public function checkRecord(string $hostname, int $type = self::TYPE_A): bool
    {
        $result = $this->query($hostname, $type);

        return $result !== null && count($result) > 0;
    }

    /**
     * Get MX records.
     *
     * @return array<array{host: string, priority: int}>|null
     */
    public function getMXRecords(string $domain): ?array
    {
        $records = $this->query($domain, self::TYPE_MX);
        if ($records === null) {
            return null;
        }

        $result = [];
        foreach ($records as $record) {
            if (isset($record['target'], $record['pri'])) {
                $result[] = [
                    'host' => $record['target'],
                    'priority' => $record['pri'],
                ];
            }
        }

        usort($result, fn ($a, $b) => $a['priority'] <=> $b['priority']);

        return $result;
    }

    /**
     * Get TXT records.
     *
     * @return array<string>|null
     */
    public function getTXTRecords(string $domain): ?array
    {
        $records = $this->query($domain, self::TYPE_TXT);
        if ($records === null) {
            return null;
        }

        $result = [];
        foreach ($records as $record) {
            if (isset($record['txt'])) {
                $result[] = $record['txt'];
            }
        }

        return $result;
    }

    /**
     * DNS query with type.
     *
     * @return array<mixed>|null
     */
    public function query(string $name, int $type = self::TYPE_A): ?array
    {
        $this->stats['queries']++;

        // Build cache key
        $cacheKey = "{$type}:{$name}";
        if ($this->cacheEnabled) {
            $cached = $this->getFromCache($cacheKey);
            if ($cached !== null) {
                $this->stats['cache_hits']++;

                return $cached;
            }
            $this->stats['cache_misses']++;
        }

        // Execute query
        $result = $this->executeQuery($name, $type);

        if ($result !== null) {
            $this->stats['successes']++;
            if ($this->cacheEnabled) {
                $this->addToCache($cacheKey, $result);
            }
        } else {
            $this->stats['failures']++;
        }

        return $result;
    }

    /**
     * Execute DNS query with strategy.
     *
     * @return array<mixed>|null
     */
    private function executeQuery(string $name, int $type): ?array
    {
        $attempts = 0;
        $maxAttempts = $this->retries + 1;

        while ($attempts < $maxAttempts) {
            $attempts++;

            try {
                $result = match ($this->strategy) {
                    self::STRATEGY_SOCKET => $this->queryViaSocket($name, $type),
                    self::STRATEGY_PROCESS => $this->queryViaProcess($name, $type),
                    default => $this->queryViaNative($name, $type),
                };

                if ($result !== null) {
                    return $result;
                }
            } catch (DNSTimeoutException $e) {
                $this->stats['timeouts']++;
                $this->stats['last_timeout_error'] = $e->getMessage();
                Logger::channel('api')->warning('DNS query timeout', [
                    'name' => $name,
                    'type' => $type,
                    'attempt' => $attempts,
                    'error' => $e->getMessage(),
                ]);
            } catch (\Throwable $e) {
                // Log error and continue to retry
                $this->stats['errors']++;
                $this->stats['last_error'] = $e->getMessage();
                Logger::channel('api')->error('DNS query error', [
                    'name' => $name,
                    'type' => $type,
                    'attempt' => $attempts,
                    'error' => $e->getMessage(),
                ]);
            }

            if ($attempts < $maxAttempts) {
                $this->stats['retries']++;
            }
        }

        return null;
    }

    /**
     * Native PHP DNS query (no real timeout).
     */
    private function queryViaNative(string $name, int $type): ?array
    {
        // Set alarm for Unix systems (imperfect but better than nothing)
        if (function_exists('pcntl_alarm')) {
            pcntl_alarm((int) ceil($this->timeout));
        }

        try {
            $result = @dns_get_record($name, $type);

            if (function_exists('pcntl_alarm')) {
                pcntl_alarm(0);
            }

            return $result !== false ? $result : null;
        } finally {
            if (function_exists('pcntl_alarm')) {
                pcntl_alarm(0);
            }
        }
    }

    /**
     * Query via UDP socket with real timeout.
     */
    private function queryViaSocket(string $name, int $type): ?array
    {
        $nameservers = $this->getAvailableNameservers();
        if (empty($nameservers)) {
            // All nameservers are in circuit breaker - try to recover
            $this->resetCircuitBreakers();
            $nameservers = $this->nameservers;
        }

        foreach ($nameservers as $server) {
            $result = $this->queryDNSServer($server, $name, $type);
            if ($result !== null) {
                $this->recordSuccess($server);

                return $result;
            }
            $this->recordFailure($server);
        }

        return null;
    }

    /**
     * Query specific DNS server via UDP.
     */
    private function queryDNSServer(string $server, string $name, int $type): ?array
    {
        $socket = @socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        if ($socket === false) {
            return null;
        }

        try {
            // Set socket timeout
            $timeoutSec = (int) floor($this->timeout);
            $timeoutMicro = (int) (($this->timeout - $timeoutSec) * 1000000);

            socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, [
                'sec' => $timeoutSec,
                'usec' => $timeoutMicro,
            ]);
            socket_set_option($socket, SOL_SOCKET, SO_SNDTIMEO, [
                'sec' => $timeoutSec,
                'usec' => $timeoutMicro,
            ]);

            // Build DNS query packet
            $packet = $this->buildDNSPacket($name, $type);

            // Send query
            $sent = @socket_sendto($socket, $packet, strlen($packet), 0, $server, 53);
            if ($sent === false) {
                return null;
            }

            // Receive response
            $response = '';
            $from = '';
            $port = 0;
            $received = @socket_recvfrom($socket, $response, 65535, 0, $from, $port);

            if ($received === false || $received < 12) {
                throw new DNSTimeoutException("DNS query timeout for {$name}");
            }

            // Parse response
            return $this->parseDNSResponse($response, $type);

        } finally {
            @socket_close($socket);
        }
    }

    /**
     * Query via child process (Unix only, provides true isolation).
     */
    private function queryViaProcess(string $name, int $type): ?array
    {
        if (!function_exists('pcntl_fork')) {
            // Fallback to socket method
            return $this->queryViaSocket($name, $type);
        }

        // Create pipe for IPC
        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $typeMap = [
            self::TYPE_A => 'A',
            self::TYPE_AAAA => 'AAAA',
            self::TYPE_PTR => 'PTR',
            self::TYPE_MX => 'MX',
            self::TYPE_TXT => 'TXT',
            self::TYPE_NS => 'NS',
            self::TYPE_CNAME => 'CNAME',
            self::TYPE_SOA => 'SOA',
        ];
        $typeStr = $typeMap[$type] ?? 'A';

        // Use dig command with timeout
        $cmd = sprintf(
            'dig +short +time=%d +tries=1 %s %s 2>/dev/null',
            (int) ceil($this->timeout),
            escapeshellarg($typeStr),
            escapeshellarg($name),
        );

        $process = @proc_open($cmd, $descriptors, $pipes);
        if (!is_resource($process)) {
            return $this->queryViaSocket($name, $type);
        }

        try {
            fclose($pipes[0]);

            // Set stream non-blocking for timeout
            stream_set_blocking($pipes[1], false);

            $startTime = microtime(true);
            $output = '';

            while (true) {
                $elapsed = microtime(true) - $startTime;
                if ($elapsed >= $this->timeout) {
                    throw new DNSTimeoutException("DNS query timeout for {$name}");
                }

                $read = [$pipes[1]];
                $write = null;
                $except = null;
                $remaining = $this->timeout - $elapsed;

                $changed = @stream_select($read, $write, $except, (int) $remaining, (int) (($remaining - (int) $remaining) * 1000000));

                if ($changed === false) {
                    break;
                }
                if ($changed === 0) {
                    throw new DNSTimeoutException("DNS query timeout for {$name}");
                }

                $data = fread($pipes[1], 8192);
                if ($data === false || $data === '') {
                    break;
                }
                $output .= $data;
            }

            fclose($pipes[1]);
            fclose($pipes[2]);

            $exitCode = proc_close($process);

            if ($exitCode !== 0 || empty(trim($output))) {
                return null;
            }

            // Parse dig output
            $lines = array_filter(array_map('trim', explode("\n", $output)));

            $results = [];
            foreach ($lines as $line) {
                if ($type === self::TYPE_A || $type === self::TYPE_AAAA) {
                    if (filter_var($line, FILTER_VALIDATE_IP)) {
                        $results[] = ['ip' => $line, 'type' => $typeStr];
                    }
                } elseif ($type === self::TYPE_PTR) {
                    $results[] = ['target' => $line];
                } elseif ($type === self::TYPE_MX) {
                    if (preg_match('/^(\d+)\s+(.+)$/', $line, $m)) {
                        $results[] = ['pri' => (int) $m[1], 'target' => $m[2]];
                    }
                } elseif ($type === self::TYPE_TXT) {
                    $results[] = ['txt' => trim($line, '"')];
                } else {
                    $results[] = ['data' => $line];
                }
            }

            return $results ?: null;

        } catch (\Throwable $e) {
            @fclose($pipes[1] ?? null);
            @fclose($pipes[2] ?? null);
            @proc_terminate($process);
            @proc_close($process);

            throw $e;
        }
    }

    /**
     * Build DNS query packet.
     */
    private function buildDNSPacket(string $name, int $type): string
    {
        // Transaction ID (random)
        $id = random_int(0, 65535);

        // Flags: Standard query, recursion desired
        $flags = 0x0100;

        // Header
        $header = pack('nnnnnn', $id, $flags, 1, 0, 0, 0);

        // Question section
        $question = '';
        foreach (explode('.', $name) as $part) {
            $question .= chr(strlen($part)) . $part;
        }
        $question .= "\x00"; // Null terminator

        // Map internal type to DNS wire format
        $qtype = match ($type) {
            self::TYPE_A => 1,
            self::TYPE_AAAA => 28,
            self::TYPE_PTR => 12,
            self::TYPE_MX => 15,
            self::TYPE_TXT => 16,
            self::TYPE_NS => 2,
            self::TYPE_CNAME => 5,
            self::TYPE_SOA => 6,
            default => 1,
        };

        $question .= pack('nn', $qtype, 1); // QTYPE, QCLASS (IN)

        return $header . $question;
    }

    /**
     * Parse DNS response packet.
     *
     * @return array<mixed>|null
     */
    private function parseDNSResponse(string $response, int $type): ?array
    {
        if (strlen($response) < 12) {
            return null;
        }

        $header = unpack('nid/nflags/nqdcount/nancount/nnscount/narcount', substr($response, 0, 12));
        if ($header === false) {
            return null;
        }

        // Check for errors (RCODE in lower 4 bits of flags)
        $rcode = $header['flags'] & 0x000F;
        if ($rcode !== 0) {
            return null;
        }

        $ancount = $header['ancount'];
        if ($ancount === 0) {
            return [];
        }

        // Skip header and question section
        $offset = 12;
        for ($i = 0; $i < $header['qdcount']; $i++) {
            while ($offset < strlen($response) && ord($response[$offset]) !== 0) {
                $len = ord($response[$offset]);
                if (($len & 0xC0) === 0xC0) {
                    $offset += 2;
                    break;
                }
                $offset += $len + 1;
            }
            if ($offset < strlen($response) && ord($response[$offset]) === 0) {
                $offset++;
            }
            $offset += 4; // QTYPE + QCLASS
        }

        // Parse answers
        $results = [];
        for ($i = 0; $i < $ancount && $offset < strlen($response); $i++) {
            $record = $this->parseResourceRecord($response, $offset, $type);
            if ($record !== null) {
                $results[] = $record;
            }
        }

        return $results ?: null;
    }

    /**
     * Parse single resource record.
     */
    private function parseResourceRecord(string $response, int &$offset, int $expectedType): ?array
    {
        // Skip name (may be compressed)
        $offset = $this->skipName($response, $offset);
        if ($offset === false || $offset + 10 > strlen($response)) {
            return null;
        }

        $data = unpack('ntype/nclass/Nttl/nrdlength', substr($response, $offset, 10));
        if ($data === false) {
            return null;
        }
        $offset += 10;

        $rdlength = $data['rdlength'];
        if ($offset + $rdlength > strlen($response)) {
            return null;
        }

        $rdata = substr($response, $offset, $rdlength);
        $offset += $rdlength;

        // Parse based on type
        $result = match ($data['type']) {
            1 => ['ip' => inet_ntop($rdata), 'type' => 'A'],
            28 => ['ip' => inet_ntop($rdata), 'type' => 'AAAA'],
            12 => ['target' => $this->parseName($response, $offset - $rdlength)],
            15 => $this->parseMXRecord($response, $offset - $rdlength, $rdlength),
            16 => ['txt' => $this->parseTXTRecord($rdata)],
            5 => ['target' => $this->parseName($response, $offset - $rdlength)],
            default => null,
        };

        return $result;
    }

    /**
     * Skip DNS name (handling compression).
     */
    private function skipName(string $response, int $offset): int|false
    {
        while ($offset < strlen($response)) {
            $len = ord($response[$offset]);
            if ($len === 0) {
                return $offset + 1;
            }
            if (($len & 0xC0) === 0xC0) {
                return $offset + 2;
            }
            $offset += $len + 1;
        }

        return false;
    }

    /**
     * Parse DNS name from response.
     */
    private function parseName(string $response, int $offset): string
    {
        $name = '';
        $jumped = false;
        $maxJumps = 10;
        $jumps = 0;

        while ($offset < strlen($response)) {
            $len = ord($response[$offset]);

            if ($len === 0) {
                break;
            }

            if (($len & 0xC0) === 0xC0) {
                if ($jumps++ > $maxJumps) {
                    break;
                }
                $pointer = (($len & 0x3F) << 8) | ord($response[$offset + 1]);
                $offset = $pointer;
                $jumped = true;
                continue;
            }

            $offset++;
            $name .= substr($response, $offset, $len) . '.';
            $offset += $len;
        }

        return rtrim($name, '.');
    }

    /**
     * Parse MX record.
     */
    private function parseMXRecord(string $response, int $offset, int $rdlength): array
    {
        $priority = unpack('n', substr($response, $offset, 2));
        $host = $this->parseName($response, $offset + 2);

        return [
            'pri' => $priority[1] ?? 0,
            'target' => $host,
        ];
    }

    /**
     * Parse TXT record.
     */
    private function parseTXTRecord(string $rdata): string
    {
        $txt = '';
        $offset = 0;

        while ($offset < strlen($rdata)) {
            $len = ord($rdata[$offset]);
            $txt .= substr($rdata, $offset + 1, $len);
            $offset += $len + 1;
        }

        return $txt;
    }

    /**
     * Build PTR query name from IP.
     */
    private function buildPTRName(string $ip): ?string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $octets = array_reverse(explode('.', $ip));

            return implode('.', $octets) . '.in-addr.arpa';
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $expanded = inet_pton($ip);
            if ($expanded === false) {
                return null;
            }
            $hex = bin2hex($expanded);
            $chars = str_split($hex);

            return implode('.', array_reverse($chars)) . '.ip6.arpa';
        }

        return null;
    }

    /**
     * Get available nameservers (not in circuit breaker).
     *
     * @return array<string>
     */
    private function getAvailableNameservers(): array
    {
        $available = [];
        $now = time();

        foreach ($this->nameservers as $server) {
            if (!isset($this->circuitBreaker[$server])) {
                $available[] = $server;
                continue;
            }

            $state = $this->circuitBreaker[$server];
            if (!$state['open']) {
                $available[] = $server;
                continue;
            }

            // Check if recovery time has passed
            if ($now - $state['last_failure'] >= $this->circuitBreakerRecovery) {
                $this->circuitBreaker[$server]['open'] = false;
                $this->circuitBreaker[$server]['failures'] = 0;
                $available[] = $server;
            }
        }

        return $available;
    }

    /**
     * Record success for nameserver.
     */
    private function recordSuccess(string $server): void
    {
        if (isset($this->circuitBreaker[$server])) {
            $this->circuitBreaker[$server]['failures'] = 0;
            $this->circuitBreaker[$server]['open'] = false;
        }
    }

    /**
     * Record failure for nameserver.
     *
     * NOTE: In async environments (Swoole/ReactPHP), concurrent access to
     * $this->circuitBreaker is possible. This implementation is idempotent
     * and tolerates race conditions - worst case is slightly delayed circuit
     * opening, which is acceptable for DNS failover.
     *
     * For production high-concurrency use, consider using Redis for atomic
     * circuit breaker state management.
     */
    private function recordFailure(string $server): void
    {
        // Initialize if needed (idempotent)
        if (!isset($this->circuitBreaker[$server])) {
            $this->circuitBreaker[$server] = [
                'failures' => 0,
                'last_failure' => 0,
                'open' => false,
            ];
        }

        // Increment failures and update timestamp
        // Note: In async context, concurrent increments may result in
        // slight under-counting, but circuit will still open correctly
        $failures = $this->circuitBreaker[$server]['failures'] + 1;
        $this->circuitBreaker[$server]['failures'] = $failures;
        $this->circuitBreaker[$server]['last_failure'] = time();

        // Open circuit if threshold reached
        if ($failures >= $this->circuitBreakerThreshold) {
            $this->circuitBreaker[$server]['open'] = true;
        }
    }

    /**
     * Reset all circuit breakers.
     */
    private function resetCircuitBreakers(): void
    {
        $this->circuitBreaker = [];
    }

    /**
     * Get from cache.
     */
    private function getFromCache(string $key): mixed
    {
        if (!isset($this->cache[$key])) {
            return null;
        }

        $entry = $this->cache[$key];
        if ($entry['expires'] < time()) {
            unset($this->cache[$key]);

            return null;
        }

        return $entry['result'];
    }

    /**
     * Add to cache with TTL-based cleanup.
     *
     * Performs periodic cleanup of expired entries to prevent memory leaks
     * in long-running processes (daemons, Swoole workers, etc.).
     */
    private function addToCache(string $key, mixed $value): void
    {
        $now = time();

        $this->cache[$key] = [
            'result' => $value,
            'expires' => $now + $this->cacheTTL,
        ];

        // Periodic cleanup: every 100 inserts, remove expired entries
        static $insertCount = 0;
        $insertCount++;

        if ($insertCount >= 100) {
            $insertCount = 0;
            $this->cleanupExpiredCache($now);
        }

        // Hard limit: if cache still too large after cleanup, evict oldest
        if (count($this->cache) > 1000) {
            // Sort by expiry and keep newest 500
            uasort($this->cache, fn ($a, $b) => $a['expires'] <=> $b['expires']);
            $this->cache = array_slice($this->cache, -500, null, true);
        }
    }

    /**
     * Remove expired entries from cache.
     */
    private function cleanupExpiredCache(int $now): void
    {
        foreach ($this->cache as $key => $entry) {
            if ($entry['expires'] < $now) {
                unset($this->cache[$key]);
            }
        }
    }

    /**
     * Clear cache.
     */
    public function clearCache(): void
    {
        $this->cache = [];
    }

    /**
     * Get statistics.
     *
     * @return array<string, mixed>
     */
    public function getStatistics(): array
    {
        $total = (int) $this->stats['queries'];
        $cacheHits = (int) $this->stats['cache_hits'];
        $cacheMisses = (int) $this->stats['cache_misses'];
        $successes = (int) $this->stats['successes'];
        $timeouts = (int) $this->stats['timeouts'];

        return [
            ...$this->stats,
            'cache_hit_rate' => $total > 0
                ? round(($cacheHits / $total) * 100, 2)
                : 0,
            'success_rate' => $total > 0
                ? round(($successes / max(1, $cacheMisses)) * 100, 2)
                : 0,
            'timeout_rate' => $total > 0
                ? round(($timeouts / max(1, $cacheMisses)) * 100, 2)
                : 0,
            'circuit_breaker_status' => $this->circuitBreaker,
        ];
    }

    /**
     * Reset statistics.
     */
    public function resetStatistics(): void
    {
        $this->stats = [
            'queries' => 0,
            'cache_hits' => 0,
            'cache_misses' => 0,
            'successes' => 0,
            'failures' => 0,
            'timeouts' => 0,
            'retries' => 0,
        ];
    }

    /**
     * Create with strict timeout (socket-based).
     */
    public static function withTimeout(float $seconds): self
    {
        return new self([
            'timeout' => $seconds,
            'strategy' => self::STRATEGY_SOCKET,
        ]);
    }

    /**
     * Create for security validation (fast, cached).
     */
    public static function forSecurityValidation(): self
    {
        return new self([
            'timeout' => 2.0,
            'retries' => 1,
            'strategy' => self::STRATEGY_SOCKET,
            'cache_ttl' => 3600, // 1 hour cache
            'cache_enabled' => true,
        ]);
    }
}
