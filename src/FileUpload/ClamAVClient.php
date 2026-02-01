<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\FileUpload;

use AdosLabs\EnterprisePSR3Logger\LoggerFacade as Logger;

/**
 * ClamAV Antivirus Client.
 *
 * Enterprise-grade antivirus integration using ClamAV daemon.
 * Supports both Unix socket and TCP connections.
 *
 * FEATURES:
 * - File scanning
 * - Stream scanning (for memory data)
 * - Batch scanning
 * - Connection pooling
 * - Automatic reconnection
 * - Health checks
 *
 * REQUIREMENTS:
 * - ClamAV daemon (clamd) running
 * - Socket or TCP access to clamd
 *
 * INSTALLATION (Ubuntu/Debian):
 * ```bash
 * apt-get install clamav clamav-daemon
 * systemctl start clamav-daemon
 * ```
 *
 * @version 1.0.0
 */
final class ClamAVClient
{
    private const CHUNK_SIZE = 8192;

    private const DEFAULT_TIMEOUT = 30;

    private const STREAM_MAX_LENGTH = 26214400; // 25 MB

    private string $socket;

    private float $timeout;

    private mixed $connection = null;

    private bool $persistent;

    /**
     * @param string $socket Socket path or TCP address (e.g., "/var/run/clamav/clamd.sock" or "tcp://127.0.0.1:3310")
     * @param float $timeout Connection timeout in seconds
     * @param bool $persistent Use persistent connections
     */
    public function __construct(
        string $socket = '/var/run/clamav/clamd.sock',
        float $timeout = self::DEFAULT_TIMEOUT,
        bool $persistent = true,
    ) {
        $this->socket = $socket;
        $this->timeout = $timeout;
        $this->persistent = $persistent;
    }

    /**
     * Scan a file for malware.
     *
     * @param string $filePath Path to file to scan
     *
     * @throws ClamAVException
     *
     * @return array{clean: bool, virus: string|null, raw: string}
     */
    public function scanFile(string $filePath): array
    {
        if (!file_exists($filePath)) {
            throw new ClamAVException("File not found: {$filePath}");
        }

        if (!is_readable($filePath)) {
            throw new ClamAVException("File not readable: {$filePath}");
        }

        $realPath = realpath($filePath);
        if ($realPath === false) {
            throw new ClamAVException("Cannot resolve path: {$filePath}");
        }

        // Use SCAN command (clamd reads file directly)
        $response = $this->sendCommand("SCAN {$realPath}");

        return $this->parseResponse($response);
    }

    /**
     * Scan data stream for malware.
     *
     * @param string $data Data to scan
     *
     * @throws ClamAVException
     *
     * @return array{clean: bool, virus: string|null, raw: string}
     */
    public function scanStream(string $data): array
    {
        $length = strlen($data);

        if ($length > self::STREAM_MAX_LENGTH) {
            throw new ClamAVException('Data exceeds maximum stream length');
        }

        $connection = $this->getConnection();

        // Send INSTREAM command
        $this->write($connection, "zINSTREAM\0");

        // Send data in chunks
        $offset = 0;
        while ($offset < $length) {
            $chunk = substr($data, $offset, self::CHUNK_SIZE);
            $chunkLength = strlen($chunk);

            // Send chunk length (4 bytes, network byte order)
            $this->write($connection, pack('N', $chunkLength));
            $this->write($connection, $chunk);

            $offset += $chunkLength;
        }

        // Send end marker (zero-length chunk)
        $this->write($connection, pack('N', 0));

        // Read response
        $response = $this->read($connection);

        if (!$this->persistent) {
            $this->disconnect();
        }

        return $this->parseResponse($response);
    }

    /**
     * Scan multiple files.
     *
     * @param array<string> $filePaths Files to scan
     *
     * @return array<string, array{clean: bool, virus: string|null, raw: string}>
     */
    public function scanBatch(array $filePaths): array
    {
        $results = [];

        foreach ($filePaths as $filePath) {
            try {
                $results[$filePath] = $this->scanFile($filePath);
            } catch (ClamAVException $e) {
                Logger::channel('security')->error('ClamAV batch scan failed', [
                    'file_path' => $filePath,
                    'error' => $e->getMessage(),
                ]);
                $results[$filePath] = [
                    'clean' => false,
                    'virus' => null,
                    'raw' => 'ERROR: ' . $e->getMessage(),
                ];
            }
        }

        return $results;
    }

    /**
     * Scan directory recursively.
     *
     * @param string $directory Directory to scan
     *
     * @throws ClamAVException
     *
     * @return array{clean: bool, infected_files: array<string>, total_files: int, raw: string}
     */
    public function scanDirectory(string $directory): array
    {
        if (!is_dir($directory)) {
            throw new ClamAVException("Directory not found: {$directory}");
        }

        $realPath = realpath($directory);
        if ($realPath === false) {
            throw new ClamAVException("Cannot resolve path: {$directory}");
        }

        // Use CONTSCAN for recursive scanning
        $response = $this->sendCommand("CONTSCAN {$realPath}");

        $lines = explode("\n", trim($response));
        $infectedFiles = [];
        $totalFiles = 0;

        foreach ($lines as $line) {
            if (empty($line)) {
                continue;
            }

            $totalFiles++;

            if (!str_contains($line, ': OK')) {
                // Extract infected file path
                if (preg_match('/^(.+):\s*(.+)\s+FOUND$/', $line, $matches)) {
                    $infectedFiles[$matches[1]] = $matches[2];
                }
            }
        }

        return [
            'clean' => empty($infectedFiles),
            'infected_files' => $infectedFiles,
            'total_files' => $totalFiles,
            'raw' => $response,
        ];
    }

    /**
     * Get ClamAV version.
     *
     * @throws ClamAVException
     *
     * @return string Version string
     */
    public function getVersion(): string
    {
        return trim($this->sendCommand('VERSION'));
    }

    /**
     * Get ClamAV statistics.
     *
     * @throws ClamAVException
     *
     * @return array<string, mixed>
     */
    public function getStats(): array
    {
        $response = $this->sendCommand('STATS');
        $stats = [];
        $lines = explode("\n", $response);

        foreach ($lines as $line) {
            if (str_contains($line, ':')) {
                [$key, $value] = explode(':', $line, 2);
                $stats[trim($key)] = trim($value);
            }
        }

        return $stats;
    }

    /**
     * Ping ClamAV daemon.
     *
     * @return bool True if daemon is responding
     */
    public function ping(): bool
    {
        try {
            $response = $this->sendCommand('PING');

            return trim($response) === 'PONG';
        } catch (ClamAVException $e) {
            return false;
        }
    }

    /**
     * Reload virus database.
     *
     * @throws ClamAVException
     *
     * @return bool True if reload was successful
     */
    public function reload(): bool
    {
        $response = $this->sendCommand('RELOAD');

        return str_contains($response, 'RELOADING');
    }

    /**
     * Check daemon health.
     *
     * @return array{healthy: bool, version: string|null, signatures: int|null, error: string|null}
     */
    public function health(): array
    {
        try {
            $ping = $this->ping();
            if (!$ping) {
                Logger::channel('security')->warning('ClamAV daemon not responding to ping');

                return [
                    'healthy' => false,
                    'version' => null,
                    'signatures' => null,
                    'error' => 'Daemon not responding to ping',
                ];
            }

            $version = $this->getVersion();
            $stats = $this->getStats();

            return [
                'healthy' => true,
                'version' => $version,
                'signatures' => isset($stats['SIGNATURES']) ? (int) $stats['SIGNATURES'] : null,
                'error' => null,
            ];
        } catch (ClamAVException $e) {
            Logger::channel('security')->error('ClamAV health check failed', [
                'error' => $e->getMessage(),
            ]);

            return [
                'healthy' => false,
                'version' => null,
                'signatures' => null,
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Send command to ClamAV daemon.
     *
     * @throws ClamAVException
     */
    private function sendCommand(string $command): string
    {
        $connection = $this->getConnection();

        // Use null-terminated command for zCommands
        if (!str_starts_with($command, 'z')) {
            $command = "z{$command}\0";
        }

        $this->write($connection, $command);
        $response = $this->read($connection);

        if (!$this->persistent) {
            $this->disconnect();
        }

        return $response;
    }

    /**
     * Get connection to daemon.
     *
     * @throws ClamAVException
     *
     * @return resource
     */
    private function getConnection()
    {
        if ($this->connection !== null && is_resource($this->connection)) {
            // Check if connection is still valid
            $meta = stream_get_meta_data($this->connection);
            if (!$meta['eof'] && !$meta['timed_out']) {
                return $this->connection;
            }
            $this->disconnect();
        }

        // Determine connection type
        if (str_starts_with($this->socket, 'tcp://')) {
            $socket = $this->socket;
        } else {
            // Unix socket
            $socket = "unix://{$this->socket}";
        }

        $errno = 0;
        $errstr = '';

        $flags = STREAM_CLIENT_CONNECT;
        if ($this->persistent) {
            $flags |= STREAM_CLIENT_PERSISTENT;
        }

        $context = stream_context_create([
            'socket' => [
                'tcp_nodelay' => true,
            ],
        ]);

        $connection = @stream_socket_client(
            $socket,
            $errno,
            $errstr,
            $this->timeout,
            $flags,
            $context,
        );

        if ($connection === false) {
            Logger::channel('security')->error('ClamAV connection failed', [
                'socket' => $this->socket,
                'errno' => $errno,
                'errstr' => $errstr,
            ]);

            throw new ClamAVException("Failed to connect to ClamAV: [{$errno}] {$errstr}");
        }

        stream_set_timeout($connection, (int) $this->timeout, (int) (($this->timeout - (int) $this->timeout) * 1000000));

        $this->connection = $connection;

        return $this->connection;
    }

    /**
     * Write data to connection.
     *
     * @param resource $connection
     *
     * @throws ClamAVException
     */
    private function write($connection, string $data): void
    {
        $written = @fwrite($connection, $data);

        if ($written === false || $written !== strlen($data)) {
            Logger::channel('security')->error('ClamAV write failed');

            throw new ClamAVException('Failed to write to ClamAV');
        }
    }

    /**
     * Read response from connection.
     *
     * @param resource $connection
     *
     * @throws ClamAVException
     */
    private function read($connection): string
    {
        $response = '';

        while (!feof($connection)) {
            $chunk = @fread($connection, self::CHUNK_SIZE);

            if ($chunk === false) {
                Logger::channel('security')->error('ClamAV read failed');

                throw new ClamAVException('Failed to read from ClamAV');
            }

            if ($chunk === '') {
                break;
            }

            $response .= $chunk;

            // Check for timeout
            $meta = stream_get_meta_data($connection);
            if ($meta['timed_out']) {
                Logger::channel('security')->error('ClamAV connection timed out');

                throw new ClamAVException('Connection to ClamAV timed out');
            }

            // Check for complete response (null-terminated)
            if (str_ends_with($response, "\0")) {
                $response = rtrim($response, "\0");
                break;
            }
        }

        return $response;
    }

    /**
     * Parse ClamAV response.
     *
     * @return array{clean: bool, virus: string|null, raw: string}
     */
    private function parseResponse(string $response): array
    {
        $response = trim($response);

        // Check for OK response
        if (str_ends_with($response, ': OK') || $response === 'OK') {
            return [
                'clean' => true,
                'virus' => null,
                'raw' => $response,
            ];
        }

        // Check for FOUND response
        if (preg_match('/:\s*(.+)\s+FOUND$/', $response, $matches)) {
            return [
                'clean' => false,
                'virus' => trim($matches[1]),
                'raw' => $response,
            ];
        }

        // Check for error
        if (str_contains($response, 'ERROR')) {
            throw new ClamAVException("ClamAV error: {$response}");
        }

        // Unknown response
        return [
            'clean' => true,
            'virus' => null,
            'raw' => $response,
        ];
    }

    /**
     * Disconnect from daemon.
     */
    public function disconnect(): void
    {
        if ($this->connection !== null && is_resource($this->connection)) {
            @fclose($this->connection);
        }
        $this->connection = null;
    }

    /**
     * Destructor.
     */
    public function __destruct()
    {
        if (!$this->persistent) {
            $this->disconnect();
        }
    }
}
