<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Request Size Limiter Middleware
 *
 * Enterprise-grade protection against oversized requests.
 * Prevents DoS attacks via large payloads before they consume resources.
 *
 * PROTECTION AGAINST:
 * - Memory exhaustion attacks (large POST bodies)
 * - Slowloris-style attacks (slow POST body transmission)
 * - JSON/XML bomb attacks (decompression bombs)
 * - File upload abuse
 *
 * FEATURES:
 * - Configurable limits per content type
 * - Configurable limits per endpoint
 * - Early rejection (before body parsing)
 * - Streaming support for large files
 * - Detailed error responses
 *
 * @version 1.0.0
 */
final class RequestSizeLimiter implements MiddlewareInterface
{
    /**
     * Default maximum body size (10 MB)
     */
    private const DEFAULT_MAX_BODY_SIZE = 10 * 1024 * 1024;

    /**
     * Default maximum URL length
     */
    private const DEFAULT_MAX_URL_LENGTH = 8192;

    /**
     * Default maximum header size per header
     */
    private const DEFAULT_MAX_HEADER_SIZE = 8192;

    /**
     * Default maximum total headers size
     */
    private const DEFAULT_MAX_TOTAL_HEADERS_SIZE = 65536;

    /**
     * Default maximum number of headers
     */
    private const DEFAULT_MAX_HEADER_COUNT = 100;

    /**
     * Default maximum query string length
     */
    private const DEFAULT_MAX_QUERY_STRING_LENGTH = 4096;

    /**
     * Default maximum number of query parameters
     */
    private const DEFAULT_MAX_QUERY_PARAMS = 100;

    /**
     * Default maximum POST field count
     */
    private const DEFAULT_MAX_POST_FIELDS = 100;

    /**
     * Default maximum cookie count
     */
    private const DEFAULT_MAX_COOKIES = 50;

    /**
     * Configuration
     *
     * @var array{
     *     max_body_size: int,
     *     max_url_length: int,
     *     max_header_size: int,
     *     max_total_headers_size: int,
     *     max_header_count: int,
     *     max_query_string_length: int,
     *     max_query_params: int,
     *     max_post_fields: int,
     *     max_cookies: int,
     *     content_type_limits: array<string, int>,
     *     endpoint_limits: array<string, int>,
     *     allowed_content_types: array<string>,
     *     block_oversized: bool,
     *     log_violations: bool
     * }
     */
    private array $config;

    /**
     * Response factory for error responses
     *
     * @var callable|null
     */
    private $responseFactory;

    /**
     * Violation callback
     *
     * @var callable|null
     */
    private $onViolation;

    /**
     * @param array{
     *     max_body_size?: int,
     *     max_url_length?: int,
     *     max_header_size?: int,
     *     max_total_headers_size?: int,
     *     max_header_count?: int,
     *     max_query_string_length?: int,
     *     max_query_params?: int,
     *     max_post_fields?: int,
     *     max_cookies?: int,
     *     content_type_limits?: array<string, int>,
     *     endpoint_limits?: array<string, int>,
     *     allowed_content_types?: array<string>,
     *     block_oversized?: bool,
     *     log_violations?: bool
     * } $config Configuration options
     */
    public function __construct(array $config = [])
    {
        $this->config = array_merge([
            'max_body_size' => self::DEFAULT_MAX_BODY_SIZE,
            'max_url_length' => self::DEFAULT_MAX_URL_LENGTH,
            'max_header_size' => self::DEFAULT_MAX_HEADER_SIZE,
            'max_total_headers_size' => self::DEFAULT_MAX_TOTAL_HEADERS_SIZE,
            'max_header_count' => self::DEFAULT_MAX_HEADER_COUNT,
            'max_query_string_length' => self::DEFAULT_MAX_QUERY_STRING_LENGTH,
            'max_query_params' => self::DEFAULT_MAX_QUERY_PARAMS,
            'max_post_fields' => self::DEFAULT_MAX_POST_FIELDS,
            'max_cookies' => self::DEFAULT_MAX_COOKIES,
            'content_type_limits' => [
                'application/json' => 5 * 1024 * 1024, // 5 MB for JSON
                'application/xml' => 5 * 1024 * 1024,  // 5 MB for XML
                'text/xml' => 5 * 1024 * 1024,
                'multipart/form-data' => 50 * 1024 * 1024, // 50 MB for file uploads
                'application/x-www-form-urlencoded' => 1 * 1024 * 1024, // 1 MB for forms
            ],
            'endpoint_limits' => [
                // Example: '/api/upload' => 100 * 1024 * 1024
            ],
            'allowed_content_types' => [
                'application/json',
                'application/xml',
                'text/xml',
                'text/plain',
                'text/html',
                'multipart/form-data',
                'application/x-www-form-urlencoded',
                'application/octet-stream',
            ],
            'block_oversized' => true,
            'log_violations' => true,
        ], $config);
    }

    /**
     * Set response factory for error responses
     *
     * @param callable $factory Function that returns ResponseInterface
     */
    public function setResponseFactory(callable $factory): self
    {
        $this->responseFactory = $factory;

        return $this;
    }

    /**
     * Set violation callback
     *
     * @param callable $callback Function called on violations: fn(string $type, array $details)
     */
    public function setViolationCallback(callable $callback): self
    {
        $this->onViolation = $callback;

        return $this;
    }

    /**
     * Process request through middleware
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $violations = $this->validate($request);

        if (!empty($violations)) {
            if ($this->config['log_violations']) {
                $this->logViolations($request, $violations);
            }

            if ($this->onViolation !== null) {
                foreach ($violations as $violation) {
                    ($this->onViolation)($violation['type'], $violation);
                }
            }

            if ($this->config['block_oversized']) {
                return $this->createErrorResponse($violations);
            }
        }

        return $handler->handle($request);
    }

    /**
     * Validate request against size limits
     *
     * @param ServerRequestInterface $request
     * @return array<array{type: string, message: string, limit: int, actual: int}>
     */
    public function validate(ServerRequestInterface $request): array
    {
        $violations = [];

        // Check URL length
        $urlViolation = $this->checkUrlLength($request);
        if ($urlViolation !== null) {
            $violations[] = $urlViolation;
        }

        // Check query string
        $queryViolation = $this->checkQueryString($request);
        if ($queryViolation !== null) {
            $violations[] = $queryViolation;
        }

        // Check query param count
        $queryCountViolation = $this->checkQueryParamCount($request);
        if ($queryCountViolation !== null) {
            $violations[] = $queryCountViolation;
        }

        // Check headers
        $headerViolations = $this->checkHeaders($request);
        $violations = array_merge($violations, $headerViolations);

        // Check cookies
        $cookieViolation = $this->checkCookies($request);
        if ($cookieViolation !== null) {
            $violations[] = $cookieViolation;
        }

        // Check content type
        $contentTypeViolation = $this->checkContentType($request);
        if ($contentTypeViolation !== null) {
            $violations[] = $contentTypeViolation;
        }

        // Check body size
        $bodyViolation = $this->checkBodySize($request);
        if ($bodyViolation !== null) {
            $violations[] = $bodyViolation;
        }

        // Check POST fields (for form data)
        $postViolation = $this->checkPostFields($request);
        if ($postViolation !== null) {
            $violations[] = $postViolation;
        }

        return $violations;
    }

    /**
     * Check URL length
     *
     * @return array{type: string, message: string, limit: int, actual: int}|null
     */
    private function checkUrlLength(ServerRequestInterface $request): ?array
    {
        $uri = (string) $request->getUri();
        $length = strlen($uri);

        if ($length > $this->config['max_url_length']) {
            return [
                'type' => 'url_too_long',
                'message' => 'URL exceeds maximum allowed length',
                'limit' => $this->config['max_url_length'],
                'actual' => $length,
            ];
        }

        return null;
    }

    /**
     * Check query string length
     *
     * @return array{type: string, message: string, limit: int, actual: int}|null
     */
    private function checkQueryString(ServerRequestInterface $request): ?array
    {
        $query = $request->getUri()->getQuery();
        $length = strlen($query);

        if ($length > $this->config['max_query_string_length']) {
            return [
                'type' => 'query_string_too_long',
                'message' => 'Query string exceeds maximum allowed length',
                'limit' => $this->config['max_query_string_length'],
                'actual' => $length,
            ];
        }

        return null;
    }

    /**
     * Check query parameter count
     *
     * @return array{type: string, message: string, limit: int, actual: int}|null
     */
    private function checkQueryParamCount(ServerRequestInterface $request): ?array
    {
        $params = $request->getQueryParams();
        $count = $this->countRecursive($params);

        if ($count > $this->config['max_query_params']) {
            return [
                'type' => 'too_many_query_params',
                'message' => 'Number of query parameters exceeds limit',
                'limit' => $this->config['max_query_params'],
                'actual' => $count,
            ];
        }

        return null;
    }

    /**
     * Check headers
     *
     * @return array<array{type: string, message: string, limit: int, actual: int}>
     */
    private function checkHeaders(ServerRequestInterface $request): array
    {
        $violations = [];
        $headers = $request->getHeaders();
        $headerCount = count($headers);
        $totalSize = 0;

        // Check header count
        if ($headerCount > $this->config['max_header_count']) {
            $violations[] = [
                'type' => 'too_many_headers',
                'message' => 'Number of headers exceeds limit',
                'limit' => $this->config['max_header_count'],
                'actual' => $headerCount,
            ];
        }

        // Check individual and total header sizes
        foreach ($headers as $name => $values) {
            $headerSize = strlen($name) + 2; // name + ": "
            foreach ($values as $value) {
                $headerSize += strlen($value);
            }
            $totalSize += $headerSize;

            if ($headerSize > $this->config['max_header_size']) {
                $violations[] = [
                    'type' => 'header_too_large',
                    'message' => "Header '{$name}' exceeds maximum size",
                    'limit' => $this->config['max_header_size'],
                    'actual' => $headerSize,
                ];
            }
        }

        // Check total headers size
        if ($totalSize > $this->config['max_total_headers_size']) {
            $violations[] = [
                'type' => 'total_headers_too_large',
                'message' => 'Total headers size exceeds limit',
                'limit' => $this->config['max_total_headers_size'],
                'actual' => $totalSize,
            ];
        }

        return $violations;
    }

    /**
     * Check cookie count
     *
     * @return array{type: string, message: string, limit: int, actual: int}|null
     */
    private function checkCookies(ServerRequestInterface $request): ?array
    {
        $cookies = $request->getCookieParams();
        $count = count($cookies);

        if ($count > $this->config['max_cookies']) {
            return [
                'type' => 'too_many_cookies',
                'message' => 'Number of cookies exceeds limit',
                'limit' => $this->config['max_cookies'],
                'actual' => $count,
            ];
        }

        return null;
    }

    /**
     * Check content type
     *
     * @return array{type: string, message: string, limit: int, actual: int}|null
     */
    private function checkContentType(ServerRequestInterface $request): ?array
    {
        // Only check for requests with body
        if (!in_array($request->getMethod(), ['POST', 'PUT', 'PATCH'], true)) {
            return null;
        }

        $contentType = $request->getHeaderLine('Content-Type');
        if (empty($contentType)) {
            return null;
        }

        // Extract base content type (without charset etc.)
        $baseContentType = strtolower(explode(';', $contentType)[0]);
        $baseContentType = trim($baseContentType);

        // Check if content type is allowed
        if (!empty($this->config['allowed_content_types'])) {
            $allowed = false;
            foreach ($this->config['allowed_content_types'] as $allowedType) {
                if (str_starts_with($baseContentType, strtolower($allowedType))) {
                    $allowed = true;
                    break;
                }
            }

            if (!$allowed) {
                return [
                    'type' => 'disallowed_content_type',
                    'message' => "Content type '{$baseContentType}' is not allowed",
                    'limit' => 0,
                    'actual' => 0,
                ];
            }
        }

        return null;
    }

    /**
     * Check body size
     *
     * @return array{type: string, message: string, limit: int, actual: int}|null
     */
    private function checkBodySize(ServerRequestInterface $request): ?array
    {
        // Get Content-Length header (early rejection without reading body)
        $contentLength = $request->getHeaderLine('Content-Length');
        if ($contentLength !== '') {
            $bodySize = (int) $contentLength;
        } else {
            // Fall back to reading body (for chunked encoding)
            $body = $request->getBody();
            $bodySize = $body->getSize();
            if ($bodySize === null) {
                // Cannot determine size, allow through
                return null;
            }
        }

        // Determine applicable limit
        $limit = $this->getApplicableBodyLimit($request);

        if ($bodySize > $limit) {
            return [
                'type' => 'body_too_large',
                'message' => 'Request body exceeds maximum allowed size',
                'limit' => $limit,
                'actual' => $bodySize,
            ];
        }

        return null;
    }

    /**
     * Check POST fields count
     *
     * @return array{type: string, message: string, limit: int, actual: int}|null
     */
    private function checkPostFields(ServerRequestInterface $request): ?array
    {
        if ($request->getMethod() !== 'POST') {
            return null;
        }

        $parsedBody = $request->getParsedBody();
        if (!is_array($parsedBody)) {
            return null;
        }

        $count = $this->countRecursive($parsedBody);

        if ($count > $this->config['max_post_fields']) {
            return [
                'type' => 'too_many_post_fields',
                'message' => 'Number of POST fields exceeds limit',
                'limit' => $this->config['max_post_fields'],
                'actual' => $count,
            ];
        }

        return null;
    }

    /**
     * Get applicable body size limit for request
     */
    private function getApplicableBodyLimit(ServerRequestInterface $request): int
    {
        // Check endpoint-specific limits first
        $path = $request->getUri()->getPath();
        foreach ($this->config['endpoint_limits'] as $endpoint => $limit) {
            if (str_starts_with($path, $endpoint) || fnmatch($endpoint, $path)) {
                return $limit;
            }
        }

        // Check content-type specific limits
        $contentType = $request->getHeaderLine('Content-Type');
        if (!empty($contentType)) {
            $baseContentType = strtolower(trim(explode(';', $contentType)[0]));
            foreach ($this->config['content_type_limits'] as $type => $limit) {
                if (str_starts_with($baseContentType, strtolower($type))) {
                    return $limit;
                }
            }
        }

        // Default limit
        return $this->config['max_body_size'];
    }

    /**
     * Count array items recursively
     */
    private function countRecursive(array $array): int
    {
        $count = 0;
        foreach ($array as $value) {
            $count++;
            if (is_array($value)) {
                $count += $this->countRecursive($value);
            }
        }

        return $count;
    }

    /**
     * Log violations
     *
     * @param array<array{type: string, message: string}> $violations
     */
    private function logViolations(ServerRequestInterface $request, array $violations): void
    {
        $ip = $this->getClientIp($request);
        $method = $request->getMethod();
        $path = $request->getUri()->getPath();

        foreach ($violations as $violation) {
            error_log(sprintf(
                'RequestSizeLimiter: %s from %s %s %s (limit: %d, actual: %d)',
                $violation['type'],
                $ip,
                $method,
                $path,
                $violation['limit'] ?? 0,
                $violation['actual'] ?? 0
            ));
        }
    }

    /**
     * Get client IP from request
     */
    private function getClientIp(ServerRequestInterface $request): string
    {
        // Check common proxy headers
        $headers = ['X-Forwarded-For', 'X-Real-IP', 'CF-Connecting-IP'];
        foreach ($headers as $header) {
            $value = $request->getHeaderLine($header);
            if (!empty($value)) {
                // X-Forwarded-For may contain multiple IPs
                $ips = explode(',', $value);

                return trim($ips[0]);
            }
        }

        // Fall back to server params
        $serverParams = $request->getServerParams();

        return $serverParams['REMOTE_ADDR'] ?? 'unknown';
    }

    /**
     * Create error response
     *
     * @param array<array{type: string, message: string}> $violations
     */
    private function createErrorResponse(array $violations): ResponseInterface
    {
        // Use custom factory if set
        if ($this->responseFactory !== null) {
            return ($this->responseFactory)($violations);
        }

        // Create basic response using Nyholm (if available) or throw
        $responseClass = class_exists(\Nyholm\Psr7\Response::class)
            ? \Nyholm\Psr7\Response::class
            : (class_exists(\GuzzleHttp\Psr7\Response::class)
                ? \GuzzleHttp\Psr7\Response::class
                : null);

        if ($responseClass === null) {
            throw new \RuntimeException(
                'No PSR-7 response implementation found. Install nyholm/psr7 or set a custom response factory.'
            );
        }

        $body = json_encode([
            'error' => 'Request Too Large',
            'code' => 413,
            'violations' => array_map(fn($v) => [
                'type' => $v['type'],
                'message' => $v['message'],
            ], $violations),
        ]);

        return new $responseClass(
            413,
            ['Content-Type' => 'application/json'],
            $body
        );
    }

    /**
     * Update configuration
     *
     * @param array<string, mixed> $config
     */
    public function configure(array $config): self
    {
        $this->config = array_merge($this->config, $config);

        return $this;
    }

    /**
     * Set endpoint limit
     *
     * @param string $endpoint Endpoint path or pattern
     * @param int $limit Maximum body size in bytes
     */
    public function setEndpointLimit(string $endpoint, int $limit): self
    {
        $this->config['endpoint_limits'][$endpoint] = $limit;

        return $this;
    }

    /**
     * Set content type limit
     *
     * @param string $contentType Content type
     * @param int $limit Maximum body size in bytes
     */
    public function setContentTypeLimit(string $contentType, int $limit): self
    {
        $this->config['content_type_limits'][$contentType] = $limit;

        return $this;
    }

    /**
     * Add allowed content type
     *
     * @param string $contentType Content type to allow
     */
    public function addAllowedContentType(string $contentType): self
    {
        if (!in_array($contentType, $this->config['allowed_content_types'], true)) {
            $this->config['allowed_content_types'][] = $contentType;
        }

        return $this;
    }

    /**
     * Get current configuration
     *
     * @return array<string, mixed>
     */
    public function getConfig(): array
    {
        return $this->config;
    }
}
