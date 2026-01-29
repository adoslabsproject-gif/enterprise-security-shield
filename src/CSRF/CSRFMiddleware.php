<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\CSRF;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * CSRF Protection Middleware (PSR-15).
 *
 * Automatically validates CSRF tokens on state-changing requests.
 */
final class CSRFMiddleware implements MiddlewareInterface
{
    private CSRFTokenManager $tokenManager;

    private array $config;

    /**
     * @var callable|null
     */
    private $responseFactory;

    /**
     * @param CSRFTokenManager $tokenManager
     * @param array{
     *     safe_methods?: array<string>,
     *     exclude_paths?: array<string>,
     *     exclude_patterns?: array<string>,
     *     log_failures?: bool
     * } $config
     */
    public function __construct(CSRFTokenManager $tokenManager, array $config = [])
    {
        $this->tokenManager = $tokenManager;
        $this->config = array_merge([
            'safe_methods' => ['GET', 'HEAD', 'OPTIONS', 'TRACE'],
            'exclude_paths' => [],
            'exclude_patterns' => [],
            'log_failures' => true,
        ], $config);
    }

    /**
     * Set response factory for error responses.
     */
    public function setResponseFactory(callable $factory): self
    {
        $this->responseFactory = $factory;

        return $this;
    }

    /**
     * Process request.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $method = $request->getMethod();
        $path = $request->getUri()->getPath();

        // Skip safe methods
        if (in_array($method, $this->config['safe_methods'], true)) {
            return $handler->handle($request);
        }

        // Skip excluded paths
        foreach ($this->config['exclude_paths'] as $excludePath) {
            if ($path === $excludePath || str_starts_with($path, $excludePath)) {
                return $handler->handle($request);
            }
        }

        // Skip excluded patterns
        foreach ($this->config['exclude_patterns'] as $pattern) {
            if (preg_match($pattern, $path)) {
                return $handler->handle($request);
            }
        }

        // Extract token from request
        $requestData = $this->buildRequestData($request);
        $result = $this->tokenManager->validateRequest($requestData);

        if (!$result->valid) {
            if ($this->config['log_failures']) {
                $this->logFailure($request, $result);
            }

            return $this->createErrorResponse($result);
        }

        return $handler->handle($request);
    }

    /**
     * Build request data array for validation.
     */
    private function buildRequestData(ServerRequestInterface $request): array
    {
        $headers = [];
        foreach ($request->getHeaders() as $name => $values) {
            $headers[$name] = $values[0] ?? '';
        }

        $serverParams = $request->getServerParams();

        return [
            'headers' => $headers,
            'POST' => $request->getParsedBody() ?? [],
            'GET' => $request->getQueryParams(),
            'COOKIE' => $request->getCookieParams(),
            'ip' => $this->getClientIp($request),
            'user_agent' => $request->getHeaderLine('User-Agent'),
        ];
    }

    /**
     * Get client IP.
     */
    private function getClientIp(ServerRequestInterface $request): string
    {
        $headers = ['X-Forwarded-For', 'X-Real-IP', 'CF-Connecting-IP'];

        foreach ($headers as $header) {
            $value = $request->getHeaderLine($header);
            if (!empty($value)) {
                $ips = explode(',', $value);

                return trim($ips[0]);
            }
        }

        $serverParams = $request->getServerParams();

        return $serverParams['REMOTE_ADDR'] ?? 'unknown';
    }

    /**
     * Log validation failure.
     */
    private function logFailure(ServerRequestInterface $request, ValidationResult $result): void
    {
        $ip = $this->getClientIp($request);
        $path = $request->getUri()->getPath();
        $method = $request->getMethod();

        error_log(sprintf(
            'CSRF validation failed: %s %s from %s - %s',
            $method,
            $path,
            $ip,
            $result->message,
        ));
    }

    /**
     * Create error response.
     */
    private function createErrorResponse(ValidationResult $result): ResponseInterface
    {
        if ($this->responseFactory !== null) {
            return ($this->responseFactory)($result);
        }

        // Create basic response
        $responseClass = class_exists(\Nyholm\Psr7\Response::class)
            ? \Nyholm\Psr7\Response::class
            : (class_exists(\GuzzleHttp\Psr7\Response::class)
                ? \GuzzleHttp\Psr7\Response::class
                : null);

        if ($responseClass === null) {
            throw new \RuntimeException('No PSR-7 response implementation available');
        }

        $body = json_encode([
            'error' => 'CSRF validation failed',
            'message' => $result->message,
        ]);

        return new $responseClass(
            403,
            ['Content-Type' => 'application/json'],
            $body,
        );
    }
}
