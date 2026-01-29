<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Tests\Unit\Middleware;

use AdosLabs\EnterpriseSecurityShield\Middleware\RequestSizeLimiter;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * @covers \AdosLabs\EnterpriseSecurityShield\Middleware\RequestSizeLimiter
 */
final class RequestSizeLimiterTest extends TestCase
{
    private RequestSizeLimiter $limiter;

    private RequestHandlerInterface $handler;

    protected function setUp(): void
    {
        $this->limiter = new RequestSizeLimiter();

        // Create a mock handler that returns 200 OK
        $this->handler = new class () implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new Response(200, [], 'OK');
            }
        };
    }

    // =========================================================================
    // CONSTRUCTOR TESTS
    // =========================================================================

    public function testDefaultConfiguration(): void
    {
        $config = $this->limiter->getConfig();

        $this->assertEquals(10 * 1024 * 1024, $config['max_body_size']);
        $this->assertEquals(8192, $config['max_url_length']);
        $this->assertEquals(100, $config['max_query_params']);
        $this->assertTrue($config['block_oversized']);
    }

    public function testCustomConfiguration(): void
    {
        $limiter = new RequestSizeLimiter([
            'max_body_size' => 1024,
            'max_url_length' => 256,
        ]);

        $config = $limiter->getConfig();

        $this->assertEquals(1024, $config['max_body_size']);
        $this->assertEquals(256, $config['max_url_length']);
    }

    // =========================================================================
    // URL LENGTH TESTS
    // =========================================================================

    public function testAllowsNormalUrlLength(): void
    {
        $request = new ServerRequest('GET', '/api/users');

        $response = $this->limiter->process($request, $this->handler);

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testBlocksTooLongUrl(): void
    {
        $limiter = new RequestSizeLimiter(['max_url_length' => 50]);
        $longPath = '/' . str_repeat('a', 100);
        $request = new ServerRequest('GET', $longPath);

        $response = $limiter->process($request, $this->handler);

        $this->assertEquals(413, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        $this->assertEquals('url_too_long', $body['violations'][0]['type']);
    }

    // =========================================================================
    // QUERY STRING TESTS
    // =========================================================================

    public function testAllowsNormalQueryString(): void
    {
        $request = new ServerRequest('GET', '/api/users?page=1&limit=10');

        $response = $this->limiter->process($request, $this->handler);

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testBlocksTooLongQueryString(): void
    {
        $limiter = new RequestSizeLimiter(['max_query_string_length' => 50]);
        $longQuery = 'q=' . str_repeat('a', 100);
        $request = new ServerRequest('GET', '/api/search?' . $longQuery);

        $response = $limiter->process($request, $this->handler);

        $this->assertEquals(413, $response->getStatusCode());
    }

    public function testBlocksTooManyQueryParams(): void
    {
        $limiter = new RequestSizeLimiter(['max_query_params' => 5]);

        // Build query string with more params
        $params = [];
        for ($i = 0; $i < 10; $i++) {
            $params["param{$i}"] = "value{$i}";
        }
        $queryString = http_build_query($params);

        $request = (new ServerRequest('GET', '/api/search'))
            ->withQueryParams($params);

        $response = $limiter->process($request, $this->handler);

        $this->assertEquals(413, $response->getStatusCode());
    }

    // =========================================================================
    // HEADER TESTS
    // =========================================================================

    public function testAllowsNormalHeaders(): void
    {
        $request = (new ServerRequest('GET', '/api/users'))
            ->withHeader('Accept', 'application/json')
            ->withHeader('User-Agent', 'Test/1.0');

        $response = $this->limiter->process($request, $this->handler);

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testBlocksTooManyHeaders(): void
    {
        $limiter = new RequestSizeLimiter(['max_header_count' => 5]);

        $request = new ServerRequest('GET', '/api/users');
        for ($i = 0; $i < 10; $i++) {
            $request = $request->withHeader("X-Custom-{$i}", "value{$i}");
        }

        $response = $limiter->process($request, $this->handler);

        $this->assertEquals(413, $response->getStatusCode());
    }

    public function testBlocksTooLargeHeader(): void
    {
        $limiter = new RequestSizeLimiter(['max_header_size' => 100]);

        $request = (new ServerRequest('GET', '/api/users'))
            ->withHeader('X-Large-Header', str_repeat('x', 500));

        $response = $limiter->process($request, $this->handler);

        $this->assertEquals(413, $response->getStatusCode());
    }

    // =========================================================================
    // COOKIE TESTS
    // =========================================================================

    public function testAllowsNormalCookies(): void
    {
        $request = (new ServerRequest('GET', '/api/users'))
            ->withCookieParams(['session' => 'abc123']);

        $response = $this->limiter->process($request, $this->handler);

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testBlocksTooManyCookies(): void
    {
        $limiter = new RequestSizeLimiter(['max_cookies' => 5]);

        $cookies = [];
        for ($i = 0; $i < 10; $i++) {
            $cookies["cookie{$i}"] = "value{$i}";
        }

        $request = (new ServerRequest('GET', '/api/users'))
            ->withCookieParams($cookies);

        $response = $limiter->process($request, $this->handler);

        $this->assertEquals(413, $response->getStatusCode());
    }

    // =========================================================================
    // BODY SIZE TESTS
    // =========================================================================

    public function testAllowsNormalBodySize(): void
    {
        $body = json_encode(['name' => 'Test']);
        $request = new ServerRequest('POST', '/api/users', [
            'Content-Type' => 'application/json',
            'Content-Length' => strlen($body),
        ], $body);

        $response = $this->limiter->process($request, $this->handler);

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testBlocksTooLargeBody(): void
    {
        $limiter = new RequestSizeLimiter([
            'max_body_size' => 100,
            'content_type_limits' => [], // Disable content-type specific limits
        ]);

        $body = str_repeat('x', 500);
        $request = new ServerRequest('POST', '/api/users', [
            'Content-Type' => 'application/json',
            'Content-Length' => strlen($body),
        ], $body);

        $response = $limiter->process($request, $this->handler);

        $this->assertEquals(413, $response->getStatusCode());
    }

    public function testContentTypeLimits(): void
    {
        $limiter = new RequestSizeLimiter([
            'max_body_size' => 10 * 1024 * 1024,
            'content_type_limits' => [
                'application/json' => 100,
            ],
        ]);

        $body = str_repeat('x', 500);
        $request = new ServerRequest('POST', '/api/users', [
            'Content-Type' => 'application/json',
            'Content-Length' => strlen($body),
        ], $body);

        $response = $limiter->process($request, $this->handler);

        $this->assertEquals(413, $response->getStatusCode());
    }

    public function testEndpointLimits(): void
    {
        $limiter = new RequestSizeLimiter([
            'max_body_size' => 10 * 1024 * 1024,
            'endpoint_limits' => [
                '/api/upload' => 100 * 1024 * 1024, // Allow large uploads
                '/api/data' => 100, // Very small limit
            ],
        ]);

        // Request to /api/data with large body should be blocked
        $body = str_repeat('x', 500);
        $request = new ServerRequest('POST', '/api/data', [
            'Content-Type' => 'application/json',
            'Content-Length' => strlen($body),
        ], $body);

        $response = $limiter->process($request, $this->handler);

        $this->assertEquals(413, $response->getStatusCode());
    }

    // =========================================================================
    // CONTENT TYPE VALIDATION
    // =========================================================================

    public function testAllowsAllowedContentTypes(): void
    {
        $request = new ServerRequest('POST', '/api/users', [
            'Content-Type' => 'application/json',
            'Content-Length' => '10',
        ], '{"a":"b"}');

        $response = $this->limiter->process($request, $this->handler);

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testBlocksDisallowedContentTypes(): void
    {
        $limiter = new RequestSizeLimiter([
            'allowed_content_types' => ['application/json'],
        ]);

        $request = new ServerRequest('POST', '/api/users', [
            'Content-Type' => 'application/x-evil-type',
            'Content-Length' => '10',
        ], 'test data');

        $response = $limiter->process($request, $this->handler);

        $this->assertEquals(413, $response->getStatusCode());
    }

    // =========================================================================
    // POST FIELDS TESTS
    // =========================================================================

    public function testAllowsNormalPostFields(): void
    {
        $request = (new ServerRequest('POST', '/api/form', [
            'Content-Type' => 'application/x-www-form-urlencoded',
        ]))
            ->withParsedBody(['name' => 'Test', 'email' => 'test@example.com']);

        $response = $this->limiter->process($request, $this->handler);

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testBlocksTooManyPostFields(): void
    {
        $limiter = new RequestSizeLimiter(['max_post_fields' => 5]);

        $fields = [];
        for ($i = 0; $i < 20; $i++) {
            $fields["field{$i}"] = "value{$i}";
        }

        $request = (new ServerRequest('POST', '/api/form', [
            'Content-Type' => 'application/x-www-form-urlencoded',
        ]))
            ->withParsedBody($fields);

        $response = $limiter->process($request, $this->handler);

        $this->assertEquals(413, $response->getStatusCode());
    }

    // =========================================================================
    // VALIDATE METHOD TESTS
    // =========================================================================

    public function testValidateReturnsEmptyArrayForValidRequest(): void
    {
        $request = new ServerRequest('GET', '/api/users');

        $violations = $this->limiter->validate($request);

        $this->assertEmpty($violations);
    }

    public function testValidateReturnsViolationsForInvalidRequest(): void
    {
        $limiter = new RequestSizeLimiter(['max_url_length' => 10]);
        $request = new ServerRequest('GET', '/a/very/long/url/path');

        $violations = $limiter->validate($request);

        $this->assertNotEmpty($violations);
        $this->assertEquals('url_too_long', $violations[0]['type']);
    }

    // =========================================================================
    // CONFIGURATION METHODS TESTS
    // =========================================================================

    public function testConfigureUpdatesConfiguration(): void
    {
        $this->limiter->configure([
            'max_body_size' => 5000,
            'max_url_length' => 1000,
        ]);

        $config = $this->limiter->getConfig();

        $this->assertEquals(5000, $config['max_body_size']);
        $this->assertEquals(1000, $config['max_url_length']);
    }

    public function testSetEndpointLimit(): void
    {
        $this->limiter->setEndpointLimit('/api/upload', 100 * 1024 * 1024);

        $config = $this->limiter->getConfig();

        $this->assertEquals(100 * 1024 * 1024, $config['endpoint_limits']['/api/upload']);
    }

    public function testSetContentTypeLimit(): void
    {
        $this->limiter->setContentTypeLimit('application/octet-stream', 200 * 1024 * 1024);

        $config = $this->limiter->getConfig();

        $this->assertEquals(200 * 1024 * 1024, $config['content_type_limits']['application/octet-stream']);
    }

    public function testAddAllowedContentType(): void
    {
        $this->limiter->addAllowedContentType('application/custom-type');

        $config = $this->limiter->getConfig();

        $this->assertContains('application/custom-type', $config['allowed_content_types']);
    }

    // =========================================================================
    // CALLBACK TESTS
    // =========================================================================

    public function testViolationCallbackIsCalled(): void
    {
        $limiter = new RequestSizeLimiter(['max_url_length' => 10]);

        $violations = [];
        $limiter->setViolationCallback(function (string $type, array $details) use (&$violations) {
            $violations[] = $details;
        });

        $request = new ServerRequest('GET', '/a/very/long/url/path');
        $limiter->process($request, $this->handler);

        $this->assertNotEmpty($violations);
        $this->assertEquals('url_too_long', $violations[0]['type']);
    }

    public function testCustomResponseFactory(): void
    {
        $limiter = new RequestSizeLimiter(['max_url_length' => 10]);

        $limiter->setResponseFactory(function (array $violations) {
            return new Response(
                400,
                ['Content-Type' => 'text/plain'],
                'Custom error',
            );
        });

        $request = new ServerRequest('GET', '/a/very/long/url/path');
        $response = $limiter->process($request, $this->handler);

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('Custom error', (string) $response->getBody());
    }

    // =========================================================================
    // NON-BLOCKING MODE TESTS
    // =========================================================================

    public function testNonBlockingModeAllowsOversizedRequests(): void
    {
        $limiter = new RequestSizeLimiter([
            'max_url_length' => 10,
            'block_oversized' => false,
        ]);

        $request = new ServerRequest('GET', '/a/very/long/url/path');
        $response = $limiter->process($request, $this->handler);

        // Should pass through to handler
        $this->assertEquals(200, $response->getStatusCode());
    }

    // =========================================================================
    // FLUENT INTERFACE TESTS
    // =========================================================================

    public function testFluentInterface(): void
    {
        $result = $this->limiter
            ->configure(['max_body_size' => 1000])
            ->setEndpointLimit('/api/upload', 50000)
            ->setContentTypeLimit('text/xml', 5000)
            ->addAllowedContentType('custom/type')
            ->setResponseFactory(fn ($v) => new Response(400))
            ->setViolationCallback(fn ($t, $d) => null);

        $this->assertInstanceOf(RequestSizeLimiter::class, $result);
    }
}
