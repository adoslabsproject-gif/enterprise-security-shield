<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Headers;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Security Headers Middleware (PSR-15)
 *
 * Enterprise-grade HTTP security headers implementation.
 * Follows OWASP recommendations and browser best practices.
 *
 * HEADERS IMPLEMENTED:
 * - Content-Security-Policy (CSP)
 * - Strict-Transport-Security (HSTS)
 * - X-Frame-Options
 * - X-Content-Type-Options
 * - X-XSS-Protection
 * - Referrer-Policy
 * - Permissions-Policy
 * - Cross-Origin-Embedder-Policy (COEP)
 * - Cross-Origin-Opener-Policy (COOP)
 * - Cross-Origin-Resource-Policy (CORP)
 * - Cache-Control (security-related)
 *
 * @version 1.0.0
 */
final class SecurityHeadersMiddleware implements MiddlewareInterface
{
    private array $config;

    /**
     * @param array{
     *     hsts?: array{enabled?: bool, max_age?: int, include_subdomains?: bool, preload?: bool},
     *     csp?: array{enabled?: bool, report_only?: bool, directives?: array<string, array<string>|string>, report_uri?: string},
     *     frame_options?: string,
     *     content_type_options?: bool,
     *     xss_protection?: bool,
     *     referrer_policy?: string,
     *     permissions_policy?: array<string, array<string>>,
     *     coep?: string,
     *     coop?: string,
     *     corp?: string,
     *     cache_control?: string,
     *     remove_headers?: array<string>,
     *     custom_headers?: array<string, string>
     * } $config
     */
    public function __construct(array $config = [])
    {
        $this->config = array_merge([
            // HSTS - HTTP Strict Transport Security
            'hsts' => [
                'enabled' => true,
                'max_age' => 31536000, // 1 year
                'include_subdomains' => true,
                'preload' => false,
            ],

            // CSP - Content Security Policy
            'csp' => [
                'enabled' => true,
                'report_only' => false,
                'directives' => [
                    'default-src' => ["'self'"],
                    'script-src' => ["'self'"],
                    'style-src' => ["'self'", "'unsafe-inline'"],
                    'img-src' => ["'self'", 'data:', 'https:'],
                    'font-src' => ["'self'"],
                    'connect-src' => ["'self'"],
                    'frame-ancestors' => ["'self'"],
                    'form-action' => ["'self'"],
                    'base-uri' => ["'self'"],
                    'object-src' => ["'none'"],
                ],
                'report_uri' => '',
            ],

            // X-Frame-Options (DENY, SAMEORIGIN, ALLOW-FROM uri)
            'frame_options' => 'SAMEORIGIN',

            // X-Content-Type-Options: nosniff
            'content_type_options' => true,

            // X-XSS-Protection (deprecated but still useful for old browsers)
            'xss_protection' => true,

            // Referrer-Policy
            'referrer_policy' => 'strict-origin-when-cross-origin',

            // Permissions-Policy (formerly Feature-Policy)
            'permissions_policy' => [
                'accelerometer' => [],
                'camera' => [],
                'geolocation' => [],
                'gyroscope' => [],
                'magnetometer' => [],
                'microphone' => [],
                'payment' => [],
                'usb' => [],
            ],

            // Cross-Origin-Embedder-Policy
            'coep' => '', // 'require-corp' or 'credentialless'

            // Cross-Origin-Opener-Policy
            'coop' => 'same-origin',

            // Cross-Origin-Resource-Policy
            'corp' => 'same-origin',

            // Cache-Control for sensitive pages
            'cache_control' => '',

            // Headers to remove
            'remove_headers' => [
                'X-Powered-By',
                'Server',
            ],

            // Custom headers
            'custom_headers' => [],
        ], $config);
    }

    /**
     * Process request and add security headers
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $response = $handler->handle($request);

        // Add security headers
        $response = $this->addHstsHeader($response, $request);
        $response = $this->addCspHeader($response);
        $response = $this->addFrameOptionsHeader($response);
        $response = $this->addContentTypeOptionsHeader($response);
        $response = $this->addXssProtectionHeader($response);
        $response = $this->addReferrerPolicyHeader($response);
        $response = $this->addPermissionsPolicyHeader($response);
        $response = $this->addCrossOriginHeaders($response);
        $response = $this->addCacheControlHeader($response);
        $response = $this->addCustomHeaders($response);
        $response = $this->removeUnsafeHeaders($response);

        return $response;
    }

    /**
     * Add HSTS header
     */
    private function addHstsHeader(ResponseInterface $response, ServerRequestInterface $request): ResponseInterface
    {
        $hsts = $this->config['hsts'];

        if (!$hsts['enabled']) {
            return $response;
        }

        // Only add HSTS on HTTPS
        $scheme = $request->getUri()->getScheme();
        if ($scheme !== 'https') {
            // Check for proxy headers
            $forwardedProto = $request->getHeaderLine('X-Forwarded-Proto');
            if ($forwardedProto !== 'https') {
                return $response;
            }
        }

        $value = "max-age={$hsts['max_age']}";

        if ($hsts['include_subdomains']) {
            $value .= '; includeSubDomains';
        }

        if ($hsts['preload']) {
            $value .= '; preload';
        }

        return $response->withHeader('Strict-Transport-Security', $value);
    }

    /**
     * Add CSP header
     */
    private function addCspHeader(ResponseInterface $response): ResponseInterface
    {
        $csp = $this->config['csp'];

        if (!$csp['enabled']) {
            return $response;
        }

        $directives = [];
        foreach ($csp['directives'] as $directive => $values) {
            if (is_array($values)) {
                $directives[] = $directive . ' ' . implode(' ', $values);
            } else {
                $directives[] = $directive . ' ' . $values;
            }
        }

        if (!empty($csp['report_uri'])) {
            $directives[] = 'report-uri ' . $csp['report_uri'];
        }

        $headerValue = implode('; ', $directives);
        $headerName = $csp['report_only']
            ? 'Content-Security-Policy-Report-Only'
            : 'Content-Security-Policy';

        return $response->withHeader($headerName, $headerValue);
    }

    /**
     * Add X-Frame-Options header
     */
    private function addFrameOptionsHeader(ResponseInterface $response): ResponseInterface
    {
        $value = $this->config['frame_options'];

        if (empty($value)) {
            return $response;
        }

        return $response->withHeader('X-Frame-Options', $value);
    }

    /**
     * Add X-Content-Type-Options header
     */
    private function addContentTypeOptionsHeader(ResponseInterface $response): ResponseInterface
    {
        if (!$this->config['content_type_options']) {
            return $response;
        }

        return $response->withHeader('X-Content-Type-Options', 'nosniff');
    }

    /**
     * Add X-XSS-Protection header
     */
    private function addXssProtectionHeader(ResponseInterface $response): ResponseInterface
    {
        if (!$this->config['xss_protection']) {
            return $response;
        }

        return $response->withHeader('X-XSS-Protection', '1; mode=block');
    }

    /**
     * Add Referrer-Policy header
     */
    private function addReferrerPolicyHeader(ResponseInterface $response): ResponseInterface
    {
        $value = $this->config['referrer_policy'];

        if (empty($value)) {
            return $response;
        }

        return $response->withHeader('Referrer-Policy', $value);
    }

    /**
     * Add Permissions-Policy header
     */
    private function addPermissionsPolicyHeader(ResponseInterface $response): ResponseInterface
    {
        $policies = $this->config['permissions_policy'];

        if (empty($policies)) {
            return $response;
        }

        $directives = [];
        foreach ($policies as $feature => $allowlist) {
            if (empty($allowlist)) {
                $directives[] = "{$feature}=()";
            } elseif ($allowlist === ['*']) {
                $directives[] = "{$feature}=*";
            } elseif ($allowlist === ['self']) {
                $directives[] = "{$feature}=(self)";
            } else {
                $quoted = array_map(fn($v) => $v === 'self' ? 'self' : "\"{$v}\"", $allowlist);
                $directives[] = "{$feature}=(" . implode(' ', $quoted) . ")";
            }
        }

        return $response->withHeader('Permissions-Policy', implode(', ', $directives));
    }

    /**
     * Add Cross-Origin headers
     */
    private function addCrossOriginHeaders(ResponseInterface $response): ResponseInterface
    {
        // COEP
        if (!empty($this->config['coep'])) {
            $response = $response->withHeader('Cross-Origin-Embedder-Policy', $this->config['coep']);
        }

        // COOP
        if (!empty($this->config['coop'])) {
            $response = $response->withHeader('Cross-Origin-Opener-Policy', $this->config['coop']);
        }

        // CORP
        if (!empty($this->config['corp'])) {
            $response = $response->withHeader('Cross-Origin-Resource-Policy', $this->config['corp']);
        }

        return $response;
    }

    /**
     * Add Cache-Control header
     */
    private function addCacheControlHeader(ResponseInterface $response): ResponseInterface
    {
        $value = $this->config['cache_control'];

        if (empty($value)) {
            return $response;
        }

        return $response->withHeader('Cache-Control', $value);
    }

    /**
     * Add custom headers
     */
    private function addCustomHeaders(ResponseInterface $response): ResponseInterface
    {
        foreach ($this->config['custom_headers'] as $name => $value) {
            $response = $response->withHeader($name, $value);
        }

        return $response;
    }

    /**
     * Remove unsafe headers
     */
    private function removeUnsafeHeaders(ResponseInterface $response): ResponseInterface
    {
        foreach ($this->config['remove_headers'] as $header) {
            $response = $response->withoutHeader($header);
        }

        return $response;
    }

    /**
     * Create preset configurations
     */
    public static function strict(): self
    {
        return new self([
            'hsts' => [
                'enabled' => true,
                'max_age' => 63072000, // 2 years
                'include_subdomains' => true,
                'preload' => true,
            ],
            'csp' => [
                'enabled' => true,
                'directives' => [
                    'default-src' => ["'none'"],
                    'script-src' => ["'self'"],
                    'style-src' => ["'self'"],
                    'img-src' => ["'self'"],
                    'font-src' => ["'self'"],
                    'connect-src' => ["'self'"],
                    'frame-ancestors' => ["'none'"],
                    'form-action' => ["'self'"],
                    'base-uri' => ["'self'"],
                    'object-src' => ["'none'"],
                    'upgrade-insecure-requests' => '',
                ],
            ],
            'frame_options' => 'DENY',
            'referrer_policy' => 'no-referrer',
            'coep' => 'require-corp',
            'coop' => 'same-origin',
            'corp' => 'same-origin',
            'cache_control' => 'no-store, no-cache, must-revalidate, proxy-revalidate',
        ]);
    }

    /**
     * Create balanced preset
     */
    public static function balanced(): self
    {
        return new self([
            'hsts' => [
                'enabled' => true,
                'max_age' => 31536000,
                'include_subdomains' => true,
                'preload' => false,
            ],
            'csp' => [
                'enabled' => true,
                'directives' => [
                    'default-src' => ["'self'"],
                    'script-src' => ["'self'", "'unsafe-inline'"],
                    'style-src' => ["'self'", "'unsafe-inline'"],
                    'img-src' => ["'self'", 'data:', 'https:'],
                    'font-src' => ["'self'", 'https:'],
                    'connect-src' => ["'self'"],
                    'frame-ancestors' => ["'self'"],
                    'form-action' => ["'self'"],
                    'base-uri' => ["'self'"],
                    'object-src' => ["'none'"],
                ],
            ],
            'frame_options' => 'SAMEORIGIN',
            'referrer_policy' => 'strict-origin-when-cross-origin',
            'coop' => 'same-origin-allow-popups',
            'corp' => 'same-site',
        ]);
    }

    /**
     * Create API preset (no CSP, optimized for APIs)
     */
    public static function api(): self
    {
        return new self([
            'hsts' => [
                'enabled' => true,
                'max_age' => 31536000,
                'include_subdomains' => true,
            ],
            'csp' => ['enabled' => false],
            'frame_options' => 'DENY',
            'referrer_policy' => 'no-referrer',
            'permissions_policy' => [],
            'coep' => '',
            'coop' => '',
            'corp' => 'same-origin',
            'cache_control' => 'no-store',
        ]);
    }

    /**
     * Generate nonce for CSP
     */
    public static function generateNonce(): string
    {
        return base64_encode(random_bytes(16));
    }

    /**
     * Add nonce to CSP script-src
     */
    public function withNonce(string $nonce): self
    {
        $config = $this->config;

        if (!isset($config['csp']['directives']['script-src'])) {
            $config['csp']['directives']['script-src'] = [];
        }

        $config['csp']['directives']['script-src'][] = "'nonce-{$nonce}'";

        return new self($config);
    }

    /**
     * Add hash to CSP script-src
     */
    public function withScriptHash(string $script, string $algorithm = 'sha256'): self
    {
        $hash = base64_encode(hash($algorithm, $script, true));
        $config = $this->config;

        if (!isset($config['csp']['directives']['script-src'])) {
            $config['csp']['directives']['script-src'] = [];
        }

        $config['csp']['directives']['script-src'][] = "'{$algorithm}-{$hash}'";

        return new self($config);
    }

    /**
     * Get current configuration
     */
    public function getConfig(): array
    {
        return $this->config;
    }
}
