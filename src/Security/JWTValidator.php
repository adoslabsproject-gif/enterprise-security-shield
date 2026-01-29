<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Security;

/**
 * JWT Security Validator.
 *
 * Validates JWT tokens and detects common JWT attacks:
 * - Algorithm confusion (alg:none, RS256→HS256)
 * - Key confusion attacks
 * - Claim tampering
 * - Expired/not-yet-valid tokens
 * - Weak signatures
 *
 * IMPORTANT: This is a SECURITY VALIDATOR, not a full JWT library.
 * Use firebase/php-jwt or lcobucci/jwt for actual JWT handling.
 * This class provides additional security checks on top of those libraries.
 */
final class JWTValidator
{
    /**
     * Allowed algorithms (whitelist approach).
     *
     * @var array<string>
     */
    private array $allowedAlgorithms = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'];

    /**
     * Dangerous algorithms that should NEVER be allowed.
     *
     * @var array<string>
     */
    private const DANGEROUS_ALGORITHMS = ['none', 'None', 'NONE', 'nOnE'];

    /**
     * Required claims.
     *
     * @var array<string>
     */
    private array $requiredClaims = ['exp', 'iat'];

    /**
     * Maximum token age in seconds.
     */
    private int $maxTokenAge = 86400; // 24 hours

    /**
     * Clock skew tolerance in seconds.
     */
    private int $clockSkew = 60;

    /**
     * Constructor.
     *
     * @param array<string, mixed> $config Configuration options
     */
    public function __construct(array $config = [])
    {
        if (isset($config['allowed_algorithms'])) {
            $this->allowedAlgorithms = $config['allowed_algorithms'];
        }
        if (isset($config['required_claims'])) {
            $this->requiredClaims = $config['required_claims'];
        }
        if (isset($config['max_token_age'])) {
            $this->maxTokenAge = $config['max_token_age'];
        }
        if (isset($config['clock_skew'])) {
            $this->clockSkew = $config['clock_skew'];
        }
    }

    /**
     * Validate JWT token for security issues.
     *
     * NOTE: This does NOT verify the signature - use a JWT library for that.
     * This validates the token structure and claims for security issues.
     *
     * @param string $token JWT token
     *
     * @return array{
     *     valid: bool,
     *     errors: array<string>,
     *     warnings: array<string>,
     *     header: array<string, mixed>|null,
     *     payload: array<string, mixed>|null,
     *     attacks_detected: array<string>
     * }
     */
    public function validate(string $token): array
    {
        $errors = [];
        $warnings = [];
        $attacksDetected = [];
        $header = null;
        $payload = null;

        // Parse token
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            $errors[] = 'Invalid JWT format - expected 3 parts';

            return [
                'valid' => false,
                'errors' => $errors,
                'warnings' => $warnings,
                'header' => null,
                'payload' => null,
                'attacks_detected' => $attacksDetected,
            ];
        }

        [$headerB64, $payloadB64, $signatureB64] = $parts;

        // Decode header
        $headerJson = $this->base64UrlDecode($headerB64);
        if ($headerJson === false) {
            $errors[] = 'Invalid base64 encoding in header';

            return $this->buildResult(false, $errors, $warnings, null, null, $attacksDetected);
        }

        $header = json_decode($headerJson, true);
        if (!is_array($header)) {
            $errors[] = 'Invalid JSON in header';

            return $this->buildResult(false, $errors, $warnings, null, null, $attacksDetected);
        }

        // Decode payload
        $payloadJson = $this->base64UrlDecode($payloadB64);
        if ($payloadJson === false) {
            $errors[] = 'Invalid base64 encoding in payload';

            return $this->buildResult(false, $errors, $warnings, $header, null, $attacksDetected);
        }

        $payload = json_decode($payloadJson, true);
        if (!is_array($payload)) {
            $errors[] = 'Invalid JSON in payload';

            return $this->buildResult(false, $errors, $warnings, $header, null, $attacksDetected);
        }

        // Security Check 1: Algorithm validation (CRITICAL)
        $alg = $header['alg'] ?? null;

        if ($alg === null) {
            $errors[] = 'Missing algorithm in header';
            $attacksDetected[] = 'MISSING_ALGORITHM';
        } elseif (in_array($alg, self::DANGEROUS_ALGORITHMS, true)) {
            $errors[] = "CRITICAL: Algorithm 'none' detected - this is an attack!";
            $attacksDetected[] = 'ALG_NONE_ATTACK';
        } elseif (!in_array($alg, $this->allowedAlgorithms, true)) {
            $errors[] = "Algorithm '{$alg}' not in allowed list";
            $attacksDetected[] = 'DISALLOWED_ALGORITHM';
        }

        // Security Check 2: Algorithm confusion attack detection
        if ($alg !== null && $this->detectAlgorithmConfusion($alg, $signatureB64)) {
            $warnings[] = 'Possible algorithm confusion attack detected';
            $attacksDetected[] = 'ALG_CONFUSION';
        }

        // Security Check 3: Required claims
        foreach ($this->requiredClaims as $claim) {
            if (!isset($payload[$claim])) {
                $errors[] = "Missing required claim: {$claim}";
            }
        }

        // Security Check 4: Expiration (exp)
        if (isset($payload['exp'])) {
            $exp = (int) $payload['exp'];
            $now = time();

            if ($exp < ($now - $this->clockSkew)) {
                $errors[] = 'Token has expired';
            }
        }

        // Security Check 5: Not Before (nbf)
        if (isset($payload['nbf'])) {
            $nbf = (int) $payload['nbf'];
            $now = time();

            if ($nbf > ($now + $this->clockSkew)) {
                $errors[] = 'Token not yet valid (nbf claim)';
            }
        }

        // Security Check 6: Issued At (iat) - check for future or too old
        if (isset($payload['iat'])) {
            $iat = (int) $payload['iat'];
            $now = time();

            if ($iat > ($now + $this->clockSkew)) {
                $warnings[] = 'Token issued in the future - possible clock skew or tampering';
                $attacksDetected[] = 'FUTURE_IAT';
            }

            if (($now - $iat) > $this->maxTokenAge) {
                $warnings[] = 'Token is older than maximum allowed age';
            }
        }

        // Security Check 7: JTI (JWT ID) for replay protection
        if (!isset($payload['jti'])) {
            $warnings[] = 'No jti claim - replay attacks possible';
        }

        // Security Check 8: Suspicious claims
        $suspiciousClaims = $this->detectSuspiciousClaims($payload);
        if (!empty($suspiciousClaims)) {
            $warnings[] = 'Suspicious claims detected: ' . implode(', ', $suspiciousClaims);
            $attacksDetected[] = 'SUSPICIOUS_CLAIMS';
        }

        // Security Check 9: Signature presence
        if ($signatureB64 === '') {
            $errors[] = 'Missing signature';
            $attacksDetected[] = 'MISSING_SIGNATURE';
        }

        // Security Check 10: Header injection
        if ($this->detectHeaderInjection($header)) {
            $errors[] = 'Possible header injection attack';
            $attacksDetected[] = 'HEADER_INJECTION';
        }

        return $this->buildResult(
            empty($errors),
            $errors,
            $warnings,
            $header,
            $payload,
            $attacksDetected,
        );
    }

    /**
     * Detect algorithm confusion attacks.
     *
     * RS256 → HS256 attack: attacker uses public key as HMAC secret.
     */
    private function detectAlgorithmConfusion(string $alg, string $signature): bool
    {
        // If algorithm is HS* but signature looks like RSA length
        if (str_starts_with($alg, 'HS')) {
            $sigBytes = strlen($this->base64UrlDecode($signature) ?: '');

            // RSA signatures are typically 256, 384, or 512 bytes
            // HMAC-SHA signatures are 32, 48, or 64 bytes
            if ($sigBytes >= 128) {
                return true; // Suspicious - HMAC with RSA-length signature
            }
        }

        return false;
    }

    /**
     * Detect suspicious claims that might indicate tampering.
     *
     * @return array<string>
     */
    private function detectSuspiciousClaims(array $payload): array
    {
        $suspicious = [];

        // Admin/role escalation attempts
        $roleKeys = ['admin', 'role', 'roles', 'is_admin', 'isAdmin', 'permissions'];
        foreach ($roleKeys as $key) {
            if (isset($payload[$key])) {
                $value = $payload[$key];
                if ($value === true || $value === 'admin' || $value === 'root' || $value === 'superuser') {
                    $suspicious[] = $key;
                }
                if (is_array($value) && (in_array('admin', $value, true) || in_array('root', $value, true))) {
                    $suspicious[] = $key;
                }
            }
        }

        // User ID manipulation
        if (isset($payload['sub']) && ($payload['sub'] === '0' || $payload['sub'] === 0 || $payload['sub'] === '1' || $payload['sub'] === 1)) {
            $suspicious[] = 'sub (common admin IDs)';
        }

        return $suspicious;
    }

    /**
     * Detect header injection attacks.
     */
    private function detectHeaderInjection(array $header): bool
    {
        // JKU (JWK Set URL) injection
        if (isset($header['jku'])) {
            $jku = $header['jku'];
            // Check for suspicious domains
            if (
                str_contains($jku, 'localhost') ||
                str_contains($jku, '127.0.0.1') ||
                str_contains($jku, '0.0.0.0') ||
                preg_match('/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/', $jku)
            ) {
                return true;
            }
        }

        // X5U (X.509 URL) injection
        if (isset($header['x5u'])) {
            return true; // Generally dangerous - requires strict validation
        }

        // JWK embedded key (could be attacker's key)
        if (isset($header['jwk'])) {
            return true; // Embedded keys are dangerous
        }

        return false;
    }

    /**
     * Base64 URL decode.
     *
     * @return string|false
     */
    private function base64UrlDecode(string $data): string|false
    {
        $padding = strlen($data) % 4;
        if ($padding > 0) {
            $data .= str_repeat('=', 4 - $padding);
        }

        return base64_decode(strtr($data, '-_', '+/'), true);
    }

    /**
     * Build result array.
     *
     * @return array{
     *     valid: bool,
     *     errors: array<string>,
     *     warnings: array<string>,
     *     header: array<string, mixed>|null,
     *     payload: array<string, mixed>|null,
     *     attacks_detected: array<string>
     * }
     */
    private function buildResult(
        bool $valid,
        array $errors,
        array $warnings,
        ?array $header,
        ?array $payload,
        array $attacksDetected,
    ): array {
        return [
            'valid' => $valid,
            'errors' => $errors,
            'warnings' => $warnings,
            'header' => $header,
            'payload' => $payload,
            'attacks_detected' => $attacksDetected,
        ];
    }

    /**
     * Set allowed algorithms.
     *
     * @param array<string> $algorithms
     */
    public function setAllowedAlgorithms(array $algorithms): self
    {
        // Never allow 'none'
        $this->allowedAlgorithms = array_filter(
            $algorithms,
            fn ($alg) => !in_array(strtolower($alg), ['none'], true),
        );

        return $this;
    }

    /**
     * Set required claims.
     *
     * @param array<string> $claims
     */
    public function setRequiredClaims(array $claims): self
    {
        $this->requiredClaims = $claims;

        return $this;
    }
}
