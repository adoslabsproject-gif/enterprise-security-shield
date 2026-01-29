<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\CSRF;

/**
 * CSRF Validation Result.
 */
final class ValidationResult
{
    public function __construct(
        public readonly bool $valid,
        public readonly string $message,
    ) {
    }

    public function isValid(): bool
    {
        return $this->valid;
    }
}
