<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\FileUpload;

/**
 * File Validation Result
 *
 * Immutable value object containing validation results.
 */
final class ValidationResult
{
    /**
     * @param bool $valid Whether the file passed validation
     * @param array<string> $errors List of validation errors
     * @param array<string> $warnings List of validation warnings
     * @param array<string, mixed> $metadata Additional metadata about the file
     */
    public function __construct(
        public readonly bool $valid,
        public readonly array $errors,
        public readonly array $warnings,
        public readonly array $metadata,
    ) {
    }

    /**
     * Check if validation passed
     */
    public function isValid(): bool
    {
        return $this->valid;
    }

    /**
     * Check if there are any warnings
     */
    public function hasWarnings(): bool
    {
        return !empty($this->warnings);
    }

    /**
     * Get first error message
     */
    public function getFirstError(): ?string
    {
        return $this->errors[0] ?? null;
    }

    /**
     * Get all error messages as string
     */
    public function getErrorsAsString(string $separator = '; '): string
    {
        return implode($separator, $this->errors);
    }

    /**
     * Get metadata value
     */
    public function getMeta(string $key, mixed $default = null): mixed
    {
        return $this->metadata[$key] ?? $default;
    }

    /**
     * Convert to array
     *
     * @return array{valid: bool, errors: array<string>, warnings: array<string>, metadata: array<string, mixed>}
     */
    public function toArray(): array
    {
        return [
            'valid' => $this->valid,
            'errors' => $this->errors,
            'warnings' => $this->warnings,
            'metadata' => $this->metadata,
        ];
    }

    /**
     * Convert to JSON
     */
    public function toJson(): string
    {
        return json_encode($this->toArray(), JSON_THROW_ON_ERROR);
    }
}
