<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Storage;

use AdosLabs\EnterpriseSecurityShield\Contracts\LoggerInterface;

/**
 * Null Logger - No-Op Implementation.
 *
 * Silent logger that does nothing.
 * Use for development/testing when you don't want logs,
 * or as a fallback when no logger is configured.
 */
class NullLogger implements LoggerInterface
{
    public function emergency(string $message, array $context = []): void
    {
    }

    public function critical(string $message, array $context = []): void
    {
    }

    public function error(string $message, array $context = []): void
    {
    }

    public function warning(string $message, array $context = []): void
    {
    }

    public function info(string $message, array $context = []): void
    {
    }

    public function debug(string $message, array $context = []): void
    {
    }
}
