<?php

namespace Senza1dio\SecurityShield\Contracts;

/**
 * Logger Interface - PSR-3 Compatible
 *
 * Allows SecurityShield to integrate with any logging system:
 * - Monolog
 * - Laravel Log
 * - Symfony Logger
 * - Custom loggers
 */
interface LoggerInterface
{
    /**
     * Log emergency event (system unusable)
     *
     * @param string $message
     * @param array<string, mixed> $context
     * @return void
     */
    public function emergency(string $message, array $context = []): void;

    /**
     * Log critical event (requires immediate action)
     *
     * @param string $message
     * @param array<string, mixed> $context
     * @return void
     */
    public function critical(string $message, array $context = []): void;

    /**
     * Log error event
     *
     * @param string $message
     * @param array<string, mixed> $context
     * @return void
     */
    public function error(string $message, array $context = []): void;

    /**
     * Log warning event
     *
     * @param string $message
     * @param array<string, mixed> $context
     * @return void
     */
    public function warning(string $message, array $context = []): void;

    /**
     * Log info event
     *
     * @param string $message
     * @param array<string, mixed> $context
     * @return void
     */
    public function info(string $message, array $context = []): void;

    /**
     * Log debug event
     *
     * @param string $message
     * @param array<string, mixed> $context
     * @return void
     */
    public function debug(string $message, array $context = []): void;
}
