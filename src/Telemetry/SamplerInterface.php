<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Telemetry;

/**
 * Sampler Interface.
 *
 * Defines the contract for trace sampling strategies.
 */
interface SamplerInterface
{
    /**
     * Determine if a span should be sampled.
     *
     * @param string $spanName Span name
     * @param SpanKind $spanKind Span kind
     * @param array<string, mixed> $attributes Span attributes
     *
     * @return bool True if span should be recorded
     */
    public function shouldSample(string $spanName, SpanKind $spanKind, array $attributes): bool;
}
