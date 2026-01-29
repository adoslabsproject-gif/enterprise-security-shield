<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Telemetry\Samplers;

use AdosLabs\EnterpriseSecurityShield\Telemetry\SamplerInterface;
use AdosLabs\EnterpriseSecurityShield\Telemetry\SpanKind;

/**
 * Always On Sampler.
 *
 * Samples all traces. Use in development or when complete tracing is needed.
 */
class AlwaysOnSampler implements SamplerInterface
{
    public function shouldSample(string $spanName, SpanKind $spanKind, array $attributes): bool
    {
        return true;
    }
}
