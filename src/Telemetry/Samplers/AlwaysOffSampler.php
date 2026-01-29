<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Telemetry\Samplers;

use AdosLabs\EnterpriseSecurityShield\Telemetry\SamplerInterface;
use AdosLabs\EnterpriseSecurityShield\Telemetry\SpanKind;

/**
 * Always Off Sampler.
 *
 * Never samples traces. Use in production when tracing is disabled.
 */
class AlwaysOffSampler implements SamplerInterface
{
    public function shouldSample(string $spanName, SpanKind $spanKind, array $attributes): bool
    {
        return false;
    }
}
