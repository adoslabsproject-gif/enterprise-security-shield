<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Telemetry\Metrics;

/**
 * OpenTelemetry Metric Types.
 */
enum MetricType: string
{
    /**
     * Counter - monotonically increasing value.
     */
    case COUNTER = 'counter';

    /**
     * UpDownCounter - value that can increase or decrease.
     */
    case UP_DOWN_COUNTER = 'up_down_counter';

    /**
     * Gauge - point-in-time value.
     */
    case GAUGE = 'gauge';

    /**
     * Histogram - distribution of values.
     */
    case HISTOGRAM = 'histogram';
}
