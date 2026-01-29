<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Network;

/**
 * DNS Timeout Exception.
 *
 * Thrown when a DNS query exceeds the configured timeout.
 */
final class DNSTimeoutException extends \RuntimeException
{
}
