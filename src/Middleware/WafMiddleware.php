<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Middleware;

/**
 * WafMiddleware - Backward Compatibility Alias.
 *
 * @deprecated Use SecurityMiddleware instead. This class will be removed in v3.0.
 * @see SecurityMiddleware
 */
class_alias(SecurityMiddleware::class, 'AdosLabs\EnterpriseSecurityShield\Middleware\WafMiddleware');
