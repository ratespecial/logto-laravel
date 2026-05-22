<?php

declare(strict_types=1);

namespace Ratespecial\Logto\Exceptions;

use Exception;

/**
 * Thrown when the OIDC discovery document or JWKS cannot be retrieved or is
 * malformed.
 */
class OidcDiscoveryException extends Exception {}
