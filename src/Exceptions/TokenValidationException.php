<?php

declare(strict_types=1);

namespace Ratespecial\Logto\Exceptions;

use Exception;

/**
 * Thrown when an access token fails validation (bad issuer, bad audience, bad signature, etc.).
 */
class TokenValidationException extends Exception {}
