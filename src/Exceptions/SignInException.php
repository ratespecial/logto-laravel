<?php

declare(strict_types=1);

namespace Ratespecial\Logto\Exceptions;

use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * Thrown by the web sign-in callback when the flow can't complete (state mismatch, Logto returned an
 * error, token exchange failed, invalid ID token, user not allowed).  Renders as a 403 with a message that is safe to show.
 *
 * Host apps can customise the response with `$exceptions->render(fn (SignInException $e) => ...)`.
 */
class SignInException extends HttpException
{
    public function __construct(string $message, ?\Throwable $previous = null)
    {
        parent::__construct(403, $message, $previous);
    }
}
