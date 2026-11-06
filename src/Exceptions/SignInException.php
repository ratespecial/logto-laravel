<?php

declare(strict_types=1);

namespace Ratespecial\Logto\Exceptions;

use Symfony\Component\HttpKernel\Exception\HttpException;
use Throwable;

/**
 * Thrown by the web sign-in callback when the flow can't complete (state mismatch, Logto returned an
 * error, token exchange failed, invalid ID token, user not allowed).  Renders as a 403.
 *
 * The message is safe to show to the user. When `app.debug` is on, the developer detail (if any) is appended to it
 * so the cause shows on the 403 page; {@see $detail} is always available to custom renderers.
 *
 * Host apps can customise the response with `$exceptions->render(fn (SignInException $e) => ...)`.
 */
class SignInException extends HttpException
{
    /**
     * @param  string  $message  Safe to show to the user.
     * @param  string|null  $detail  Developer-facing cause, e.g. which configuration to check. Shown only in debug mode.
     */
    public function __construct(string $message, ?Throwable $previous = null, public readonly ?string $detail = null)
    {
        $shown = config('app.debug') && $detail !== null ? "{$message} ({$detail})" : $message;

        parent::__construct(403, $shown, $previous);
    }

    /**
     * @return array<string, mixed>
     */
    public function context(): array
    {
        return $this->detail === null ? [] : ['detail' => $this->detail];
    }
}
