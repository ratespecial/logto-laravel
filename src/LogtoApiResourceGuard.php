<?php

declare(strict_types=1);

namespace Ratespecial\Logto;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Ratespecial\Logto\Exceptions\OidcDiscoveryException;
use Ratespecial\Logto\Services\LogtoTokenValidator;
use Ratespecial\Logto\Services\UserResolver;
use Throwable;

/**
 * Ensures:
 * - JWT is valid and signed by Logto application
 * - JWT audience is this Laravel API
 * - JWT scope isn't blank, meaning they have permission to do at least one action here
 *
 * Will JIT provision a user if they don't exist (see {@see UserResolver})
 */
class LogtoApiResourceGuard implements Guard
{
    use GuardHelpers;

    public function __construct(
        private Request $request,
        private readonly LogtoTokenValidator $validator,
        private readonly UserResolver $resolver,
    ) {}

    public function user()
    {
        if ($this->user !== null) {
            return $this->user;
        }

        $claims = $this->resolveClaims();
        if ($claims === null) {
            return null;
        }

        $this->user = $this->resolver->resolve($claims);

        return $this->user;
    }

    /**
     * Swap in a new request and forget the user resolved from the previous one.
     */
    public function setRequest(Request $request): static
    {
        $this->request = $request;
        $this->user    = null;

        return $this;
    }

    /**
     * @param  array<string, mixed>  $credentials
     */
    public function validate(array $credentials = []): bool
    {
        return false;
    }

    /**
     * @return array<string, mixed>|null
     *
     * @throws OidcDiscoveryException
     */
    protected function resolveClaims(): ?array
    {
        $token = $this->request->bearerToken();
        if ($token === null) {
            return null;
        }

        try {
            $claims = $this->validator->validate($token);
        } catch (OidcDiscoveryException $ex) {
            // Something is likely wrong with the configuration.  Be loud about this so it's not confused with a bad login.
            throw $ex;
        } catch (Throwable $ex) {
            return $this->reject("invalid token: {$ex->getMessage()}");
        }

        if (empty($claims['sub'])) {
            return $this->reject('missing subject');
        }

        // User can get a token for any resource as long as it exists; require at least one scope here
        if (empty($claims['scope'])) {
            return $this->reject('empty scope');
        }

        return $claims;
    }

    protected function reject(string $reason): null
    {
        Log::debug("Logto JWT rejected: $reason");

        return null;
    }
}
