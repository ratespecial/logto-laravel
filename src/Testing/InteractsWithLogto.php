<?php

declare(strict_types=1);

namespace Ratespecial\Logto\Testing;

use Illuminate\Foundation\Testing\TestCase;
use LogicException;
use Ratespecial\Logto\Services\OidcDiscoveryService;

/**
 * For a host app's TestCase. Sends requests with a real, signed Logto access token, so the full
 * `logto` guard path runs: signature, issuer, audience, scope check and JIT provisioning.
 *
 * Use actingAs($user, 'logto') instead when the test doesn't care about the token path.
 *
 * @mixin TestCase
 */
trait InteractsWithLogto
{
    /**
     * Send subsequent requests with a Bearer token carrying the given scopes.
     *
     * @param  string|list<string>  $scopes  Must not be empty; the guard rejects tokens without scopes.
     * @param  array<string, mixed>  $claims  Extra/overriding claims, e.g. sub, email, name.
     */
    public function actingAsLogto(string|array $scopes, array $claims = []): static
    {
        $claims['scope'] = is_array($scopes) ? implode(' ', $scopes) : $scopes;

        return $this->withToken($this->logtoToken($claims));
    }

    /**
     * Sign a Logto access token the faked discovery service will accept.
     *
     * @param  array<string, mixed>  $claims
     */
    public function logtoToken(array $claims = []): string
    {
        $discovery = $this->app->make(OidcDiscoveryService::class);

        if (! $discovery instanceof FakeOidcDiscoveryService) {
            throw new LogicException('Logto is not faked. Signed test tokens need logto.testing.fake enabled while running unit tests.');
        }

        return $discovery->fake->token($claims);
    }
}
