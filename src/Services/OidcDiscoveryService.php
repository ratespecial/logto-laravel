<?php

declare(strict_types=1);

namespace Ratespecial\Logto\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Ratespecial\Logto\Exceptions\OidcDiscoveryException;
use Ratespecial\Logto\Models\OidcDiscoveryDoc;

class OidcDiscoveryService
{
    /**
     * @var string Cache key for the JWKS document.
     */
    private const string JWKS_CACHE_KEY = 'logto.jwks';

    /**
     * @var string Cache key marking that a forced JWKS refresh happened recently.
     */
    private const string JWKS_REFRESH_LOCK_KEY = 'logto.jwks-refreshed';

    /**
     * @var int Minimum seconds between forced JWKS refreshes, so tokens with made-up key IDs can't make
     *          every request fetch from Logto.
     */
    private const int JWKS_REFRESH_COOLDOWN = 60;

    public function __construct(
        private readonly string $issuer,
        private readonly int $cacheTtl,
    ) {}

    /**
     * Fetch (and cache) Logto's OIDC discovery document.
     *
     * @throws OidcDiscoveryException
     */
    public function get(): OidcDiscoveryDoc
    {
        $data = Cache::remember('logto.oidc-discovery', $this->cacheTtl, function () {
            $url      = rtrim($this->issuer, '/') . '/.well-known/openid-configuration';
            $response = Http::get($url);

            if (! $response->successful()) {
                throw new OidcDiscoveryException('Failed to fetch Logto OIDC discovery document');
            }

            return $response->json();
        });

        return OidcDiscoveryDoc::fromArray($data);
    }

    /**
     * Fetch (and cache) the JSON Web Key Set advertised by the discovery document.
     *
     * @see https://datatracker.ietf.org/doc/html/rfc7517
     *
     * @return array<string, mixed>
     *
     * @throws OidcDiscoveryException
     */
    public function getJwks(): array
    {
        return Cache::remember(self::JWKS_CACHE_KEY, $this->cacheTtl, fn () => $this->fetchJwks());
    }

    /**
     * Refetch the JWKS, bypassing the cache. Called when a token names a key ID the cached set doesn't have,
     * which is what happens right after Logto rotates its signing key.
     *
     * At most one refresh runs per cooldown period; other calls get the cached set. If the fetch fails the
     * cached set is kept and returned, so the token is rejected as usual rather than erroring.
     *
     * @return array<string, mixed>
     *
     * @throws OidcDiscoveryException When nothing is cached and the JWKS can't be fetched.
     */
    public function refreshJwks(): array
    {
        if (! Cache::add(self::JWKS_REFRESH_LOCK_KEY, true, self::JWKS_REFRESH_COOLDOWN)) {
            return $this->getJwks();
        }

        try {
            $jwks = $this->fetchJwks();
        } catch (OidcDiscoveryException $ex) {
            Log::warning("Logto JWKS refresh failed: {$ex->getMessage()}");

            return $this->getJwks();
        }

        Cache::put(self::JWKS_CACHE_KEY, $jwks, $this->cacheTtl);

        return $jwks;
    }

    /**
     * @return array<string, mixed>
     *
     * @throws OidcDiscoveryException
     */
    private function fetchJwks(): array
    {
        $jwksUri = $this->get()->jwks_uri;

        if ($jwksUri === null) {
            throw new OidcDiscoveryException('OIDC discovery document has no jwks_uri');
        }

        $response = Http::get($jwksUri);

        if (! $response->successful()) {
            throw new OidcDiscoveryException('Failed to fetch Logto JWKS');
        }

        return $response->json();
    }
}
