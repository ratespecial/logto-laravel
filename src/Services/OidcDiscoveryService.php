<?php

declare(strict_types=1);

namespace Ratespecial\Logto\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Ratespecial\Logto\Exceptions\OidcDiscoveryException;
use Ratespecial\Logto\Models\OidcDiscoveryDoc;

class OidcDiscoveryService
{
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
        return Cache::remember('logto.jwks', $this->cacheTtl, function () {
            $jwksUri = $this->get()->jwks_uri;

            if ($jwksUri === null) {
                throw new OidcDiscoveryException('OIDC discovery document has no jwks_uri');
            }

            $response = Http::get($jwksUri);

            if (! $response->successful()) {
                throw new OidcDiscoveryException('Failed to fetch Logto JWKS');
            }

            return $response->json();
        });
    }
}
