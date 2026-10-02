<?php

declare(strict_types=1);

namespace Ratespecial\Logto\Testing;

use Ratespecial\Logto\Models\OidcDiscoveryDoc;
use Ratespecial\Logto\Services\OidcDiscoveryService;

/**
 * Serves {@see LogtoFake}'s discovery document and JWKS without HTTP or cache.
 * Bound in place of {@see OidcDiscoveryService} while running unit tests (logto.testing.fake).
 */
class FakeOidcDiscoveryService extends OidcDiscoveryService
{
    public function __construct(
        public readonly LogtoFake $fake,
    ) {
        parent::__construct($fake->issuer, 0);
    }

    public function get(): OidcDiscoveryDoc
    {
        return OidcDiscoveryDoc::fromArray($this->fake->discoveryDoc());
    }

    /**
     * @return array<string, mixed>
     */
    public function getJwks(): array
    {
        return $this->fake->jwks();
    }
}
