<?php

declare(strict_types=1);

namespace Tests\Ratespecial\Logto\Services;

use Illuminate\Foundation\Application;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;
use Ratespecial\Logto\Exceptions\OidcDiscoveryException;
use Ratespecial\Logto\Services\OidcDiscoveryService;

class OidcDiscoveryServiceTest extends TestCase
{
    private const string ISSUER = 'https://logto.example.com/oidc';

    private const string JWKS_URI = self::ISSUER . '/jwks';

    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        $app['config']->set('cache.default', 'array');
    }

    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();
    }

    public function testGetJwksCachesTheKeySet(): void
    {
        $this->fakeLogto(Http::sequence()->push(self::jwks('key-1'))->push(self::jwks('key-2')));

        $service = $this->makeService();

        $first  = $service->getJwks();
        $second = $service->getJwks();

        $this->assertSame('key-1', $first['keys'][0]['kid']);
        $this->assertSame('key-1', $second['keys'][0]['kid']);
        $this->assertSame(1, $this->jwksFetchCount());
    }

    public function testRefreshJwksBypassesAndUpdatesTheCache(): void
    {
        $this->fakeLogto(Http::sequence()->push(self::jwks('key-1'))->push(self::jwks('key-2')));

        $service = $this->makeService();
        $service->getJwks();

        $this->assertSame('key-2', $service->refreshJwks()['keys'][0]['kid']);
        $this->assertSame('key-2', $service->getJwks()['keys'][0]['kid']);
        $this->assertSame(2, $this->jwksFetchCount());
    }

    public function testRefreshJwksIsRateLimited(): void
    {
        $this->fakeLogto(Http::sequence()
            ->push(self::jwks('key-1'))
            ->push(self::jwks('key-2'))
            ->push(self::jwks('key-3')));

        $service = $this->makeService();
        $service->getJwks();
        $service->refreshJwks();

        // Within the cooldown, a second refresh serves the cache instead of fetching.
        $this->assertSame('key-2', $service->refreshJwks()['keys'][0]['kid']);
        $this->assertSame(2, $this->jwksFetchCount());

        $this->travel(61)->seconds();

        $this->assertSame('key-3', $service->refreshJwks()['keys'][0]['kid']);
        $this->assertSame(3, $this->jwksFetchCount());
    }

    public function testRefreshJwksKeepsCachedSetWhenFetchFails(): void
    {
        $this->fakeLogto(Http::sequence()->push(self::jwks('key-1'))->push('down', 503));

        $service = $this->makeService();
        $service->getJwks();

        $this->assertSame('key-1', $service->refreshJwks()['keys'][0]['kid']);
        $this->assertSame('key-1', $service->getJwks()['keys'][0]['kid']);
    }

    public function testRefreshJwksThrowsWhenFetchFailsAndNothingIsCached(): void
    {
        $this->fakeLogto(Http::sequence()->push('down', 503)->push('down', 503));

        $this->expectException(OidcDiscoveryException::class);

        $this->makeService()->refreshJwks();
    }

    private function makeService(): OidcDiscoveryService
    {
        return new OidcDiscoveryService(self::ISSUER, 600);
    }

    private function fakeLogto(mixed $jwksResponses): void
    {
        Http::fake([
            self::ISSUER . '/.well-known/openid-configuration' => Http::response([
                'issuer'   => self::ISSUER,
                'jwks_uri' => self::JWKS_URI,
            ]),
            self::JWKS_URI => $jwksResponses,
        ]);
    }

    private function jwksFetchCount(): int
    {
        return Http::recorded(fn (Request $request) => $request->url() === self::JWKS_URI)->count();
    }

    /**
     * @return array{keys: list<array{kid: string}>}
     */
    private static function jwks(string $kid): array
    {
        return ['keys' => [['kid' => $kid]]];
    }
}
