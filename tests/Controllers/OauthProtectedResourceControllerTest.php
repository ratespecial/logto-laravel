<?php

declare(strict_types=1);

namespace Tests\Ratespecial\Logto\Controllers;

use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase;
use Ratespecial\Logto\LogtoServiceProvider;
use Ratespecial\Logto\Models\OidcDiscoveryDoc;
use Ratespecial\Logto\Services\OidcDiscoveryService;

class OauthProtectedResourceControllerTest extends TestCase
{
    /**
     * @param  Application  $app
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [LogtoServiceProvider::class];
    }

    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        $app['config']->set('logto', [
            'api-resource'      => 'https://api.example.com',
            'scopes-supported'  => 'mcp:use',
            'mcp'               => [
                'routes'                        => true,
                'scopes-supported'              => 'mcp:use',
                'protected-resource-middleware' => '',
            ],
        ]);
        $app['config']->set('services.logto', [
            'endpoint'     => 'https://tenant.logto.app',
            'api-resource' => 'https://api.example.com',
            'cache-ttl'    => 60,
        ]);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $doc          = new OidcDiscoveryDoc();
        $doc->issuer  = 'https://tenant.logto.app/oidc';

        $discovery = $this->createMock(OidcDiscoveryService::class);
        $discovery->method('get')->willReturn($doc);

        $this->app->instance(OidcDiscoveryService::class, $discovery);
    }

    public function testReturnsProtectedResourceMetadata(): void
    {
        $response = $this->getJson('/.well-known/oauth-protected-resource');

        $response->assertOk();
        $response->assertExactJson([
            'resource'              => 'https://api.example.com',
            'authorization_servers' => ['https://tenant.logto.app/oidc'],
            'scopes_supported'      => ['mcp:use'],
        ]);
    }

    public function testReturnsMetadataForNestedPath(): void
    {
        $response = $this->getJson('/.well-known/oauth-protected-resource/some/nested/path');

        $response->assertOk();
        $response->assertJsonPath('resource', 'https://api.example.com');
        $response->assertJsonPath('authorization_servers.0', 'https://tenant.logto.app/oidc');
    }

    public function testParsesSpaceDelimitedScopesIntoArray(): void
    {
        config(['logto.scopes-supported' => 'mcp:use read:foo write:bar']);

        $response = $this->getJson('/.well-known/oauth-protected-resource');

        $response->assertOk();
        $response->assertJsonPath('scopes_supported', ['mcp:use', 'read:foo', 'write:bar']);
    }
}
