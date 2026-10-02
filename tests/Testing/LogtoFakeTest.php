<?php

declare(strict_types=1);

namespace Tests\Ratespecial\Logto\Testing;

use Firebase\JWT\JWT;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;
use LogicException;
use Orchestra\Testbench\TestCase;
use Ratespecial\Logto\LogtoServiceProvider;
use Ratespecial\Logto\Services\OidcDiscoveryService;
use Ratespecial\Logto\Testing\FakeOidcDiscoveryService;
use Ratespecial\Logto\Testing\InteractsWithLogto;
use Ratespecial\Logto\Testing\LogtoFake;
use Tests\Ratespecial\Logto\Fixtures\TestUser;

class LogtoFakeTest extends TestCase
{
    use InteractsWithLogto;

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
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);
        $app['config']->set('logto.endpoint', 'https://tenant.logto.app');
        $app['config']->set('logto.api-resource', 'https://api.example.com');
        $app['config']->set('auth.guards.logto.provider', 'users');
        $app['config']->set('auth.providers.users.model', TestUser::class);
    }

    /**
     * @param  Router  $router
     */
    protected function defineRoutes($router): void
    {
        $router->middleware('auth:logto')->get('/me', function (Request $request) {
            /** @var TestUser $user */
            $user = $request->user('logto');

            return [
                'sub'      => $user->logto_sub,
                'canRead'  => $user->hasOAuthScope('user:read'),
                'canWrite' => $user->hasOAuthScope('user:write'),
            ];
        });
    }

    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('logto_sub')->nullable()->unique();
            $table->string('email')->nullable();
            $table->string('name')->nullable();
            $table->timestamps();
        });
    }

    public function testDiscoveryServiceIsFakedWhileRunningUnitTests(): void
    {
        $discovery = $this->app->make(OidcDiscoveryService::class);

        $this->assertInstanceOf(FakeOidcDiscoveryService::class, $discovery);
        $this->assertSame('https://tenant.logto.app/oidc', $discovery->get()->issuer);
    }

    public function testDiscoveryServiceIsRealWhenFakeIsDisabled(): void
    {
        config(['logto.testing.fake' => false]);

        $discovery = $this->app->make(OidcDiscoveryService::class);

        $this->assertNotInstanceOf(FakeOidcDiscoveryService::class, $discovery);
    }

    public function testFakeDoesNotNeedAnEndpoint(): void
    {
        config(['logto.endpoint' => '']);

        $discovery = $this->app->make(OidcDiscoveryService::class);

        $this->assertSame(LogtoFake::DEFAULT_ENDPOINT . '/oidc', $discovery->get()->issuer);
    }

    public function testActingAsLogtoRunsTheGuardAndProvisionsTheUser(): void
    {
        Http::fake();

        $this->actingAsLogto(['user:read'], ['sub' => 'alice', 'email' => 'alice@example.com'])
            ->getJson('/me')
            ->assertOk()
            ->assertExactJson(['sub' => 'alice', 'canRead' => true, 'canWrite' => false]);

        $this->assertSame('alice@example.com', TestUser::query()->where('logto_sub', 'alice')->value('email'));
        Http::assertNothingSent();
    }

    public function testRejectsTokenWithEmptyScope(): void
    {
        $this->actingAsLogto('')->getJson('/me')->assertUnauthorized();
    }

    public function testRejectsTokenForAnotherAudience(): void
    {
        $this->withToken($this->logtoToken(['aud' => 'https://other.example.com', 'scope' => 'user:read']))
            ->getJson('/me')
            ->assertUnauthorized();
    }

    public function testRejectsTokenSignedByAnotherKey(): void
    {
        $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($resource, $strangerKey);

        $token = JWT::encode([
            'iss'   => 'https://tenant.logto.app/oidc',
            'aud'   => 'https://api.example.com',
            'sub'   => 'mallory',
            'scope' => 'user:read',
        ], $strangerKey, 'RS256', LogtoFake::KID);

        $this->withToken($token)->getJson('/me')->assertUnauthorized();
    }

    public function testGuardFollowsEachRequestInATest(): void
    {
        $this->actingAsLogto('user:read', ['sub' => 'first'])->getJson('/me')->assertJson(['sub' => 'first']);
        $this->actingAsLogto('user:write', ['sub' => 'second'])->getJson('/me')->assertJson(['sub' => 'second', 'canWrite' => true]);
        $this->withoutToken()->getJson('/me')->assertUnauthorized();
    }

    public function testLogtoTokenThrowsWhenFakeIsDisabled(): void
    {
        config(['logto.testing.fake' => false]);

        $this->expectException(LogicException::class);

        $this->logtoToken();
    }
}
