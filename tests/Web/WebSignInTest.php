<?php

declare(strict_types=1);

namespace Tests\Ratespecial\Logto\Web;

use Firebase\JWT\JWT;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase;
use Ratespecial\Logto\Events\UserProvisionedEvent;
use Ratespecial\Logto\LogtoServiceProvider;
use Ratespecial\Logto\Services\LogtoWebClient;
use Tests\Ratespecial\Logto\Fixtures\TestUser;

class WebSignInTest extends TestCase
{
    private const string ENDPOINT = 'https://tenant.logto.app';

    private const string ISSUER   = 'https://tenant.logto.app/oidc';

    private const string APP_ID   = 'web-app-id';

    private const string SECRET   = 'web-app-secret';

    private const string KID      = 'test-key-1';

    private string $privateKey;

    /** @var array{keys: list<array<string, string>>} */
    private array $jwks;

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
        $app['config']->set('app.url', 'https://app.example.com');
        $app['config']->set('app.key', 'base64:' . base64_encode(random_bytes(32)));
        $app['config']->set('auth.providers.users.model', TestUser::class);
        $app['config']->set('logto.endpoint', self::ENDPOINT);
        $app['config']->set('logto.web', array_merge(config('logto.web') ?? [], [
            'routes'     => true,
            'app-id'     => self::APP_ID,
            'app-secret' => self::SECRET,
        ]));
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

        Event::fake([UserProvisionedEvent::class]);
        Cache::flush();

        $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($resource, $privateKey);
        $this->privateKey = $privateKey;

        $details    = openssl_pkey_get_details($resource);
        $this->jwks = ['keys' => [[
            'kty' => 'RSA',
            'kid' => self::KID,
            'use' => 'sig',
            'alg' => 'RS256',
            'n'   => self::base64Url($details['rsa']['n']),
            'e'   => self::base64Url($details['rsa']['e']),
        ]]];
    }

    public function testSignInRedirectsToLogtoWithPkceAndStoresFlowInSession(): void
    {
        $this->fakeLogto();

        $response = $this->get('https://app.example.com/logto/sign-in');

        $response->assertRedirect();
        $url = (string) $response->headers->get('Location');
        $this->assertStringStartsWith(self::ENDPOINT . '/oidc/auth?', $url);

        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        $flow = session('logto.web');

        $this->assertSame(self::APP_ID, $query['client_id']);
        $this->assertSame('https://app.example.com/logto/callback', $query['redirect_uri']);
        $this->assertSame('code', $query['response_type']);
        $this->assertSame('openid profile email', $query['scope']);
        $this->assertSame('S256', $query['code_challenge_method']);
        $this->assertSame(LogtoWebClient::codeChallenge($flow['verifier']), $query['code_challenge']);
        $this->assertSame($flow['state'], $query['state']);
        $this->assertSame($flow['nonce'], $query['nonce']);
        $this->assertArrayNotHasKey('resource', $query);
    }

    public function testSignInRequestsConfiguredResource(): void
    {
        config(['logto.web.resource' => 'https://api.example.com']);
        $this->fakeLogto();

        $url = (string) $this->get('https://app.example.com/logto/sign-in')->headers->get('Location');

        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        $this->assertSame('https://api.example.com', $query['resource']);
    }

    public function testCallbackProvisionsUserLogsInAndRedirectsToIntendedUrl(): void
    {
        $this->fakeLogto(['sub' => 'web-user', 'email' => 'alice@example.com', 'name' => 'Alice']);

        $response = $this->withSession(['logto.web' => $this->flow(), 'url.intended' => 'https://app.example.com/admin/dashboard'])
            ->get('https://app.example.com/logto/callback?code=abc&state=the-state');

        $response->assertRedirect('https://app.example.com/admin/dashboard');
        $this->assertAuthenticated();

        $user = Auth::user();
        $this->assertInstanceOf(TestUser::class, $user);
        $this->assertSame('alice@example.com', $user->email);
        $this->assertSame('Alice', $user->name);
        $this->assertSame('web-user', $user->logto_sub);
        Event::assertDispatchedTimes(UserProvisionedEvent::class, 1);

        Http::assertSent(function (Request $request) {
            if ($request->url() !== self::ENDPOINT . '/oidc/token') {
                return false;
            }

            $this->assertSame('Basic ' . base64_encode(self::APP_ID . ':' . self::SECRET), $request->header('Authorization')[0]);
            $this->assertSame('authorization_code', $request['grant_type']);
            $this->assertSame('abc', $request['code']);
            $this->assertSame('the-verifier', $request['code_verifier']);
            $this->assertSame('https://app.example.com/logto/callback', $request['redirect_uri']);

            return true;
        });
    }

    public function testCallbackRedirectsToConfiguredDefaultWhenNothingIntended(): void
    {
        config(['logto.web.redirect-after-login' => '/admin']);
        $this->fakeLogto();

        $this->withSession(['logto.web' => $this->flow()])
            ->get('https://app.example.com/logto/callback?code=abc&state=the-state')
            ->assertRedirect('/admin');
    }

    public function testCallbackLogsInExistingUserMatchedBySubject(): void
    {
        $existing = TestUser::query()->create(['logto_sub' => 'web-user', 'email' => 'old@example.com']);
        $this->fakeLogto(['sub' => 'web-user', 'email' => 'new@example.com']);

        $this->withSession(['logto.web' => $this->flow()])->get('https://app.example.com/logto/callback?code=abc&state=the-state');

        $this->assertAuthenticatedAs($existing);
        $this->assertSame('new@example.com', $existing->fresh()?->email);
        Event::assertNotDispatched(UserProvisionedEvent::class);
    }

    public function testCallbackLinksUnclaimedUserByEmailWhenEnabled(): void
    {
        config(['logto.link-unclaimed-by-email' => true]);
        $existing = TestUser::query()->create(['logto_sub' => null, 'email' => 'alice@example.com']);
        $this->fakeLogto(['sub' => 'web-user', 'email' => 'alice@example.com']);

        $this->withSession(['logto.web' => $this->flow()])->get('https://app.example.com/logto/callback?code=abc&state=the-state');

        $this->assertAuthenticatedAs($existing);
        $this->assertSame('web-user', $existing->fresh()?->logto_sub);
    }

    public function testCallbackRejectsStateMismatch(): void
    {
        $this->fakeLogto();

        $this->withSession(['logto.web' => $this->flow()])
            ->get('https://app.example.com/logto/callback?code=abc&state=wrong')
            ->assertForbidden();

        $this->assertGuest();
        Http::assertNotSent(fn (Request $request) => str_ends_with($request->url(), '/token'));
    }

    public function testCallbackRejectsMissingFlowInSession(): void
    {
        $this->fakeLogto();

        $this->get('https://app.example.com/logto/callback?code=abc&state=the-state')->assertForbidden();
    }

    public function testFlowIsSingleUse(): void
    {
        $this->fakeLogto();

        $this->withSession(['logto.web' => $this->flow()])->get('https://app.example.com/logto/callback?code=abc&state=wrong');

        $this->assertNull(session('logto.web'));
    }

    public function testCallbackSurfacesErrorReturnedByLogto(): void
    {
        $this->fakeLogto();

        $response = $this->withSession(['logto.web' => $this->flow()])
            ->get('https://app.example.com/logto/callback?state=the-state&error=access_denied&error_description=User+denied+access');

        $response->assertForbidden();
        $this->assertSame('Sign-in failed: User denied access', $response->exception?->getMessage());
        $this->assertGuest();
    }

    public function testCallbackRejectsFailedTokenExchange(): void
    {
        $this->fakeLogto(tokenStatus: 400);

        $this->withSession(['logto.web' => $this->flow()])
            ->get('https://app.example.com/logto/callback?code=abc&state=the-state')
            ->assertForbidden();

        $this->assertGuest();
    }

    public function testCallbackRejectsNonceMismatch(): void
    {
        $this->fakeLogto(['nonce' => 'someone-elses-nonce']);

        $this->withSession(['logto.web' => $this->flow()])
            ->get('https://app.example.com/logto/callback?code=abc&state=the-state')
            ->assertForbidden();

        $this->assertGuest();
    }

    public function testCallbackRejectsIdTokenForAnotherApp(): void
    {
        $this->fakeLogto(['aud' => 'some-other-app']);

        $this->withSession(['logto.web' => $this->flow()])
            ->get('https://app.example.com/logto/callback?code=abc&state=the-state')
            ->assertForbidden();

        $this->assertGuest();
    }

    public function testCallbackRejectsIdTokenFromWrongIssuer(): void
    {
        $this->fakeLogto(['iss' => 'https://evil.example.com/oidc']);

        $this->withSession(['logto.web' => $this->flow()])
            ->get('https://app.example.com/logto/callback?code=abc&state=the-state')
            ->assertForbidden();

        $this->assertGuest();
    }

    public function testCallbackRejectsExpiredIdToken(): void
    {
        $this->fakeLogto(['exp' => time() - 3600]);

        $this->withSession(['logto.web' => $this->flow()])
            ->get('https://app.example.com/logto/callback?code=abc&state=the-state')
            ->assertForbidden();

        $this->assertGuest();
    }

    public function testCallbackRejectsIdTokenSignedByUnknownKey(): void
    {
        $stranger = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($stranger, $strangerKey);
        $this->fakeLogto(signingKey: $strangerKey);

        $this->withSession(['logto.web' => $this->flow()])
            ->get('https://app.example.com/logto/callback?code=abc&state=the-state')
            ->assertForbidden();

        $this->assertGuest();
    }

    public function testCallbackRejectsUserWithoutEmailAndStoresNothing(): void
    {
        $this->fakeLogto(['email' => null]);

        $this->withSession(['logto.web' => $this->flow()])
            ->get('https://app.example.com/logto/callback?code=abc&state=the-state')
            ->assertForbidden();

        $this->assertGuest();
        $this->assertSame(0, TestUser::query()->count());
    }

    public function testCallbackProvisionsUserWithoutEmailWhenConfigured(): void
    {
        config(['logto.provision-without-email' => true]);
        $this->fakeLogto(['email' => null]);

        $this->withSession(['logto.web' => $this->flow()])->get('https://app.example.com/logto/callback?code=abc&state=the-state');

        $this->assertAuthenticated();
        $this->assertSame(1, TestUser::query()->count());
    }

    public function testResourceRequiresAccessTokenWithScope(): void
    {
        config(['logto.web.resource' => 'https://api.example.com']);
        $this->fakeLogto(accessClaims: ['aud' => 'https://api.example.com', 'scope' => 'orders:read']);

        $this->withSession(['logto.web' => $this->flow()])->get('https://app.example.com/logto/callback?code=abc&state=the-state');

        $user = Auth::user();
        $this->assertInstanceOf(TestUser::class, $user);
        $this->assertTrue($user->hasOAuthScope('orders:read'));
    }

    public function testResourceWithEmptyScopeIsRefused(): void
    {
        config(['logto.web.resource' => 'https://api.example.com']);
        $this->fakeLogto(accessClaims: ['aud' => 'https://api.example.com', 'scope' => '']);

        $this->withSession(['logto.web' => $this->flow()])
            ->get('https://app.example.com/logto/callback?code=abc&state=the-state')
            ->assertForbidden();

        $this->assertGuest();
        $this->assertSame(0, TestUser::query()->count());
    }

    public function testResourceWithoutAccessTokenIsRefused(): void
    {
        config(['logto.web.resource' => 'https://api.example.com']);
        $this->fakeLogto();

        $this->withSession(['logto.web' => $this->flow()])
            ->get('https://app.example.com/logto/callback?code=abc&state=the-state')
            ->assertForbidden();

        $this->assertGuest();
    }

    public function testSignOutLogsOutAndRedirectsToLogtoEndSession(): void
    {
        config(['logto.web.redirect-after-logout' => '/admin/login']);
        $this->fakeLogto();
        $user = TestUser::query()->create(['logto_sub' => 'web-user', 'email' => 'alice@example.com']);

        $response = $this->actingAs($user)->post('https://app.example.com/logto/sign-out');

        $this->assertGuest();
        $url = (string) $response->headers->get('Location');
        $this->assertStringStartsWith(self::ENDPOINT . '/oidc/session/end?', $url);

        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        $this->assertSame(self::APP_ID, $query['client_id']);
        $this->assertSame('https://app.example.com/admin/login', $query['post_logout_redirect_uri']);
    }

    public function testSignOutFallsBackToLocalRedirectWithoutEndSessionEndpoint(): void
    {
        $this->fakeLogto(discoveryOverrides: ['end_session_endpoint' => null]);

        $this->post('https://app.example.com/logto/sign-out')->assertRedirect('https://app.example.com');
    }

    public function testSignOutRequiresPost(): void
    {
        $this->get('https://app.example.com/logto/sign-out')->assertStatus(405);
    }

    public function testRoutesAreNamed(): void
    {
        $this->assertSame('/logto/sign-in', route('logto.sign-in', absolute: false));
        $this->assertSame('/logto/callback', route('logto.callback', absolute: false));
        $this->assertSame('/logto/sign-out', route('logto.sign-out', absolute: false));
    }

    /**
     * @return array{state: string, nonce: string, verifier: string}
     */
    private function flow(): array
    {
        return ['state' => 'the-state', 'nonce' => 'the-nonce', 'verifier' => 'the-verifier'];
    }

    /**
     * @param  array<string, mixed>  $idClaims  Overrides merged into the ID token claims (null removes a claim).
     * @param  array<string, mixed>|null  $accessClaims  When set, the token response includes an access token with these claims.
     * @param  array<string, mixed>  $discoveryOverrides
     */
    private function fakeLogto(
        array $idClaims = [],
        ?array $accessClaims = null,
        int $tokenStatus = 200,
        ?string $signingKey = null,
        array $discoveryOverrides = [],
    ): void {
        $signingKey ??= $this->privateKey;

        $idToken = JWT::encode(array_filter(array_merge([
            'iss'   => self::ISSUER,
            'aud'   => self::APP_ID,
            'sub'   => 'web-user',
            'email' => 'alice@example.com',
            'nonce' => 'the-nonce',
            'iat'   => time(),
            'exp'   => time() + 600,
        ], $idClaims), fn ($v) => $v !== null), $signingKey, 'RS256', self::KID);

        $tokens = ['id_token' => $idToken, 'token_type' => 'Bearer'];
        if ($accessClaims !== null) {
            $tokens['access_token'] = JWT::encode(array_merge([
                'iss' => self::ISSUER,
                'sub' => 'web-user',
                'exp' => time() + 600,
            ], $accessClaims), $signingKey, 'RS256', self::KID);
        }

        Http::fake([
            self::ISSUER . '/.well-known/openid-configuration' => Http::response(array_filter(array_merge([
                'issuer'                 => self::ISSUER,
                'authorization_endpoint' => self::ISSUER . '/auth',
                'token_endpoint'         => self::ISSUER . '/token',
                'end_session_endpoint'   => self::ISSUER . '/session/end',
                'jwks_uri'               => self::ISSUER . '/jwks',
            ], $discoveryOverrides), fn ($v) => $v !== null)),
            self::ISSUER . '/jwks'                             => Http::response($this->jwks),
            self::ISSUER . '/token'                            => Http::response($tokenStatus === 200 ? $tokens : ['error' => 'invalid_grant'], $tokenStatus),
        ]);
    }

    private static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
