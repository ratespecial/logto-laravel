<?php

declare(strict_types=1);

namespace Tests\Ratespecial\Logto;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase;
use Ratespecial\Logto\Events\UserProvisionedEvent;
use Ratespecial\Logto\Exceptions\TokenValidationException;
use Ratespecial\Logto\LogtoApiResourceGuard;
use Ratespecial\Logto\LogtoServiceProvider;
use Ratespecial\Logto\Services\LogtoTokenValidator;
use Ratespecial\Logto\Services\UserResolver;
use Tests\Ratespecial\Logto\Fixtures\TestUser;

class LogtoApiResourceGuardTest extends TestCase
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
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);
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
    }

    public function testReturnsNullWhenNoBearerToken(): void
    {
        $guard = $this->makeGuard(new Request(), $this->createMock(LogtoTokenValidator::class));

        $this->assertNull($guard->user());
    }

    public function testReturnsNullWhenValidatorRejectsToken(): void
    {
        $validator = $this->createMock(LogtoTokenValidator::class);
        $validator->method('validate')->willThrowException(new TokenValidationException('Invalid token issuer'));

        $guard = $this->makeGuard($this->makeRequestWithToken('bad.token.here'), $validator);

        $this->assertNull($guard->user());
    }

    public function testReturnsNullWhenSubjectClaimIsMissing(): void
    {
        $validator = $this->createMock(LogtoTokenValidator::class);
        $validator->method('validate')->willReturn(['scope' => 'user:read']);

        $guard = $this->makeGuard($this->makeRequestWithToken('a.b.c'), $validator);

        $this->assertNull($guard->user());
    }

    public function testReturnsNullWhenScopeClaimIsEmpty(): void
    {
        $validator = $this->createMock(LogtoTokenValidator::class);
        $validator->method('validate')->willReturn(['sub' => 'user-123', 'scope' => '']);

        $guard = $this->makeGuard($this->makeRequestWithToken('a.b.c'), $validator);

        $this->assertNull($guard->user());
    }

    public function testProvisionsUserUsingConfiguredAttributeMapping(): void
    {
        $validator = $this->createMock(LogtoTokenValidator::class);
        $validator->method('validate')->willReturn([
            'sub'   => 'user-123',
            'scope' => 'user:read user:write',
            'email' => 'alice@example.com',
            'name'  => 'Alice',
        ]);

        $guard = $this->makeGuard(
            $this->makeRequestWithToken('a.b.c'),
            $validator,
            ['email' => 'email', 'name' => 'name'],
        );

        /** @var TestUser $user */
        $user = $guard->user();

        $this->assertInstanceOf(TestUser::class, $user);
        $this->assertSame('alice@example.com', $user->email);
        $this->assertSame('Alice', $user->name);
        $this->assertSame('user-123', $user->logto_sub);
        $this->assertTrue($user->hasOAuthScope('user:read'));
        $this->assertTrue($user->hasOAuthScope('user:write'));
        $this->assertFalse($user->hasOAuthScope('admin'));
    }

    public function testDispatchesProvisionedEventOnlyForNewlyCreatedUsers(): void
    {
        $claims = [
            'sub'   => 'user-456',
            'scope' => 'user:read',
            'email' => 'bob@example.com',
        ];

        $validator = $this->createMock(LogtoTokenValidator::class);
        $validator->method('validate')->willReturn($claims);

        // First request — user does not yet exist.
        $this->makeGuard(
            $this->makeRequestWithToken('a.b.c'),
            $validator,
            ['email' => 'email'],
        )->user();

        Event::assertDispatchedTimes(UserProvisionedEvent::class, 1);

        // Second request with the same subject — existing record, no new event.
        $this->makeGuard(
            $this->makeRequestWithToken('a.b.c'),
            $validator,
            ['email' => 'email'],
        )->user();

        Event::assertDispatchedTimes(UserProvisionedEvent::class, 1);
    }

    public function testSkipsClaimsThatAreMissingFromTheToken(): void
    {
        $validator = $this->createMock(LogtoTokenValidator::class);
        $validator->method('validate')->willReturn([
            'sub'   => 'user-789',
            'scope' => 'user:read',
            'email' => 'carol@example.com',
            // intentionally no 'name'
        ]);

        $guard = $this->makeGuard(
            $this->makeRequestWithToken('a.b.c'),
            $validator,
            ['email' => 'email', 'name' => 'name'],
        );

        /** @var TestUser $user */
        $user = $guard->user();

        $this->assertSame('carol@example.com', $user->email);
        $this->assertNull($user->name);
    }

    public function testCachesUserAcrossRepeatedCalls(): void
    {
        $validator = $this->createMock(LogtoTokenValidator::class);
        // validate() should only be called once even when user() is called multiple times.
        $validator->expects($this->once())
            ->method('validate')
            ->willReturn(['sub' => 'user-cache', 'scope' => 'user:read']);

        $guard = $this->makeGuard($this->makeRequestWithToken('a.b.c'), $validator);

        $first  = $guard->user();
        $second = $guard->user();

        $this->assertNotNull($first);
        $this->assertSame($first, $second);
    }

    public function testLinksUnclaimedUserByEmailWhenEnabled(): void
    {
        config(['logto.link-unclaimed-by-email' => true]);
        $existing = TestUser::query()->create(['logto_sub' => null, 'email' => 'dave@example.com']);

        $user = $this->resolveWithEmailClaim('new-tenant-sub', 'dave@example.com');

        $this->assertSame($existing->getKey(), $user->getKey());
        $this->assertSame('new-tenant-sub', $user->logto_sub);
        $this->assertSame(1, TestUser::query()->count());
        Event::assertNotDispatched(UserProvisionedEvent::class);
    }

    public function testDoesNotLinkUnclaimedUserWhenDisabled(): void
    {
        $existing = TestUser::query()->create(['logto_sub' => null, 'email' => 'dave@example.com']);

        $user = $this->resolveWithEmailClaim('new-tenant-sub', 'dave@example.com');

        $this->assertNotSame($existing->getKey(), $user->getKey());
        $this->assertNull($existing->fresh()?->logto_sub);
    }

    public function testDoesNotLinkUserThatAlreadyHasASubject(): void
    {
        config(['logto.link-unclaimed-by-email' => true]);
        $existing = TestUser::query()->create(['logto_sub' => 'other-sub', 'email' => 'dave@example.com']);

        $user = $this->resolveWithEmailClaim('new-tenant-sub', 'dave@example.com');

        $this->assertNotSame($existing->getKey(), $user->getKey());
        $this->assertSame('other-sub', $existing->fresh()?->logto_sub);
    }

    public function testDoesNotLinkWhenTokenHasNoEmailClaim(): void
    {
        config(['logto.link-unclaimed-by-email' => true]);
        $existing = TestUser::query()->create(['logto_sub' => null, 'email' => null]);

        $user = $this->resolveWithEmailClaim('new-tenant-sub', null);

        $this->assertNotSame($existing->getKey(), $user->getKey());
        $this->assertNull($existing->fresh()?->logto_sub);
    }

    public function testDoesNotPersistUserWithoutEmailButStillAuthenticates(): void
    {
        $user = $this->resolveWithEmailClaim('m2m-sub', null);

        $this->assertFalse($user->exists);
        $this->assertSame('m2m-sub', $user->logto_sub);
        $this->assertTrue($user->hasOAuthScope('user:read'));
        $this->assertSame(0, TestUser::query()->count());
        Event::assertNotDispatched(UserProvisionedEvent::class);
    }

    public function testProvisionsUserWithoutEmailWhenConfigured(): void
    {
        config(['logto.provision-without-email' => true]);

        $user = $this->resolveWithEmailClaim('m2m-sub', null);

        $this->assertTrue($user->exists);
        $this->assertSame(1, TestUser::query()->count());
        Event::assertDispatchedTimes(UserProvisionedEvent::class, 1);
    }

    public function testStillUpdatesExistingUserMatchedBySubjectWhenTokenHasNoEmail(): void
    {
        $existing = TestUser::query()->create(['logto_sub' => 'known-sub', 'email' => 'eve@example.com']);

        $user = $this->resolveWithEmailClaim('known-sub', null);

        $this->assertSame($existing->getKey(), $user->getKey());
        $this->assertSame('eve@example.com', $user->fresh()?->email);
        $this->assertTrue($user->hasOAuthScope('user:read'));
        Event::assertNotDispatched(UserProvisionedEvent::class);
    }

    public function testEmailIsNotRequiredWhenEmailClaimIsNotMapped(): void
    {
        $validator = $this->createMock(LogtoTokenValidator::class);
        $validator->method('validate')->willReturn(['sub' => 'no-email-app', 'scope' => 'user:read']);

        $user = $this->makeGuard($this->makeRequestWithToken('a.b.c'), $validator, ['name' => 'name'])->user();

        $this->assertInstanceOf(TestUser::class, $user);
        $this->assertTrue($user->exists);
    }

    private function resolveWithEmailClaim(string $sub, ?string $email): TestUser
    {
        $claims = ['sub' => $sub, 'scope' => 'user:read'];
        if ($email !== null) {
            $claims['email'] = $email;
        }

        $validator = $this->createMock(LogtoTokenValidator::class);
        $validator->method('validate')->willReturn($claims);

        $user = $this->makeGuard($this->makeRequestWithToken('a.b.c'), $validator, ['email' => 'email'])->user();
        $this->assertInstanceOf(TestUser::class, $user);

        return $user;
    }

    /**
     * @param  array<string, string>  $modelAttributes
     */
    private function makeGuard(Request $request, LogtoTokenValidator $validator, array $modelAttributes = []): LogtoApiResourceGuard
    {
        return new LogtoApiResourceGuard(
            request: $request,
            validator: $validator,
            resolver: new UserResolver(TestUser::class, $modelAttributes),
        );
    }

    private function makeRequestWithToken(string $token): Request
    {
        $request = new Request();
        $request->headers->set('Authorization', "Bearer {$token}");

        return $request;
    }
}
