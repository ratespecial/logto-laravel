<?php

declare(strict_types=1);

namespace Tests\Ratespecial\Logto;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase;
use Ratespecial\Logto\Contracts\OAuthScopable;
use Ratespecial\Logto\Events\UserProvisionedEvent;
use Ratespecial\Logto\Exceptions\TokenValidationException;
use Ratespecial\Logto\HasOAuthScopes;
use Ratespecial\Logto\LogtoApiResourceGuard;
use Ratespecial\Logto\LogtoServiceProvider;
use Ratespecial\Logto\Services\LogtoTokenValidator;

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
            $table->string('logto_sub')->unique();
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

        /** @var GuardTestUser $user */
        $user = $guard->user();

        $this->assertInstanceOf(GuardTestUser::class, $user);
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

        /** @var GuardTestUser $user */
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

    /**
     * @param  array<string, string>  $modelAttributes
     */
    private function makeGuard(Request $request, LogtoTokenValidator $validator, array $modelAttributes = []): LogtoApiResourceGuard
    {
        return new LogtoApiResourceGuard(
            request: $request,
            validator: $validator,
            userModel: GuardTestUser::class,
            modelAttributes: $modelAttributes,
        );
    }

    private function makeRequestWithToken(string $token): Request
    {
        $request = new Request();
        $request->headers->set('Authorization', "Bearer {$token}");

        return $request;
    }
}

/**
 * In-test Authenticatable model. Defined in the same file so the schema and
 * fixture live next to the test that uses them.
 *
 * @property string $logto_sub
 * @property string|null $email
 * @property string|null $name
 */
class GuardTestUser extends Model implements Authenticatable, OAuthScopable
{
    use HasOAuthScopes;

    protected $table = 'users';

    protected $guarded = [];

    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    public function getAuthIdentifier(): mixed
    {
        return $this->getKey();
    }

    public function getAuthPasswordName(): string
    {
        return 'password';
    }

    public function getAuthPassword(): string
    {
        return '';
    }

    public function getRememberToken(): string
    {
        return '';
    }

    public function setRememberToken($value): void {}

    public function getRememberTokenName(): string
    {
        return '';
    }
}
