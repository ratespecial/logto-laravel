<?php

declare(strict_types=1);

namespace Ratespecial\Logto;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;
use Ratespecial\Logto\Services\LogtoTokenValidator;
use Ratespecial\Logto\Services\OidcDiscoveryService;
use Ratespecial\Logto\Services\UserResolver;
use Ratespecial\Logto\Testing\FakeOidcDiscoveryService;
use Ratespecial\Logto\Testing\LogtoFake;
use RuntimeException;

class LogtoServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/logto.php', 'logto');

        $this->registerGuardConfig();
        $this->registerTokenValidator();
        $this->registerOidcDiscoveryService();
        $this->registerFake();
    }

    public function boot(): void
    {
        $this->routes();
        $this->migrations();

        // Configure Guard driver.  Must be configured to a guard in config/auth.php `guards`.
        // For use with `auth` middleware.
        Auth::extend('logto-api-resource', function ($app, $_name, array $config) {
            $guard = new LogtoApiResourceGuard(
                request: $app['request'],
                validator: $app->make(LogtoTokenValidator::class),
                resolver: UserResolver::forProvider($config['provider']),
            );

            // Guards are cached by AuthManager; follow the current request (tests making several requests, Octane)
            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });

        // Configure Gate to use with `can:some:scope` middleware and `$user->can('some:scope')`
        Gate::before(function ($user, string $ability) {
            if ($user === null) {
                return null;
            }

            if (! method_exists($user, 'hasOAuthScope')) {
                return null;
            }

            return $user->hasOAuthScope($ability) ? true : null;
        });
    }

    /**
     * Register logto guard.
     * Usage: ->middleware('auth:logto')
     */
    protected function registerGuardConfig(): void
    {
        config([
            'auth.guards.logto' => array_merge([
                'driver'   => 'logto-api-resource',
                'provider' => null,
            ], config('auth.guards.logto', [])),
        ]);
    }

    protected function registerTokenValidator(): void
    {
        $this->app->bind(LogtoTokenValidator::class, function ($app) {
            $config = $app['config']->get('logto');

            if (empty($config['api-resource'])) {
                throw new RuntimeException('Logto audience is not configured');
            }

            return new LogtoTokenValidator(
                discovery: $app->make(OidcDiscoveryService::class),
                audience: $config['api-resource'],
            );
        });
    }

    protected function registerOidcDiscoveryService(): void
    {
        $this->app->bind(OidcDiscoveryService::class, function ($app) {
            $config = $app['config']->get('logto');

            if ($app->runningUnitTests() && ! empty($config['testing']['fake'])) {
                return new FakeOidcDiscoveryService($app->make(LogtoFake::class));
            }

            if (empty($config['endpoint'])) {
                throw new RuntimeException('Logto endpoint is not configured');
            }

            return new OidcDiscoveryService(
                issuer: $config['endpoint'] . '/oidc',
                cacheTtl: $config['cache-ttl'],
            );
        });
    }

    /**
     * Fake Logto tenant served by FakeOidcDiscoveryService while running unit tests.
     */
    protected function registerFake(): void
    {
        $this->app->singleton(LogtoFake::class, function ($app) {
            $config = $app['config']->get('logto');

            return new LogtoFake(
                issuer: ($config['endpoint'] ?: LogtoFake::DEFAULT_ENDPOINT) . '/oidc',
                audience: (string) $config['api-resource'],
            );
        });
    }

    protected function routes(): void
    {
        if ($this->app['config']->get('logto.mcp.routes')) {
            $this->loadRoutesFrom(__DIR__ . '/../routes/mcp-routes.php');
        }
    }

    protected function migrations(): void
    {
        $this->publishesMigrations([
            __DIR__ . '/../database/migrations/0001_01_01_000000_create_users_table.php' => database_path('migrations/0001_01_01_000000_create_users_table.php'),
        ], 'logto-migrations-users');

        $this->publishesMigrations([
            __DIR__ . '/../database/migrations/0001_01_01_000001_add_logto_sub_to_users_table.php' => database_path('migrations/0001_01_01_000001_add_logto_sub_to_users_table.php'),
        ], 'logto-migrations-logto-sub');
    }
}
