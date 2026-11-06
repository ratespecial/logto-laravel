<?php

declare(strict_types=1);

namespace Ratespecial\Logto;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Logout;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;
use Ratespecial\Logto\Services\LogtoTokenValidator;
use Ratespecial\Logto\Services\LogtoWebClient;
use Ratespecial\Logto\Services\OidcDiscoveryService;
use Ratespecial\Logto\Services\UserResolver;
use Ratespecial\Logto\Services\WebSessionScopes;
use Ratespecial\Logto\Support\Scopes;
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
        $this->registerWebClient();
        $this->registerFake();

        $this->app->bind(WebSessionScopes::class, fn ($app) => new WebSessionScopes($app['session.store']));
    }

    public function boot(): void
    {
        $this->routes();
        $this->migrations();
        $this->views();

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

        $this->webSessionScopes();
    }

    /**
     * Restore the scopes granted at web sign-in each time the web guard loads the user from the session,
     * and drop them when that guard logs out. See {@see WebSessionScopes}.
     */
    protected function webSessionScopes(): void
    {
        if (! $this->app['config']->get('logto.web.routes')) {
            return;
        }

        Event::listen(Authenticated::class, function (Authenticated $event) {
            if ($event->guard === config('logto.web.guard')) {
                $this->app->make(WebSessionScopes::class)->restore($event->user);
            }
        });

        Event::listen(Logout::class, function (Logout $event) {
            if ($event->guard === config('logto.web.guard')) {
                $this->app->make(WebSessionScopes::class)->forget();
            }
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

    protected function registerWebClient(): void
    {
        $this->app->bind(LogtoWebClient::class, function ($app) {
            $config = $app['config']->get('logto.web');

            if (empty($config['app-id']) || empty($config['app-secret'])) {
                throw new RuntimeException('Logto web app id/secret are not configured');
            }

            $resource       = ((string) $config['resource']) ?: null;
            $resourceScopes = Scopes::parse($config['resource-scopes']);
            $requiredScopes = Scopes::parse($config['required-scopes']);

            // Resource scopes are permissions on the resource, so they mean nothing without one.
            if ($resource === null && ($resourceScopes !== [] || $requiredScopes !== [])) {
                throw new RuntimeException(
                    'Logto web resource scopes need a resource: set LOGTO_WEB_RESOURCE, or clear LOGTO_WEB_RESOURCE_SCOPES and LOGTO_WEB_REQUIRED_SCOPES'
                );
            }

            // Logto only issues permissions that are requested by name, so with no scopes requested the
            // access token's scope would always be empty and every sign-in refused.
            if ($resource !== null && $resourceScopes === [] && $requiredScopes === []) {
                throw new RuntimeException(
                    'Logto web resource needs scopes to request: set LOGTO_WEB_RESOURCE_SCOPES and/or LOGTO_WEB_REQUIRED_SCOPES'
                );
            }

            return new LogtoWebClient(
                discovery: $app->make(OidcDiscoveryService::class),
                appId: $config['app-id'],
                appSecret: $config['app-secret'],
                oidcScopes: Scopes::parse($config['oidc-scopes']),
                resource: $resource,
                resourceScopes: $resourceScopes,
                requiredScopes: $requiredScopes,
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
        if ($this->app['config']->get('logto.web.routes')) {
            $this->loadRoutesFrom(__DIR__ . '/../routes/web-routes.php');
        }

        if ($this->app['config']->get('logto.mcp.routes')) {
            $this->loadRoutesFrom(__DIR__ . '/../routes/mcp-routes.php');
        }
    }

    /**
     * Views under the `logto` namespace, e.g. the `<x-logto::sign-out>` component. Loaded even when the web routes
     * are off, so using the component then fails with a clear "Route [logto.sign-out] not defined".
     */
    protected function views(): void
    {
        $this->loadViewsFrom(__DIR__ . '/../resources/views', 'logto');

        $this->publishes([
            __DIR__ . '/../resources/views' => resource_path('views/vendor/logto'),
        ], 'logto-views');
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
