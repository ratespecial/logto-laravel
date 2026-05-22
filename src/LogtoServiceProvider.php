<?php

declare(strict_types=1);

namespace Ratespecial\Logto;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;
use Ratespecial\Logto\Services\LogtoTokenValidator;
use Ratespecial\Logto\Services\OidcDiscoveryService;
use RuntimeException;

class LogtoServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/logto.php', 'logto');

        $this->registerGuardConfig();
        $this->registerTokenValidator();
        $this->registerOidcDiscoveryService();
    }

    public function boot(): void
    {
        $this->routes();
        $this->migrations();

        // Configure Guard driver.  Must be configured to a guard in config/auth.php `guards`.
        // For use with `auth` middleware.
        Auth::extend('logto-api-resource', function ($app, $_name, array $config) {
            $providerConfig = $app['config']->get("auth.providers.{$config['provider']}");

            return new LogtoApiResourceGuard(
                request: $app['request'],
                validator: $app->make(LogtoTokenValidator::class),
                userModel: $providerConfig['model'],
                modelAttributes: $app['config']->get('logto.model-attributes', []),
            );
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
            $config = $app['config']->get('services.logto');

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
            $config = $app['config']->get('services.logto');

            if (empty($config['endpoint'])) {
                throw new RuntimeException('Logto endpoint is not configured');
            }

            return new OidcDiscoveryService(
                issuer: $config['endpoint'],
                cacheTtl: $config['cache-ttl'],
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
