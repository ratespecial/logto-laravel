<?php

declare(strict_types=1);

namespace Tests\Ratespecial\Logto\Web;

use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase;
use Ratespecial\Logto\LogtoServiceProvider;

class SignOutComponentTest extends TestCase
{
    /**
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
        $app['config']->set('app.key', 'base64:' . base64_encode(random_bytes(32)));
        $app['config']->set('logto.endpoint', 'https://logto.example.com');
        $app['config']->set('logto.web', array_merge(config('logto.web') ?? [], [
            'routes'     => true,
            'prefix'     => 'auth/logto',
            'app-id'     => 'web-app-id',
            'app-secret' => 'web-app-secret',
        ]));
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->startSession();
    }

    public function testRendersCsrfProtectedPostToSignOutRoute(): void
    {
        $view = $this->blade('<x-logto::sign-out />');

        // The configured prefix shows the action comes from the route, not a hard-coded /logto path.
        $view->assertSee('method="POST"', false);
        $this->assertStringEndsWith('/auth/logto/sign-out', route('logto.sign-out'));
        $view->assertSee('action="' . route('logto.sign-out') . '"', false);
        $view->assertSee('name="_token" value="' . csrf_token() . '"', false);
        $view->assertSee('<button type="submit">Sign out</button>', false);
    }

    public function testSlotReplacesDefaultButton(): void
    {
        $view = $this->blade('<x-logto::sign-out><button type="submit" class="btn">Log out</button></x-logto::sign-out>');

        $view->assertSee('<button type="submit" class="btn">Log out</button>', false);
        $view->assertDontSee('>Sign out</button>', false);
    }

    public function testAttributesGoOnTheForm(): void
    {
        $view = $this->blade('<x-logto::sign-out id="logto-sign-out" class="inline" hidden />');

        $view->assertSee('action="' . route('logto.sign-out') . '" id="logto-sign-out" class="inline" hidden', false);
    }
}
