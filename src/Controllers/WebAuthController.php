<?php

declare(strict_types=1);

namespace Ratespecial\Logto\Controllers;

use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Ratespecial\Logto\Exceptions\SignInException;
use Ratespecial\Logto\Services\LogtoWebClient;
use Ratespecial\Logto\Services\UserResolver;
use RuntimeException;

/**
 * Browser sign-in (Authorization Code + PKCE) that logs the user into a standard Laravel session guard.
 *
 * Failures in the callback throw {@see SignInException}.
 */
class WebAuthController extends Controller
{
    /**
     * @var string Session key holding the in-flight state, nonce and PKCE verifier.
     */
    private const string SESSION_KEY = 'logto.web';

    public function __construct(private readonly LogtoWebClient $client) {}

    public function signIn(Request $request): RedirectResponse
    {
        $flow = [
            'state'    => Str::random(40),
            'nonce'    => Str::random(40),
            'verifier' => Str::random(64),
        ];

        // Kept alongside Laravel's own `url.intended`, which `auth` middleware sets when it redirects a guest.
        $request->session()->put(self::SESSION_KEY, $flow);

        return redirect()->away($this->client->authorizationUrl(
            redirectUri: route('logto.callback'),
            state: $flow['state'],
            nonce: $flow['nonce'],
            codeVerifier: $flow['verifier'],
        ));
    }

    public function callback(Request $request): RedirectResponse
    {
        // Single use, whatever the outcome.
        $flow = $request->session()->pull(self::SESSION_KEY);

        if (! is_array($flow) || ! hash_equals($flow['state'], (string) $request->query('state'))) {
            throw new SignInException('Sign-in failed: invalid or expired state. Please try again.');
        }

        if ($request->query->has('error')) {
            $description = (string) $request->query('error_description', $request->query('error'));

            throw new SignInException("Sign-in failed: {$description}");
        }

        $code = $request->query('code');
        if (! is_string($code) || $code === '') {
            throw new SignInException('Sign-in failed: no authorization code returned');
        }

        $tokens = $this->client->exchangeCode($code, route('logto.callback'), $flow['verifier']);
        $claims = $this->client->validateIdToken($tokens['id_token'], $flow['nonce']);

        if (empty($claims['sub'])) {
            throw new SignInException('Sign-in failed: missing subject');
        }

        if ($this->client->requiresResource()) {
            $claims = $this->withApiScope($claims, $tokens);
        }

        $guardName = (string) config('logto.web.guard');
        $provider  = config("auth.guards.{$guardName}.provider");
        if (! is_string($provider)) {
            throw new RuntimeException("Guard [{$guardName}] has no provider configured");
        }

        $user = UserResolver::forProvider($provider)->resolve($claims);
        if ($user === null) {
            throw new SignInException('Sign-in failed: your account has no email address');
        }

        $guard = Auth::guard($guardName);
        if (! $guard instanceof StatefulGuard) {
            throw new RuntimeException("Guard [{$guardName}] is not a session guard");
        }

        $guard->login($user);
        $request->session()->regenerate();

        return redirect()->intended((string) config('logto.web.redirect-after-login'));
    }

    public function signOut(Request $request): RedirectResponse
    {
        $guard = Auth::guard((string) config('logto.web.guard'));
        if ($guard instanceof StatefulGuard) {
            $guard->logout();
        }

        $request->session()->invalidate();
        $request->session()->regenerateToken();

        $after = url((string) config('logto.web.redirect-after-logout'));

        $logoutUrl = $this->client->endSessionUrl($after);

        return $logoutUrl === null ? redirect()->to($after) : redirect()->away($logoutUrl);
    }

    /**
     * When an API resource is configured the user must hold at least one scope on it; that's the access gate.
     * The access token's scope is merged into the claims so it reaches the user model.
     *
     * @param  array<string, mixed>  $claims
     * @param  array<string, mixed>  $tokens
     * @return array<string, mixed>
     */
    private function withApiScope(array $claims, array $tokens): array
    {
        if (empty($tokens['access_token'])) {
            throw new SignInException('Sign-in failed: no access token returned');
        }

        $access = $this->client->validateAccessToken($tokens['access_token']);

        if (($access['sub'] ?? null) !== $claims['sub']) {
            throw new SignInException('Sign-in failed: token subject mismatch');
        }

        if (empty($access['scope'])) {
            throw new SignInException('You do not have access to this application');
        }

        $claims['scope'] = $access['scope'];

        return $claims;
    }
}
