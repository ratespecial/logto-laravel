<?php

declare(strict_types=1);

namespace Ratespecial\Logto\Controllers;

use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Ratespecial\Logto\Exceptions\DuplicateUserEmailException;
use Ratespecial\Logto\Exceptions\SignInException;
use Ratespecial\Logto\Services\LogtoWebClient;
use Ratespecial\Logto\Services\UserResolver;
use RuntimeException;

/**
 * Browser sign-in (Authorization Code + PKCE) that logs the user into a standard Laravel session guard.
 *
 * Access levels (see "Scopes and access control" in config/logto.php):
 * - Without LOGTO_WEB_RESOURCE (the default): requiresResource() returns false {@see LogtoWebClient},
 *   and withApiScope() never runs. Anyone who can sign in to the Logto app gets a Laravel session.
 *   No access token is requested and no scopes are checked.
 * - With LOGTO_WEB_RESOURCE and LOGTO_WEB_RESOURCE_SCOPES: the user needs at least one of those permissions.
 *   In Logto, permissions are granted through roles, so this is how roles control access.
 * - With LOGTO_WEB_RESOURCE and LOGTO_WEB_REQUIRED_SCOPES: the user needs every permission listed.
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

    /**
     * Redirects a user to the Logto login page after storing state in user's session
     */
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

    /**
     * After user signs in at Logto they are redirected back here.  This route should be configured in Logto's Application -> Redirect URI
     */
    public function callback(Request $request): RedirectResponse
    {
        // Single use, whatever the outcome.
        $flow = $request->session()->pull(self::SESSION_KEY);

        // CSRF protection: the state must match the one signIn() stored in this session. A missing flow means
        // the callback was hit without going through signIn() first, or the session expired / was already used.
        if (! is_array($flow) || ! hash_equals($flow['state'], (string) $request->query('state'))) {
            throw new SignInException('Sign-in failed: invalid or expired state. Please try again.');
        }

        // Logto reports failures (e.g. user cancelled, access_denied) as error params instead of a code.
        // Checked after state so an attacker can't trigger arbitrary error messages without a valid flow.
        if ($request->query->has('error')) {
            $description = (string) $request->query('error_description', $request->query('error'));

            throw new SignInException("Sign-in failed: {$description}");
        }

        // A successful authorization response must carry a non-empty code to exchange.
        $code = $request->query('code');
        if (! is_string($code) || $code === '') {
            throw new SignInException('Sign-in failed: no authorization code returned');
        }

        // The PKCE verifier proves this server started the flow; the nonce ties the ID token to this flow,
        // preventing replay of a token issued for another sign-in.
        $tokens = $this->client->exchangeCode($code, route('logto.callback'), $flow['verifier']);
        $claims = $this->client->validateIdToken($tokens['id_token'], $flow['nonce']);

        // The subject is the stable Logto user ID that UserResolver keys on; without it we can't identify the user.
        if (empty($claims['sub'])) {
            throw new SignInException('Sign-in failed: missing subject');
        }

        // With logto.web.resource set, sign-in is gated on the user holding scopes for that API resource.
        if ($this->client->requiresResource()) {
            $claims = $this->withApiScope($claims, $tokens);
        }

        // Misconfiguration, not a user error: the guard needs a provider so we know which user model to resolve.
        $guardName = (string) config('logto.web.guard');
        $provider  = config("auth.guards.{$guardName}.provider");
        if (! is_string($provider)) {
            throw new RuntimeException("Guard [{$guardName}] has no provider configured");
        }

        // Another row already owns this email but isn't linked to this subject. Reported so an admin can
        // reconcile the accounts; the user only sees a generic message.
        try {
            $user = UserResolver::forProvider($provider)->resolve($claims);
        } catch (DuplicateUserEmailException $ex) {
            report($ex);

            throw new SignInException('Sign-in failed: an account with this email already exists. Contact an administrator.', $ex);
        }

        // UserResolver returns null when the email claim is empty and no existing row matches the subject.
        // The web flow needs a persisted user for the session, so this is rejected
        // (unless logto.provision-without-email is enabled, in which case it never returns null).
        if ($user === null) {
            throw new SignInException('Sign-in failed: your account has no email address');
        }

        // Misconfiguration: only stateful (session) guards can log a user in across requests.
        $guard = Auth::guard($guardName);
        if (! $guard instanceof StatefulGuard) {
            throw new RuntimeException("Guard [{$guardName}] is not a session guard");
        }

        $guard->login($user);

        // New session ID after authenticating, to prevent session fixation.
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
     * When an API resource is configured the user must hold at least one requested permission on it, and every
     * permission in logto.web.required-scopes; that's the access gate.
     * The access token's scope is merged into the claims so it reaches the user model.
     *
     * @param  array<string, mixed>  $claims
     * @param  array<string, mixed>  $tokens
     * @return array<string, mixed>
     */
    private function withApiScope(array $claims, array $tokens): array
    {
        // A resource was requested in the authorization URL, so Logto should have issued an access token for it.
        if (empty($tokens['access_token'])) {
            throw new SignInException('Sign-in failed: no access token returned');
        }

        // Checks signature, issuer and that the audience is the configured resource (not the app ID).
        $access = $this->client->validateAccessToken($tokens['access_token']);

        // The access token must belong to the same user as the ID token, so scopes from one user's token
        // can't be attached to another user's identity.
        if (($access['sub'] ?? null) !== $claims['sub']) {
            throw new SignInException('Sign-in failed: token subject mismatch');
        }

        // Logto only returns requested permissions the user holds, so an empty scope means the user holds none
        // of them (level 2: any one is enough).
        if (empty($access['scope'])) {
            throw new SignInException('You do not have access to this application');
        }

        // Scopes are space-delimited (RFC 6749); array_filter drops empty entries from extra spaces.
        // Every required scope must be granted (level 3); extra granted scopes are fine.
        $granted = array_filter(explode(' ', (string) $access['scope']));
        if (array_diff($this->client->requiredScopes(), $granted) !== []) {
            throw new SignInException('You do not have access to this application');
        }

        // ID tokens don't carry API scopes; copy them over so UserResolver can set them on OAuthScopable users.
        $claims['scope'] = $access['scope'];

        return $claims;
    }
}
