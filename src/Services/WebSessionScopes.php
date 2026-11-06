<?php

declare(strict_types=1);

namespace Ratespecial\Logto\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Session\Session;
use Ratespecial\Logto\Contracts\OAuthScopable;
use Ratespecial\Logto\Support\Scopes;

/**
 * Keeps the scopes granted at web sign-in for the rest of the Laravel session.
 *
 * The session guard loads the user from the database on each request, so scopes set on the model at the
 * callback would otherwise be lost after the redirect. The callback stores them here, and the provider's
 * `Authenticated` listener calls {@see restore()} each time the guard loads the user.
 *
 * The scopes are a snapshot from sign-in. A role removed in Logto takes effect when the user next signs in.
 */
class WebSessionScopes
{
    /**
     * @var string Not nested under `logto.web`, which holds the in-flight sign-in flow and is pulled whole.
     */
    private const string SESSION_KEY = 'logto_web_scopes';

    public function __construct(
        private readonly Session $session,
    ) {}

    /**
     * Store the scopes granted to this user at sign-in, or clear any stored scopes when there are none.
     */
    public function remember(Authenticatable $user, ?string $scope): void
    {
        $scopes = Scopes::parse($scope);

        if ($scopes === []) {
            $this->forget();

            return;
        }

        $this->session->put(self::SESSION_KEY, [
            'user'   => (string) $user->getAuthIdentifier(),
            'scopes' => $scopes,
        ]);
    }

    /**
     * Put the stored scopes back on the user. Scopes stored for a different user are ignored, so they can't
     * leak if something else logs another user into the same session.
     */
    public function restore(Authenticatable $user): void
    {
        if (! $user instanceof OAuthScopable) {
            return;
        }

        $stored = $this->session->get(self::SESSION_KEY);

        if (! is_array($stored) || ($stored['user'] ?? null) !== (string) $user->getAuthIdentifier()) {
            return;
        }

        $user->setOAuthScopes(Scopes::parse($stored['scopes'] ?? null));
    }

    public function forget(): void
    {
        $this->session->forget(self::SESSION_KEY);
    }
}
