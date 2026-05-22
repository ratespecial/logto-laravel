<?php

declare(strict_types=1);

namespace Ratespecial\Logto;

use Ratespecial\Logto\Contracts\OAuthScopable;

/**
 * Attach to an Authenticatable model to allow for checking OAuth scopes.
 *
 * The model must also implement {@see OAuthScopable}.
 *
 * The guard calls these methods.
 *
 * @see LogtoApiResourceGuard
 *
 * @phpstan-require-implements OAuthScopable
 */
trait HasOAuthScopes
{
    /** @var list<string> */
    protected array $oauthScopes = [];

    /**
     * Accepts a space-separated string or an array of scopes this user has access to.
     *
     * Example: "user:read user:write feature:read"
     *
     * @param  list<string>|string  $scopes
     */
    public function setOAuthScopes(array|string $scopes): void
    {
        if (is_string($scopes)) {
            $scopes = array_filter(explode(' ', $scopes));
        }

        $this->oauthScopes = array_values($scopes);
    }

    public function hasOAuthScope(string $scope): bool
    {
        return in_array($scope, $this->oauthScopes, true);
    }
}
