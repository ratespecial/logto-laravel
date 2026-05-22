<?php

declare(strict_types=1);

namespace Ratespecial\Logto\Contracts;

use Ratespecial\Logto\HasOAuthScopes;

/**
 * Contract for models that carry OAuth scopes granted by the access token.
 *
 * @see HasOAuthScopes
 */
interface OAuthScopable
{
    /**
     * @param  list<string>|string  $scopes
     */
    public function setOAuthScopes(array|string $scopes): void;

    public function hasOAuthScope(string $scope): bool;
}
