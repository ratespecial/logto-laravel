<?php

declare(strict_types=1);

namespace Ratespecial\Logto\Support;

final class Scopes
{
    /**
     * Normalise scopes into a list: a space-delimited string (RFC 6749 §3.3, as in a token's `scope` claim
     * or a config value) is split on whitespace, and an array is used as is. Empty and non-string entries
     * and duplicates are dropped. Anything else gives an empty list.
     *
     * Example: "user:read  user:write user:read" → ["user:read", "user:write"]
     *
     * @return list<string>
     */
    public static function parse(mixed $scopes): array
    {
        if (is_string($scopes)) {
            $scopes = preg_split('/\s+/', $scopes) ?: [];
        }

        if (! is_array($scopes)) {
            return [];
        }

        $valid = array_filter($scopes, fn (mixed $scope) => is_string($scope) && $scope !== '');

        return array_values(array_unique($valid));
    }
}
