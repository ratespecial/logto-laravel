<?php

declare(strict_types=1);

return [
    /*
     * Tenant URL.
     * Example: https://abcdef.logto.app
     */
    'endpoint' => env('LOGTO_ENDPOINT', ''),

    /*
     * API resource identifier.  Must match exactly
     * This will be the audience claim in the JWT
     */
    'api-resource' => env('LOGTO_API_RESOURCE', ''),

    /*
     * TTL in second for cached OIDC discovery document and JWKS
     */
    'cache-ttl' => (int) env('LOGTO_CACHE_TTL', 600),

    /*
     * Mapping of JWT claim name => user model attribute name.
     *
     * Used by LogtoApiResourceGuard to populate the $attributes passed to
     * updateOrCreate() when JIT-provisioning or refreshing the user record.
     * Only claims that are present and non-empty on the token are applied.
     */
    'model-attributes' => [
        'email' => 'email',
        'name'  => 'name',
    ],

    'mcp' => [
        'routes' => env('LOGTO_MCP_ROUTES', false),

        /*
         * Scopes advertised by the OAuth Protected Resource metadata endpoint (RFC 9728).
         * Space-delimited string of scope names.
         */
        'scopes-supported' => env('LOGTO_MCP_SCOPES', 'mcp:use'),

        /*
         * Middleware applied to the OAuth Protected Resource metadata route.
         * Comma-delimited string of middleware names/aliases.
         */
        'protected-resource-middleware' => env('LOGTO_MCP_PROTECTED_RESOURCE_MIDDLEWARE', ''),
    ],
];
