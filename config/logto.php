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
     *
     * Defaults to app.url.  MCP clients such as Claude expect the resource to match the domain of the MCP server.
     * Deliberately not url('/'), which derives from the request's Host header and would let a caller pick the audience.
     */
    'api-resource' => env('LOGTO_API_RESOURCE') ?: config('app.url'),

    /*
     * TTL in second for cached OIDC discovery document and JWKS
     */
    'cache-ttl' => (int) env('LOGTO_CACHE_TTL', 600),

    /*
     * Column on the user model that stores the Logto JWT `sub` claim.
     * Used by LogtoApiResourceGuard for updateOrCreate(), and by the
     * published migrations.
     */
    'subject-column' => env('LOGTO_SUBJECT_COLUMN', 'logto_sub'),

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

    /*
     * When no user matches the token's `sub`, claim an existing user whose subject column
     * is null and whose email (the column mapped from the `email` claim above) matches the token.
     *
     * Intended for migrating between Logto tenants after nulling out the old subjects.
     * Anyone who can obtain a token carrying a victim's email can take over that victim's
     * unclaimed record, so enable it only for the migration and turn it off afterwards.
     */
    'link-unclaimed-by-email' => (bool) env('LOGTO_LINK_UNCLAIMED_BY_EMAIL', false),

    'testing' => [
        /*
         * When the app is running unit tests, serve a fake OIDC discovery document and JWKS
         * (see Ratespecial\Logto\Testing\LogtoFake) instead of contacting Logto.
         * Set false to make tests hit the configured endpoint.
         */
        'fake' => (bool) env('LOGTO_TESTING_FAKE', true),
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
