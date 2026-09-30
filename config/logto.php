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
     * Used by UserResolver to look up users, and by the published migrations.
     */
    'subject-column' => env('LOGTO_SUBJECT_COLUMN', 'logto_sub'),

    /*
     * Mapping of JWT claim name => user model attribute name.
     *
     * Used by UserResolver to populate the attributes written when JIT-provisioning or refreshing the user record.
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

    /*
     * When a token has no email and no user matches its `sub`, don't insert a user row.  The request is still
     * authenticated as an unsaved (transient) user, which suits machine-to-machine (client_credentials) tokens.
     * Only applies when `email` is mapped in `model-attributes`.  Set true to always provision.
     *
     * Logto access tokens only carry `email` if a custom JWT claim is configured in Logto.
     * The web sign-in flow never logs in a user it can't store; it rejects them unless this is true.
     */
    'provision-without-email' => (bool) env('LOGTO_PROVISION_WITHOUT_EMAIL', false),

    /*
     * Browser sign-in for server-rendered apps: OIDC Authorization Code + PKCE against a Logto
     * "Traditional Web" application, logging the user in to a normal Laravel session guard.
     */
    'web' => [
        'routes' => (bool) env('LOGTO_WEB_ROUTES', false),

        // Logto "Traditional Web" application credentials.
        'app-id'     => env('LOGTO_WEB_APP_ID', ''),
        'app-secret' => env('LOGTO_WEB_APP_SECRET', ''),

        // Routes are /{prefix}/sign-in, /{prefix}/callback and /{prefix}/sign-out
        'prefix' => env('LOGTO_WEB_PREFIX', 'logto'),

        // Session guard (config/auth.php) the user is logged in to.  Its provider's model is used.
        'guard' => env('LOGTO_WEB_GUARD', 'web'),

        // Comma-delimited middleware for the routes.  Must include sessions.
        'middleware' => env('LOGTO_WEB_MIDDLEWARE', 'web'),

        // Space-delimited scopes to request.
        'scopes' => env('LOGTO_WEB_SCOPES', 'openid profile email'),

        /*
         * Optional API resource to request an access token for.  When set, the user must hold at least one
         * scope on it or sign-in is refused, letting Logto roles gate access.  The token's scopes are set
         * on the user for this request only.
         */
        'resource' => env('LOGTO_WEB_RESOURCE'),

        // Where to go after signing in when there is no intended URL, and after signing out.  Paths or absolute URLs.
        'redirect-after-login'  => env('LOGTO_WEB_REDIRECT_AFTER_LOGIN', '/'),
        'redirect-after-logout' => env('LOGTO_WEB_REDIRECT_AFTER_LOGOUT', '/'),
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
