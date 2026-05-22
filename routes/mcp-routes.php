<?php

use Illuminate\Support\Facades\Route;
use Ratespecial\Logto\Controllers\OauthProtectedResourceController;

$middleware = array_filter(explode(',', config('logto.mcp.protected-resource-middleware')));

/*
 * Routes for MCP clients to discover OAuth protected resources.  These are hit by Claude Code and others.
 * They should NOT be behind any authentication middleware.
 *
 * If the MCP route in your app uses authentication middleware, laravel/mcp AddWwwAuthenticateHeader will
 * catch 401 responses and add the WWW-Authenticate header pointing to these routes.  The metadata returned
 * from the OauthProtectedResourceController tells the MCP client to go to Logto for an access token.
 */

Route::get('/.well-known/oauth-protected-resource', OauthProtectedResourceController::class)
    ->middleware($middleware)
    ->name('mcp.oauth.protected-resource');

Route::get('/.well-known/oauth-protected-resource/{path?}', OauthProtectedResourceController::class)
    ->where('path', '.*')
    ->middleware($middleware)

    /**
     * Name must match what laravel/mcp uses in their AddWwwAuthenticateHeader
     *
     * @see https://github.com/laravel/mcp/blob/main/src/Server/Middleware/AddWwwAuthenticateHeader.php
     */
    ->name('mcp.oauth.protected-resource.nested');
