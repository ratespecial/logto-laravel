<?php

namespace Ratespecial\Logto\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Controller;
use Ratespecial\Logto\Services\OidcDiscoveryService;

/**
 * Returns metadata for Oauth protected resources.  This is used for MCP clients.
 *
 * @see https://www.rfc-editor.org/info/rfc9728/
 */
class OauthProtectedResourceController extends Controller
{
    public function __construct(
        private readonly OidcDiscoveryService $oidcDiscoveryService,
    ) {}

    public function __invoke(?string $path = ''): JsonResponse
    {
        $issuer          = $this->oidcDiscoveryService->get()->issuer;
        $supportedScopes = explode(' ', config('logto.scopes-supported'));

        return response()->json([
            // MCP clients such as Claude expect this to match the URL of the MCP server they're requesting from.
            'resource'              => config('logto.api-resource'),

            // Should point to logto.io tenant
            'authorization_servers' => [$issuer],

            // Scopes listed here should be set as permissions on the third party application
            'scopes_supported'      => $supportedScopes,
        ]);
    }
}
