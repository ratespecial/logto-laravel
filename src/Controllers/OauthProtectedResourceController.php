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
            'resource'              => config('logto.api-resource'),
            'authorization_servers' => [$issuer],
            'scopes_supported'      => $supportedScopes,
        ]);
    }
}
