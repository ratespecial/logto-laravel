<?php

declare(strict_types=1);

namespace Ratespecial\Logto\Services;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use Ratespecial\Logto\Exceptions\OidcDiscoveryException;
use Ratespecial\Logto\Exceptions\SignInException;
use Throwable;

/**
 * OIDC Authorization Code + PKCE client for a Logto "Traditional Web" application.
 */
class LogtoWebClient
{
    public function __construct(
        private readonly OidcDiscoveryService $discovery,
        private readonly string $appId,
        private readonly string $appSecret,
        private readonly string $scopes,
        private readonly ?string $resource = null,
    ) {}

    /**
     * @throws OidcDiscoveryException
     */
    public function authorizationUrl(string $redirectUri, string $state, string $nonce, string $codeVerifier): string
    {
        $endpoint = $this->discovery->get()->authorization_endpoint
            ?? throw new OidcDiscoveryException('OIDC discovery document has no authorization_endpoint');

        $query = [
            'client_id'             => $this->appId,
            'redirect_uri'          => $redirectUri,
            'response_type'         => 'code',
            'scope'                 => $this->scopes,
            'state'                 => $state,
            'nonce'                 => $nonce,
            'code_challenge'        => self::codeChallenge($codeVerifier),
            'code_challenge_method' => 'S256',
        ];

        if ($this->resource !== null && $this->resource !== '') {
            $query['resource'] = $this->resource;
        }

        return $endpoint . (str_contains($endpoint, '?') ? '&' : '?') . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * Exchange an authorization code for tokens.
     *
     * @return array<string, mixed> Token response (`id_token`, `access_token`, ...)
     *
     * @throws SignInException
     * @throws OidcDiscoveryException
     */
    public function exchangeCode(string $code, string $redirectUri, string $codeVerifier): array
    {
        $endpoint = $this->discovery->get()->token_endpoint
            ?? throw new OidcDiscoveryException('OIDC discovery document has no token_endpoint');

        try {
            $response = Http::asForm()
                ->withBasicAuth($this->appId, $this->appSecret)
                ->post($endpoint, [
                    'grant_type'    => 'authorization_code',
                    'code'          => $code,
                    'redirect_uri'  => $redirectUri,
                    'code_verifier' => $codeVerifier,
                ]);
        } catch (ConnectionException $ex) {
            throw new SignInException('Could not reach the sign-in service', $ex);
        }

        if (! $response->successful() || ! is_array($tokens = $response->json()) || empty($tokens['id_token'])) {
            throw new SignInException('Sign-in failed: the authorization code could not be exchanged');
        }

        return $tokens;
    }

    /**
     * Validate the ID token's signature, issuer, audience (this app), expiry and nonce.
     *
     * @return array<string, mixed> Claims
     *
     * @throws SignInException
     * @throws OidcDiscoveryException
     */
    public function validateIdToken(string $idToken, string $nonce): array
    {
        try {
            $claims = (new LogtoTokenValidator($this->discovery, $this->appId))->validate($idToken);
        } catch (OidcDiscoveryException $ex) {
            throw $ex;
        } catch (Throwable $ex) {
            throw new SignInException('Sign-in failed: invalid ID token', $ex);
        }

        if (! is_string($claims['nonce'] ?? null) || ! hash_equals($nonce, $claims['nonce'])) {
            throw new SignInException('Sign-in failed: nonce mismatch');
        }

        return $claims;
    }

    /**
     * Validate an access token issued for the configured API resource.
     *
     * @return array<string, mixed> Claims
     *
     * @throws SignInException
     * @throws OidcDiscoveryException
     */
    public function validateAccessToken(string $accessToken): array
    {
        try {
            return (new LogtoTokenValidator($this->discovery, (string) $this->resource))->validate($accessToken);
        } catch (OidcDiscoveryException $ex) {
            throw $ex;
        } catch (Throwable $ex) {
            throw new SignInException('Sign-in failed: invalid access token', $ex);
        }
    }

    public function requiresResource(): bool
    {
        return $this->resource !== null && $this->resource !== '';
    }

    /**
     * RP-initiated logout URL, or null when Logto doesn't advertise an end_session_endpoint.
     *
     * @throws OidcDiscoveryException
     */
    public function endSessionUrl(string $postLogoutRedirectUri): ?string
    {
        $endpoint = $this->discovery->get()->end_session_endpoint;
        if ($endpoint === null) {
            return null;
        }

        return $endpoint . (str_contains($endpoint, '?') ? '&' : '?') . http_build_query([
            'client_id'                => $this->appId,
            'post_logout_redirect_uri' => $postLogoutRedirectUri,
        ], '', '&', PHP_QUERY_RFC3986);
    }

    public static function codeChallenge(string $codeVerifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');
    }
}
