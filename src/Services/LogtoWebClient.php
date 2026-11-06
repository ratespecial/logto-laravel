<?php

declare(strict_types=1);

namespace Ratespecial\Logto\Services;

use Firebase\JWT\JWT;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Uri;
use Ratespecial\Logto\Exceptions\OidcDiscoveryException;
use Ratespecial\Logto\Exceptions\SignInException;
use Throwable;

/**
 * OIDC Authorization Code + PKCE client for a Logto "Traditional Web" application.
 */
class LogtoWebClient
{
    /**
     * See the "Scopes and access control" comment in config/logto.php for how these relate.
     *
     * @param  list<string>  $oidcScopes  Control which user claims the ID token carries. Grant no access.
     * @param  string|null  $resource  API resource to also request an access token for. Null for ID token only.
     * @param  list<string>  $resourceScopes  Permissions on the resource to request; holding any one is enough.
     * @param  list<string>  $requiredScopes  Permissions on the resource the user must all hold. Also requested.
     */
    public function __construct(
        private readonly OidcDiscoveryService $discovery,
        private readonly string $appId,
        private readonly string $appSecret,
        private readonly array $oidcScopes,
        private readonly ?string $resource = null,
        private readonly array $resourceScopes = [],
        private readonly array $requiredScopes = [],
    ) {}

    /**
     * The `scope` parameter for the authorization request.
     *
     * Logto only puts a permission in the access token when it is requested by name, so the resource
     * scopes, required ones included, are sent alongside the OIDC scopes.
     */
    public function requestedScopes(): string
    {
        $scopes = $this->oidcScopes;

        if ($this->requiresResource()) {
            $scopes = [...$scopes, ...$this->resourceScopes, ...$this->requiredScopes];
        }

        return implode(' ', array_unique($scopes));
    }

    /**
     * Permissions on the resource the user must all hold for sign-in to succeed.
     *
     * @return list<string>
     */
    public function requiredScopes(): array
    {
        return $this->requiredScopes;
    }

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
            'scope'                 => $this->requestedScopes(),
            'state'                 => $state,
            'nonce'                 => $nonce,
            'code_challenge'        => self::codeChallenge($codeVerifier),
            'code_challenge_method' => 'S256',
        ];

        if ($this->requiresResource()) {
            $query['resource'] = $this->resource;
        }

        return Uri::of($endpoint)->withQuery($query)->value();
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
            $logtoTokenValidator = new LogtoTokenValidator($this->discovery, $this->appId);
            $claims              = $logtoTokenValidator->validate($idToken);
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
            $logtoTokenValidator = new LogtoTokenValidator($this->discovery, (string) $this->resource);

            return $logtoTokenValidator->validate($accessToken);
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

        return Uri::of($endpoint)
            ->withQuery([
                'client_id'                => $this->appId,
                'post_logout_redirect_uri' => $postLogoutRedirectUri,
            ])
            ->value();
    }

    /**
     * PKCE S256 code challenge (RFC 7636 §4.2): BASE64URL(SHA256(verifier)), without padding.
     */
    public static function codeChallenge(string $codeVerifier): string
    {
        return JWT::urlsafeB64Encode(hash('sha256', $codeVerifier, binary: true));
    }
}
