<?php

declare(strict_types=1);

namespace Ratespecial\Logto\Services;

use Firebase\JWT\JWT;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Uri;
use Ratespecial\Logto\Exceptions\OidcDiscoveryException;
use Ratespecial\Logto\Exceptions\SignInException;
use Ratespecial\Logto\Support\Scopes;
use RuntimeException;
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

        return implode(' ', Scopes::parse($scopes));
    }

    /**
     * The API resource an access token is requested for, or null for ID token only.
     */
    public function resource(): ?string
    {
        return $this->requiresResource() ? $this->resource : null;
    }

    /**
     * Permissions requested on the resource: the resource scopes plus the required ones.
     *
     * @return list<string>
     */
    public function resourceScopes(): array
    {
        return Scopes::parse([...$this->resourceScopes, ...$this->requiredScopes]);
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
            $detail = "token endpoint {$endpoint} unreachable: {$ex->getMessage()}";
            report(new RuntimeException($detail, previous: $ex));

            throw new SignInException('Could not reach the sign-in service', $ex, $detail);
        }

        $tokens = $response->json();

        if (! $response->successful() || ! is_array($tokens) || empty($tokens['id_token'])) {
            $detail = $response->successful() ? 'token response has no id_token' : self::tokenErrorDetail($response->status(), $tokens);
            report(new RuntimeException($detail));

            throw new SignInException('Sign-in failed: the authorization code could not be exchanged', detail: $detail);
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
            throw new SignInException('Sign-in failed: invalid ID token', $ex, $ex->getMessage());
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
        // Logto issues an opaque token (only good for the userinfo endpoint) when it didn't issue one for the
        // API resource. That's a configuration problem rather than a bad token, so it gets its own message.
        if (! LogtoTokenValidator::isJwt($accessToken)) {
            $detail = "Logto returned an opaque access token, not a JWT; check logto.web.resource [{$this->resource}] "
                . 'matches an API resource indicator in Logto';
            report(new RuntimeException($detail));

            throw new SignInException('Sign-in failed: the sign-in service is misconfigured. Contact an administrator.', detail: $detail);
        }

        try {
            $logtoTokenValidator = new LogtoTokenValidator($this->discovery, (string) $this->resource);

            return $logtoTokenValidator->validate($accessToken);
        } catch (OidcDiscoveryException $ex) {
            throw $ex;
        } catch (Throwable $ex) {
            throw new SignInException('Sign-in failed: invalid access token', $ex, $ex->getMessage());
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
     * Describes a failed token response using only the OAuth error fields (RFC 6749 §5.2), never the raw body.
     */
    private static function tokenErrorDetail(int $status, mixed $body): string
    {
        $detail = "token endpoint returned HTTP {$status}";

        if (! is_array($body)) {
            return $detail;
        }

        foreach (['error', 'error_description'] as $field) {
            if (is_string($body[$field] ?? null) && $body[$field] !== '') {
                $detail .= ": {$body[$field]}";
            }
        }

        return $detail;
    }

    /**
     * PKCE S256 code challenge (RFC 7636 §4.2): BASE64URL(SHA256(verifier)), without padding.
     */
    public static function codeChallenge(string $codeVerifier): string
    {
        return JWT::urlsafeB64Encode(hash('sha256', $codeVerifier, binary: true));
    }
}
