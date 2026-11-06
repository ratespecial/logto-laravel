<?php

declare(strict_types=1);

namespace Ratespecial\Logto\Services;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Support\Arr;
use Ratespecial\Logto\Exceptions\OidcDiscoveryException;
use Ratespecial\Logto\Exceptions\TokenValidationException;
use Throwable;

class LogtoTokenValidator
{
    public function __construct(
        private readonly OidcDiscoveryService $discovery,
        private readonly string $audience,
    ) {}

    /**
     * Validate a Logto JWT access token and return its claims.
     *
     * @return array<string, mixed>
     *
     * @throws TokenValidationException
     * @throws OidcDiscoveryException
     */
    public function validate(string $token): array
    {
        // Opaque bearer tokens (e.g. a legacy api_token behind `auth:logto,api`) aren't JWTs; let the next guard handle them.
        if (substr_count($token, '.') !== 2) {
            throw new TokenValidationException('Not a JWT');
        }

        $keys = JWK::parseKeySet($this->discovery->getJwks());

        // An unknown key ID usually means Logto rotated its signing key since the JWKS was cached.
        $kid = self::keyId($token);
        if ($kid !== null && ! isset($keys[$kid])) {
            $keys = JWK::parseKeySet($this->discovery->refreshJwks());
        }

        $payload = (array) JWT::decode($token, $keys);

        if (($payload['iss'] ?? null) !== $this->discovery->get()->issuer) {
            throw new TokenValidationException('Invalid token issuer');
        }

        $audiences = Arr::wrap($payload['aud']);
        if (! in_array($this->audience, $audiences, true)) {
            throw new TokenValidationException('Invalid token audience');
        }

        return $payload;
    }

    /**
     * The `kid` from the token header, or null if the header can't be read. JWT::decode reports malformed
     * headers itself, so they aren't handled here.
     */
    private static function keyId(string $token): ?string
    {
        try {
            $header = JWT::jsonDecode(JWT::urlsafeB64Decode(explode('.', $token)[0]));
        } catch (Throwable) {
            return null;
        }

        return is_object($header) && isset($header->kid) && is_string($header->kid) ? $header->kid : null;
    }
}
