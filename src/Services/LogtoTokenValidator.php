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
    /**
     * @var int Seconds of clock difference tolerated between Logto and this server when checking `iat`, `nbf`
     *          and `exp`.  Without it a server a second behind Logto rejects fresh tokens as issued in the future.
     */
    public const int CLOCK_SKEW_SECONDS = 60;

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
        if (! self::isJwt($token)) {
            throw new TokenValidationException('Not a JWT');
        }

        $keys = JWK::parseKeySet($this->discovery->getJwks());

        // An unknown key ID usually means Logto rotated its signing key since the JWKS was cached.
        $kid = self::keyId($token);
        if ($kid !== null && ! isset($keys[$kid])) {
            $keys = JWK::parseKeySet($this->discovery->refreshJwks());
        }

        // JWT::$leeway is a global static; set it for this decode only so other JWT users in the app are unaffected
        $previousLeeway = JWT::$leeway;
        JWT::$leeway    = self::CLOCK_SKEW_SECONDS;
        try {
            $payload = (array) JWT::decode($token, $keys);
        } finally {
            JWT::$leeway = $previousLeeway;
        }

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
     * Whether the token has the three-segment JWT shape. Opaque tokens (Logto's userinfo tokens, legacy API tokens) don't.
     */
    public static function isJwt(string $token): bool
    {
        return substr_count($token, '.') === 2;
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
