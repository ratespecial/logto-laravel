<?php

declare(strict_types=1);

namespace Ratespecial\Logto\Services;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Support\Arr;
use Ratespecial\Logto\Exceptions\OidcDiscoveryException;
use Ratespecial\Logto\Exceptions\TokenValidationException;

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
        $keys = JWK::parseKeySet($this->discovery->getJwks());

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
}
