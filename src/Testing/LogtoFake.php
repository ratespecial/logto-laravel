<?php

declare(strict_types=1);

namespace Ratespecial\Logto\Testing;

use Firebase\JWT\JWT;
use Ratespecial\Logto\Services\LogtoTokenValidator;
use RuntimeException;

/**
 * Stand-in for a Logto tenant during tests. Serves a discovery document and a JWKS holding a
 * generated public key, and signs access tokens with the matching private key, so tokens it
 * issues pass {@see LogtoTokenValidator} for real.
 */
class LogtoFake
{
    /**
     * @var string Key ID advertised in the JWKS and set in the header of signed tokens.
     */
    public const string KID = 'logto-fake';

    /**
     * @var string Issuer used when logto.endpoint is not configured.
     */
    public const string DEFAULT_ENDPOINT = 'https://logto.test';

    /**
     * @var array{private: string, n: string, e: string}|null Generated once per process; RSA keygen is slow.
     */
    private static ?array $keyPair = null;

    public function __construct(
        public readonly string $issuer,
        public readonly string $audience,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function discoveryDoc(): array
    {
        return [
            'issuer'                 => $this->issuer,
            'jwks_uri'               => $this->issuer . '/jwks',
            'authorization_endpoint' => $this->issuer . '/auth',
            'token_endpoint'         => $this->issuer . '/token',
        ];
    }

    /**
     * @return array{keys: list<array<string, string>>}
     */
    public function jwks(): array
    {
        $keyPair = self::keyPair();

        return [
            'keys' => [[
                'kty' => 'RSA',
                'kid' => self::KID,
                'use' => 'sig',
                'alg' => 'RS256',
                'n'   => $keyPair['n'],
                'e'   => $keyPair['e'],
            ]],
        ];
    }

    /**
     * Sign an access token. Given claims override the defaults (iss, aud, sub, iat, exp).
     *
     * @param  array<string, mixed>  $claims
     */
    public function token(array $claims = []): string
    {
        $now = time();

        $payload = array_merge([
            'iss' => $this->issuer,
            'aud' => $this->audience,
            'sub' => 'logto-test-user',
            'iat' => $now,
            'exp' => $now + 3600,
        ], $claims);

        return JWT::encode($payload, self::keyPair()['private'], 'RS256', self::KID);
    }

    /**
     * @return array{private: string, n: string, e: string}
     */
    private static function keyPair(): array
    {
        if (self::$keyPair !== null) {
            return self::$keyPair;
        }

        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($resource === false || ! openssl_pkey_export($resource, $privateKey)) {
            throw new RuntimeException('Unable to generate RSA key for LogtoFake: ' . openssl_error_string());
        }

        $details = openssl_pkey_get_details($resource);
        if ($details === false) {
            throw new RuntimeException('Unable to read RSA key details for LogtoFake');
        }

        return self::$keyPair = [
            'private' => $privateKey,
            'n'       => self::base64Url($details['rsa']['n']),
            'e'       => self::base64Url($details['rsa']['e']),
        ];
    }

    private static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
