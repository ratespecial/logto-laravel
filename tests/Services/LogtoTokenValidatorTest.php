<?php

declare(strict_types=1);

namespace Tests\Ratespecial\Logto\Services;

use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use PHPUnit\Framework\TestCase;
use Ratespecial\Logto\Exceptions\TokenValidationException;
use Ratespecial\Logto\Models\OidcDiscoveryDoc;
use Ratespecial\Logto\Services\LogtoTokenValidator;
use Ratespecial\Logto\Services\OidcDiscoveryService;

class LogtoTokenValidatorTest extends TestCase
{
    private const string ISSUER   = 'https://logto.example.com/oidc';

    private const string AUDIENCE = 'https://api.example.com';

    private const string KID      = 'test-key-1';

    /** PEM-encoded RSA private key for signing test tokens. */
    private string $privateKey;

    /**
     * JWKS document that advertises the matching public key.
     *
     * @var array{keys: list<array<string, string>>}
     */
    private array $jwks;

    protected function setUp(): void
    {
        parent::setUp();

        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        openssl_pkey_export($resource, $privateKey);
        $this->privateKey = $privateKey;

        $details    = openssl_pkey_get_details($resource);
        $this->jwks = [
            'keys' => [[
                'kty' => 'RSA',
                'kid' => self::KID,
                'use' => 'sig',
                'alg' => 'RS256',
                'n'   => self::base64Url($details['rsa']['n']),
                'e'   => self::base64Url($details['rsa']['e']),
            ]],
        ];
    }

    public function testValidatesAGoodTokenAndReturnsClaims(): void
    {
        $token = $this->signToken([
            'iss'   => self::ISSUER,
            'aud'   => self::AUDIENCE,
            'sub'   => 'user-123',
            'scope' => 'user:read',
        ]);

        $claims = $this->makeValidator()->validate($token);

        $this->assertSame('user-123', $claims['sub']);
        $this->assertSame('user:read', $claims['scope']);
        $this->assertSame(self::ISSUER, $claims['iss']);
    }

    public function testAcceptsAudienceProvidedAsAnArray(): void
    {
        $token = $this->signToken([
            'iss' => self::ISSUER,
            'aud' => ['some-other-resource', self::AUDIENCE],
            'sub' => 'user-123',
        ]);

        $claims = $this->makeValidator()->validate($token);

        $this->assertSame('user-123', $claims['sub']);
    }

    public function testRejectsTokenWithWrongIssuer(): void
    {
        $token = $this->signToken([
            'iss' => 'https://evil.example.com/oidc',
            'aud' => self::AUDIENCE,
            'sub' => 'user-123',
        ]);

        $this->expectException(TokenValidationException::class);
        $this->expectExceptionMessage('Invalid token issuer');

        $this->makeValidator()->validate($token);
    }

    public function testRejectsTokenWithWrongAudience(): void
    {
        $token = $this->signToken([
            'iss' => self::ISSUER,
            'aud' => 'https://some-other-api.example.com',
            'sub' => 'user-123',
        ]);

        $this->expectException(TokenValidationException::class);
        $this->expectExceptionMessage('Invalid token audience');

        $this->makeValidator()->validate($token);
    }

    public function testRejectsTokenSignedByDifferentKey(): void
    {
        // Sign a token using a freshly-generated key that is NOT in the JWKS.
        $strangerResource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        openssl_pkey_export($strangerResource, $strangerPriv);

        $token = JWT::encode(
            ['iss' => self::ISSUER, 'aud' => self::AUDIENCE, 'sub' => 'user-123'],
            $strangerPriv,
            'RS256',
            self::KID,
        );

        // firebase/php-jwt raises its own exception type for signature failures.
        $this->expectException(SignatureInvalidException::class);

        $this->makeValidator()->validate($token);
    }

    private function makeValidator(): LogtoTokenValidator
    {
        $doc         = new OidcDiscoveryDoc();
        $doc->issuer = self::ISSUER;

        $discovery = $this->createMock(OidcDiscoveryService::class);
        $discovery->method('get')->willReturn($doc);
        $discovery->method('getJwks')->willReturn($this->jwks);

        return new LogtoTokenValidator($discovery, self::AUDIENCE);
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function signToken(array $claims): string
    {
        return JWT::encode($claims, $this->privateKey, 'RS256', self::KID);
    }

    private static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
