<?php

declare(strict_types=1);

namespace Tests\Ratespecial\Logto\Models;

use PHPUnit\Framework\TestCase;
use Ratespecial\Logto\Models\OidcDiscoveryDoc;

/**
 * Verifies hydration of {@see OidcDiscoveryDoc} from the example response
 * provided in Section 4.2 of OpenID Connect Discovery 1.0.
 *
 * @see https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse
 */
class OidcDiscoveryDocTest extends TestCase
{
    /**
     * Example document copied verbatim from Section 4.2 of the spec.
     */
    private const string EXAMPLE_JSON = <<<'JSON'
    {
     "issuer":
       "https://server.example.com",
     "authorization_endpoint":
       "https://server.example.com/connect/authorize",
     "token_endpoint":
       "https://server.example.com/connect/token",
     "token_endpoint_auth_methods_supported":
       ["client_secret_basic", "private_key_jwt"],
     "token_endpoint_auth_signing_alg_values_supported":
       ["RS256", "ES256"],
     "userinfo_endpoint":
       "https://server.example.com/connect/userinfo",
     "check_session_iframe":
       "https://server.example.com/connect/check_session",
     "end_session_endpoint":
       "https://server.example.com/connect/end_session",
     "jwks_uri":
       "https://server.example.com/jwks.json",
     "registration_endpoint":
       "https://server.example.com/connect/register",
     "scopes_supported":
       ["openid", "profile", "email", "address",
        "phone", "offline_access"],
     "response_types_supported":
       ["code", "code id_token", "id_token", "id_token token"],
     "acr_values_supported":
       ["urn:mace:incommon:iap:silver",
        "urn:mace:incommon:iap:bronze"],
     "subject_types_supported":
       ["public", "pairwise"],
     "userinfo_signing_alg_values_supported":
       ["RS256", "ES256", "HS256"],
     "userinfo_encryption_alg_values_supported":
       ["RSA-OAEP-256", "A128KW"],
     "userinfo_encryption_enc_values_supported":
       ["A128CBC-HS256", "A128GCM"],
     "id_token_signing_alg_values_supported":
       ["RS256", "ES256", "HS256"],
     "id_token_encryption_alg_values_supported":
       ["RSA-OAEP-256", "A128KW"],
     "id_token_encryption_enc_values_supported":
       ["A128CBC-HS256", "A128GCM"],
     "request_object_signing_alg_values_supported":
       ["none", "RS256", "ES256"],
     "display_values_supported":
       ["page", "popup"],
     "claim_types_supported":
       ["normal", "distributed"],
     "claims_supported":
       ["sub", "iss", "auth_time", "acr",
        "name", "given_name", "family_name", "nickname",
        "profile", "picture", "website",
        "email", "email_verified", "locale", "zoneinfo",
        "http://example.info/claims/groups"],
     "claims_parameter_supported":
       true,
     "service_documentation":
       "http://server.example.com/connect/service_documentation.html",
     "ui_locales_supported":
       ["en-US", "en-GB", "en-CA", "fr-FR", "fr-CA"]
    }
    JSON;

    public function testHydratesDefinedFieldsFromSpecExample(): void
    {
        $doc = OidcDiscoveryDoc::fromArray(json_decode(self::EXAMPLE_JSON, true));

        $this->assertSame('https://server.example.com', $doc->issuer);
        $this->assertSame('https://server.example.com/connect/authorize', $doc->authorization_endpoint);
        $this->assertSame('https://server.example.com/connect/token', $doc->token_endpoint);
        $this->assertSame('https://server.example.com/connect/userinfo', $doc->userinfo_endpoint);
        $this->assertSame('https://server.example.com/jwks.json', $doc->jwks_uri);
        $this->assertSame('https://server.example.com/connect/register', $doc->registration_endpoint);
        $this->assertSame('http://server.example.com/connect/service_documentation.html', $doc->service_documentation);

        $this->assertSame(['client_secret_basic', 'private_key_jwt'], $doc->token_endpoint_auth_methods_supported);
        $this->assertSame(['RS256', 'ES256'], $doc->token_endpoint_auth_signing_alg_values_supported);
        $this->assertSame(['openid', 'profile', 'email', 'address', 'phone', 'offline_access'], $doc->scopes_supported);
        $this->assertSame(['code', 'code id_token', 'id_token', 'id_token token'], $doc->response_types_supported);
        $this->assertSame(['urn:mace:incommon:iap:silver', 'urn:mace:incommon:iap:bronze'], $doc->acr_values_supported);
        $this->assertSame(['public', 'pairwise'], $doc->subject_types_supported);
        $this->assertSame(['RS256', 'ES256', 'HS256'], $doc->userinfo_signing_alg_values_supported);
        $this->assertSame(['RSA-OAEP-256', 'A128KW'], $doc->userinfo_encryption_alg_values_supported);
        $this->assertSame(['A128CBC-HS256', 'A128GCM'], $doc->userinfo_encryption_enc_values_supported);
        $this->assertSame(['RS256', 'ES256', 'HS256'], $doc->id_token_signing_alg_values_supported);
        $this->assertSame(['RSA-OAEP-256', 'A128KW'], $doc->id_token_encryption_alg_values_supported);
        $this->assertSame(['A128CBC-HS256', 'A128GCM'], $doc->id_token_encryption_enc_values_supported);
        $this->assertSame(['none', 'RS256', 'ES256'], $doc->request_object_signing_alg_values_supported);
        $this->assertSame(['page', 'popup'], $doc->display_values_supported);
        $this->assertSame(['normal', 'distributed'], $doc->claim_types_supported);
        $this->assertSame(
            ['sub', 'iss', 'auth_time', 'acr', 'name', 'given_name', 'family_name', 'nickname',
                'profile', 'picture', 'website', 'email', 'email_verified', 'locale', 'zoneinfo',
                'http://example.info/claims/groups'],
            $doc->claims_supported,
        );
        $this->assertTrue($doc->claims_parameter_supported);
        $this->assertSame(['en-US', 'en-GB', 'en-CA', 'fr-FR', 'fr-CA'], $doc->ui_locales_supported);
    }

    public function testCapturesUnknownFieldsAsDynamicProperties(): void
    {
        $doc = OidcDiscoveryDoc::fromArray(json_decode(self::EXAMPLE_JSON, true));

        // check_session_iframe and end_session_endpoint are not defined on the class
        // (they originate from the OpenID Connect Session Management spec) and so
        // must land as dynamic properties.
        $vars = get_object_vars($doc);
        $this->assertArrayHasKey('check_session_iframe', $vars);
        $this->assertArrayHasKey('end_session_endpoint', $vars);
        $this->assertSame('https://server.example.com/connect/check_session', $vars['check_session_iframe']);
        $this->assertSame('https://server.example.com/connect/end_session', $vars['end_session_endpoint']);
    }

    public function testUnsetOptionalFieldsRemainNull(): void
    {
        $doc = OidcDiscoveryDoc::fromArray(['issuer' => 'https://server.example.com']);

        $this->assertSame('https://server.example.com', $doc->issuer);
        $this->assertNull($doc->op_policy_uri);
        $this->assertNull($doc->grant_types_supported);
        $this->assertNull($doc->request_parameter_supported);
    }
}
