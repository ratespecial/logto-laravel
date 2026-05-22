<?php

declare(strict_types=1);

namespace Ratespecial\Logto\Models;

/**
 * Represents an OpenID Provider Configuration Information document as defined by
 * OpenID Connect Discovery 1.0, Section 3.
 *
 * All properties are public to allow direct access. The class is marked with
 * {@see \AllowDynamicProperties} so that any additional metadata fields introduced
 * by future revisions of the specification (or vendor extensions) can still be
 * assigned without requiring a code change.
 *
 * @see https://openid.net/specs/openid-connect-discovery-1_0.html
 */
#[\AllowDynamicProperties]
class OidcDiscoveryDoc
{
    /**
     * URL using the https scheme with no query or fragment components that the OP
     * asserts as its Issuer Identifier.
     */
    public ?string $issuer = null;

    /**
     * URL of the OP's OAuth 2.0 Authorization Endpoint.
     */
    public ?string $authorization_endpoint = null;

    /**
     * URL of the OP's OAuth 2.0 Token Endpoint. This is REQUIRED unless only the
     * Implicit Flow is used.
     */
    public ?string $token_endpoint = null;

    /**
     * URL of the OP's UserInfo Endpoint. This URL MUST use the https scheme.
     */
    public ?string $userinfo_endpoint = null;

    /**
     * URL of the OP's JSON Web Key Set document. This contains the signing key(s)
     * the RP uses to validate signatures from the OP.
     */
    public ?string $jwks_uri = null;

    /**
     * URL of the OP's Dynamic Client Registration Endpoint.
     */
    public ?string $registration_endpoint = null;

    /**
     * JSON array containing a list of the OAuth 2.0 scope values that this server
     * supports. The server MUST support the "openid" scope value.
     *
     * @var list<string>|null
     */
    public ?array $scopes_supported = null;

    /**
     * JSON array containing a list of the OAuth 2.0 response_type values that this
     * OP supports.
     *
     * @var list<string>|null
     */
    public ?array $response_types_supported = null;

    /**
     * JSON array containing a list of the OAuth 2.0 response_mode values that this
     * OP supports. If omitted, the default is ["query", "fragment"].
     *
     * @var list<string>|null
     */
    public ?array $response_modes_supported = null;

    /**
     * JSON array containing a list of the OAuth 2.0 Grant Type values that this OP
     * supports. If omitted, the default value is ["authorization_code", "implicit"].
     *
     * @var list<string>|null
     */
    public ?array $grant_types_supported = null;

    /**
     * JSON array containing a list of the Authentication Context Class References
     * that this OP supports.
     *
     * @var list<string>|null
     */
    public ?array $acr_values_supported = null;

    /**
     * JSON array containing a list of the Subject Identifier types that this OP
     * supports. Valid types include "pairwise" and "public".
     *
     * @var list<string>|null
     */
    public ?array $subject_types_supported = null;

    /**
     * JSON array containing a list of the JWS signing algorithms (alg values)
     * supported by the OP for the ID Token to encode the Claims in a JWT.
     *
     * @var list<string>|null
     */
    public ?array $id_token_signing_alg_values_supported = null;

    /**
     * JSON array containing a list of the JWE encryption algorithms (alg values)
     * supported by the OP for the ID Token.
     *
     * @var list<string>|null
     */
    public ?array $id_token_encryption_alg_values_supported = null;

    /**
     * JSON array containing a list of the JWE encryption algorithms (enc values)
     * supported by the OP for the ID Token.
     *
     * @var list<string>|null
     */
    public ?array $id_token_encryption_enc_values_supported = null;

    /**
     * JSON array containing a list of the JWS signing algorithms (alg values)
     * supported by the UserInfo Endpoint to encode the Claims in a JWT.
     *
     * @var list<string>|null
     */
    public ?array $userinfo_signing_alg_values_supported = null;

    /**
     * JSON array containing a list of the JWE encryption algorithms (alg values)
     * supported by the UserInfo Endpoint.
     *
     * @var list<string>|null
     */
    public ?array $userinfo_encryption_alg_values_supported = null;

    /**
     * JSON array containing a list of the JWE encryption algorithms (enc values)
     * supported by the UserInfo Endpoint.
     *
     * @var list<string>|null
     */
    public ?array $userinfo_encryption_enc_values_supported = null;

    /**
     * JSON array containing a list of the JWS signing algorithms (alg values)
     * supported by the OP for Request Objects.
     *
     * @var list<string>|null
     */
    public ?array $request_object_signing_alg_values_supported = null;

    /**
     * JSON array containing a list of the JWE encryption algorithms (alg values)
     * supported by the OP for Request Objects.
     *
     * @var list<string>|null
     */
    public ?array $request_object_encryption_alg_values_supported = null;

    /**
     * JSON array containing a list of the JWE encryption algorithms (enc values)
     * supported by the OP for Request Objects.
     *
     * @var list<string>|null
     */
    public ?array $request_object_encryption_enc_values_supported = null;

    /**
     * JSON array containing a list of Client Authentication methods supported by
     * this Token Endpoint. If omitted, the default is "client_secret_basic".
     *
     * @var list<string>|null
     */
    public ?array $token_endpoint_auth_methods_supported = null;

    /**
     * JSON array containing a list of the JWS signing algorithms (alg values)
     * supported by the Token Endpoint for the signature on the JWT used to
     * authenticate the Client at the Token Endpoint for "private_key_jwt" and
     * "client_secret_jwt" authentication methods.
     *
     * @var list<string>|null
     */
    public ?array $token_endpoint_auth_signing_alg_values_supported = null;

    /**
     * JSON array containing a list of the display parameter values that the OpenID
     * Provider supports.
     *
     * @var list<string>|null
     */
    public ?array $display_values_supported = null;

    /**
     * JSON array containing a list of the Claim Types that the OpenID Provider
     * supports. Valid types include "normal", "aggregated", and "distributed". If
     * omitted, the implementation supports only "normal" Claims.
     *
     * @var list<string>|null
     */
    public ?array $claim_types_supported = null;

    /**
     * JSON array containing a list of the Claim Names of the Claims that the OpenID
     * Provider MAY be able to supply values for.
     *
     * @var list<string>|null
     */
    public ?array $claims_supported = null;

    /**
     * URL of a page containing human-readable information that developers might want
     * or need to know when using the OpenID Provider.
     */
    public ?string $service_documentation = null;

    /**
     * Languages and scripts supported for values in Claims being returned, represented
     * as a JSON array of BCP47 language tag values.
     *
     * @var list<string>|null
     */
    public ?array $claims_locales_supported = null;

    /**
     * Languages and scripts supported for the user interface, represented as a JSON
     * array of BCP47 language tag values.
     *
     * @var list<string>|null
     */
    public ?array $ui_locales_supported = null;

    /**
     * Boolean value specifying whether the OP supports use of the "claims" parameter.
     * If omitted, the default value is false.
     */
    public ?bool $claims_parameter_supported = null;

    /**
     * Boolean value specifying whether the OP supports use of the "request" parameter.
     * If omitted, the default value is false.
     */
    public ?bool $request_parameter_supported = null;

    /**
     * Boolean value specifying whether the OP supports use of the "request_uri"
     * parameter. If omitted, the default value is true.
     */
    public ?bool $request_uri_parameter_supported = null;

    /**
     * Boolean value specifying whether the OP requires any "request_uri" values used
     * to be pre-registered using the "request_uris" registration parameter. If
     * omitted, the default value is false.
     */
    public ?bool $require_request_uri_registration = null;

    /**
     * URL that the OpenID Provider provides to the person registering the Client to
     * read about the OP's requirements on how the Relying Party can use the data
     * provided by the OP.
     */
    public ?string $op_policy_uri = null;

    /**
     * URL that the OpenID Provider provides to the person registering the Client to
     * read about the OpenID Provider's terms of service.
     */
    public ?string $op_tos_uri = null;

    /**
     * Hydrate an instance from the decoded JSON of a discovery document. Unknown
     * fields are stored as dynamic properties so future spec additions or vendor
     * extensions remain accessible.
     *
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        $doc = new self();

        foreach ($data as $key => $value) {
            $doc->{$key} = $value;
        }

        return $doc;
    }
}
