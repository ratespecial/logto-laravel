# ID tokens vs access tokens

Logto issues two kinds of token, and this package handles each one differently. This page explains what each token is for, how to tell them apart, and where each one appears in the package.

## Table of contents

- [Summary](#summary)
- [ID tokens](#id-tokens)
- [Access tokens](#access-tokens)
- [Side-by-side comparison](#side-by-side-comparison)
- [Common mistakes](#common-mistakes)
- [How this package uses them](#how-this-package-uses-them)
  - [API guard](#api-guard)
  - [Web sign-in](#web-sign-in)
- [References](#references)

## Summary

- An **ID token** tells *your application* who the user is. It comes from OpenID Connect (OIDC).
- An **access token** tells *an API* what the holder may do there. It comes from OAuth 2.0.

An ID token is meant to be read by the client that requested it. An access token is meant to be sent to an API, and the client should treat it as an opaque credential.

## ID tokens

An ID token is a signed JWT that proves a user authenticated with the identity provider. It is defined by [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html#IDToken), and Logto returns one when the `openid` scope is requested.

Key properties:

- **Audience (`aud`)** is the client (application) ID. The token was issued *to the app*.
- **Contents** describe the user and the sign-in event: `sub`, `iss`, `aud`, `exp`, `iat`, `nonce`, plus profile claims such as `name` or `email` when the `profile`/`email` scopes are requested.
- **Always a JWT**, so the client can validate it and read its claims.
- **Not sent anywhere.** The client validates it once at sign-in, then uses it to create its own session.

## Access tokens

An access token is a credential the client presents to a resource server (an API) in an `Authorization: Bearer` header. It is defined by [OAuth 2.0 (RFC 6749)](https://datatracker.ietf.org/doc/html/rfc6749#section-1.4).

Key properties:

- **Audience (`aud`)** is the API resource indicator, such as `https://api.example.com`. The token was issued *for that API*.
- **Contents** describe the grant: `sub`, `scope`, `client_id`, `exp`. They don't describe the user's profile.
- **Format is up to the provider.** OAuth doesn't require JWTs. Logto issues a JWT ([RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068) profile) only when the authorization request names an API resource via the `resource` parameter ([RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707)). Otherwise it issues an [opaque token](https://docs.logto.io/concepts/opaque-token) that is only useful against Logto's own userinfo endpoint.
- **Scopes** come from the Logto roles assigned to the user. A role grants a set of permissions (scopes) on an API resource.

## Side-by-side comparison

|                    | ID token                                  | Access token                                        |
|--------------------|-------------------------------------------|-----------------------------------------------------|
| Spec               | OpenID Connect                            | OAuth 2.0                                           |
| Answers            | Who is the user?                          | What may the holder do at this API?                 |
| Intended reader    | The client application                    | The API (resource server)                           |
| `aud`              | Client / app ID                           | API resource indicator                              |
| Typical claims     | `sub`, `nonce`, `email`, `name`, ...      | `sub`, `scope`, `client_id`, ...                    |
| Format             | Always a JWT                              | JWT with a resource, otherwise opaque (in Logto)    |
| Sent to an API?    | No                                        | Yes, as a Bearer token                              |
| Contains scopes?   | No (OIDC scopes only control which claims appear) | Yes, the API permissions granted            |

## Common mistakes

- **Sending an ID token to an API.** Its audience is the app, not the API, so a correctly written API rejects it. Even if it were accepted, it carries no API scopes.
- **Using an access token to identify the user in the client.** The client shouldn't parse an access token. Its format can change, and it may be opaque.
- **Skipping the audience check.** A token signed by the right issuer but meant for a different app or API must be rejected. Otherwise a token issued to one service could be replayed against another.
- **Matching tokens by trust alone.** When a flow receives both tokens, check that they share the same `sub` before combining their claims.

## How this package uses them

Both kinds of token go through `LogtoTokenValidator`, which checks the signature against Logto's JWKS, the `iss` claim against the discovery document, and `aud` against the expected audience. The only difference is which audience is expected.

### API guard

`LogtoApiResourceGuard` (`auth:logto`) accepts **access tokens only**:

- The audience must be `logto.api-resource`.
- The token must have a non-empty `sub` and `scope`.
- The scopes are attached to the user, so `can:<scope>` middleware and `$user->can('<scope>')` work through the package's `Gate::before` hook.

An ID token sent to this guard fails the audience check.

### Web sign-in

`WebAuthController` uses the **ID token** to identify the user:

- `LogtoWebClient::validateIdToken()` validates it with the web app ID as the audience and checks the `nonce` stored in the session.
- Its claims (`sub`, `email`, ...) are passed to `UserResolver`.

When `logto.web.resource` is set, the authorization request also names that resource and requests the permissions in `logto.web.resource-scopes` and `logto.web.required-scopes` (Logto only issues permissions that are asked for by name). Logto then returns a JWT **access token** alongside the ID token. `WebAuthController::withApiScope()` then:

1. Validates the access token with the resource as the audience.
2. Requires its `sub` to match the ID token's `sub`.
3. Requires at least one of the requested permissions, plus every permission in `logto.web.required-scopes`.
4. Copies its `scope` into the ID token claims, because ID tokens don't carry API scopes.

This is how Logto roles can gate browser sign-in. Without `logto.web.resource`, no access token is checked, and any user who can sign in to the Logto app gets a session.

## References

- [OpenID Connect Core 1.0: ID Token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken): the spec that defines ID tokens and their required claims.
- [RFC 6749: The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749): defines access tokens and scopes.
- [RFC 7519: JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519): the token format and registered claims (`iss`, `sub`, `aud`, `exp`, ...).
- [RFC 9068: JWT Profile for OAuth 2.0 Access Tokens](https://datatracker.ietf.org/doc/html/rfc9068): how access tokens look when issued as JWTs.
- [RFC 8707: Resource Indicators for OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc8707): the `resource` parameter that sets an access token's audience.
- [RFC 7636: Proof Key for Code Exchange (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636): protects the authorization code used in web sign-in.
- [RFC 9700: OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/rfc9700): guidance on audience restriction and token handling.
- [oauth.net: ID Tokens vs Access Tokens](https://oauth.net/id-tokens-vs-access-tokens/): a short explainer of the difference.
- [Auth0: ID Token and Access Token: What Is the Difference?](https://auth0.com/blog/id-token-access-token-what-is-the-difference/): a longer walkthrough with examples.
- [Logto: Protect global API resources](https://docs.logto.io/authorization/global-api-resources): API resources, permissions and roles in Logto.
- [Logto: Opaque token](https://docs.logto.io/concepts/opaque-token): when Logto issues opaque access tokens instead of JWTs.
