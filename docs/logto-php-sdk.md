# Evaluation: switching to `logto/sdk` (logto-io/php)

**Date:** 2026-11-06
**SDK version evaluated:** `logto/sdk` v0.3.1 ([logto-io/php](https://github.com/logto-io/php)). Last feature commit was 2024-11-28; everything since is dependency bumps.

## Verdict: don't switch

`logto/sdk` would replace about 150 lines of our code at most. To get that, we'd take on more code to make it work inside Laravel, four extra dependencies, and a weaker web sign-in flow. It doesn't help with the main thing this package does, which is validating access tokens for the API guard.

## What the SDK covers

It's a session-based client for one PHP app. `LogtoClient` handles sign-in, the callback, sign-out, token refresh and user info, and `OidcCore` handles discovery, ID token checks and the token endpoint. That's all of it.

| Our component | Does the SDK replace it? |
|---|---|
| `LogtoApiResourceGuard` + `LogtoTokenValidator` (validating API access tokens) | **No.** The SDK never checks an access token. `getAccessTokenClaims()` just base64-decodes the payload with no signature check. |
| `OidcDiscoveryService` + `OidcDiscoveryDoc` | Partly. It fetches discovery itself, but through its own Guzzle client and a file cache. |
| `LogtoWebClient` (authorize URL, code exchange, ID token check, logout URL) | Mostly. This is the ~150 lines it could replace. |
| `WebAuthController` | No. It would still be needed, and its callback would be different (see below). |
| `UserResolver`, `HasOAuthScopes`, `Gate::before`, MCP metadata routes, `src/Testing/*` | No. These are specific to Laravel or to us. |

## Problems with using it

### Security: a step down from what we have now

- **No nonce.** It never sends one or checks one, so the ID token isn't tied to the sign-in attempt. Ours does both.
- **Plain `!==` for comparing state** instead of `hash_equals`.
- **Doesn't handle `?error=`.** If a user cancels at Logto, they get a generic "Code not found." error.
- **Fragile callback check.** `handleSignInCallback()` reads `$_SERVER['SERVER_NAME']` and `REQUEST_URI` directly and compares them to the redirect URI. Behind an AWS load balancer, `SERVER_NAME` is the nginx server name. Laravel's TrustProxies doesn't change `$_SERVER`, so this check can fail in production. It also bypasses Laravel's `Request`.

### It doesn't fit Laravel

- `SessionStorage` calls `session_start()` and uses `$_SESSION` directly. We'd have to write a storage adapter for Laravel's session.
- `new LogtoClient()` fetches the discovery document in its constructor, every time it's created. Neither the HTTP client nor the cache can be swapped out from outside.
- Discovery and keys are cached with **phpfastcache's Files driver in `/tmp`**. That cache is per server, not Laravel's cache, and `cache:clear` can't empty it.
- Because it uses its own raw Guzzle client, **`Http::fake` doesn't intercept it**. `WebSignInTest` and `FakeOidcDiscoveryService`/`LogtoFake` would stop covering the web flow unless we subclass it to inject our own `OidcCore`.
- It always adds `offline_access` and `profile` to the scopes, defaults to `prompt=consent`, and stores the ID token, refresh token and access tokens in the session. We only need the tokens once, at sign-in.
- It sends the client secret in the request body. We use HTTP Basic.

### Dependencies

It adds `guzzlehttp/guzzle`, `phpfastcache/phpfastcache`, `vlucas/phpdotenv` (a runtime requirement, though a library has no reason to load `.env` files) and `phpoption`/`result-type`. phpfastcache ran without deprecation warnings on PHP 8.4 and 8.5.

### Code quality

It has no return types and no static analysis, and it builds objects by spreading JSON into constructors, so an unexpected response shape throws a `TypeError`.

There is also a real bug: `getIdTokenClaims()` and `getAccessTokenClaims()` decode base64url with plain `base64_decode()`. When a token payload contains `-` or `_`, the result is `null`. Reproduced on PHP 8.4.

## What it would actually simplify

Very little:

- Building the authorize URL. It also exposes Logto extras (`first_screen`, `direct_sign_in`, `interaction_mode`, organization URNs) that we don't use.
- The PKCE code challenge. That's one line, and it uses the same `JWT::urlsafeB64Encode` we already call.
- Refresh tokens and the userinfo endpoint. We don't use either.

The guard, user resolution, scopes, MCP routes and the test fake would stay as they are. The web flow would lose the nonce and error handling, and gain an adapter plus workarounds for the tests.

## One thing worth taking from it

The SDK verifies tokens with `firebase/php-jwt`'s `CachedKeySet`. When a token is signed with a key ID (`kid`) that isn't in the cache, it re-fetches the key set (JWKS), with a rate limit. **We don't do this.** `OidcDiscoveryService::getJwks()` caches the key set for `logto.cache-ttl` (600s by default). If Logto rotates its signing key, every new token could fail validation, on both the API guard and web sign-in, for up to 10 minutes.

**Done.** We didn't use `CachedKeySet` itself, because it needs a PSR-6 cache pool and a PSR-18 HTTP client, which Laravel doesn't provide, and it would bypass Laravel's cache and our test fake. Instead, when a token's `kid` isn't in the cached key set, `LogtoTokenValidator` calls `OidcDiscoveryService::refreshJwks()`. That refetches the JWKS and updates the cache, at most once every 60 seconds, so tokens with made-up key IDs can't make every request fetch from Logto. If the refetch fails, the cached key set is kept and the token is rejected as usual.
