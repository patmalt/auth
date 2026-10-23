# OpenID Connect provider

This opt-in provider adds the authorization-code flow with mandatory S256 PKCE to the existing passkey service. Existing registration, authentication and `/me` APIs remain available. OIDC access tokens are opaque and work with `/oauth/userinfo`; legacy API JWTs remain separate.

## Configure

Terminate HTTPS at your load balancer or reverse proxy. The provider must be reachable at an HTTPS origin with no path prefix. Its origin must match `RP_ORIGIN`, and `RP_ID` must be valid for that origin.

Generate a persistent P-256 private key outside the repository:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out oidc-key.pem
export OIDC_SIGNING_KEY_PEM="$(cat oidc-key.pem)"
export OIDC_ISSUER=https://auth.example.com
export RP_ORIGIN=https://auth.example.com
export RP_ID=auth.example.com
export OIDC_CLIENTS_JSON='[{"clientID":"my-app","redirectURIs":["com.example.myapp:/callback","https://app.example.com/callback"]}]'
```

Store the private key in your secret manager, and inject it at startup. Do not commit it. Invalid or partial configuration fails startup when `OIDC_ISSUER` is set; omitting `OIDC_ISSUER` disables OIDC. Only statically registered public clients (`token_endpoint_auth_method=none`) are supported. Redirect URIs are matched exactly, including loopback ports. Use a reverse-DNS custom scheme for a native app, or an HTTPS callback. HTTP is permitted only for explicitly registered loopback IP callbacks.

**Deployment limit:** authorization transactions, codes, access tokens, refresh tokens and revocations are process-local even when credentials are stored in DynamoDB. Run exactly one instance. Restarting invalidates all OIDC sessions. Do not use this implementation with multiple replicas or rolling deployments that overlap instances. A durable grant store with conditional/transactional consume operations is required before scaling out. Keep the signing key stable across restarts; key rotation with overlapping published keys is not implemented.

## Client flow

1. Discover `GET /.well-known/openid-configuration` at the issuer. Fetch signing keys from its `jwks_uri`.
2. Generate independent random `state`, `nonce` and a 43–128 character PKCE verifier. Compute `BASE64URL(SHA256(verifier))`, without padding.
3. Open the authorization URL in the system browser (`ASWebAuthenticationSession` on Apple platforms):

```text
/oauth/authorize?client_id=my-app&redirect_uri=com.example.myapp%3A%2Fcallback&response_type=code&scope=openid%20profile%20offline_access&state=RANDOM_STATE&nonce=RANDOM_NONCE&code_challenge=PKCE_HASH&code_challenge_method=S256
```

4. The user signs in with an already registered passkey on the provider's page and explicitly authorizes the displayed client and scopes. Registration is available through the existing registration APIs. The page requires user verification and binds the passkey challenge to a short-lived browser transaction with an HttpOnly cookie and same-origin checks. No reusable browser SSO session is created.
5. At the callback, verify `state` against the locally retained value and verify `iss` is the configured issuer. Handle returned OAuth errors. Exchange the code with `POST /oauth/token`, content type `application/x-www-form-urlencoded`:

```text
grant_type=authorization_code&client_id=my-app&redirect_uri=com.example.myapp%3A%2Fcallback&code=CODE&code_verifier=ORIGINAL_VERIFIER
```

6. Validate the ID token's ES256 signature using JWKS, permitted algorithm, `kid`, exact `iss`, `aud`, `exp`, `iat`, and original `nonce`. Use a maintained OIDC client library. Do not use an ID token to authorize API calls.
7. Call `/oauth/userinfo` with `Authorization: Bearer ACCESS_TOKEN`. Always verify the returned `sub` matches the validated ID token. The public subject is the stored WebAuthn user ID; `profile` additionally releases `preferred_username`. Do not interpret the username as a verified email.

Authorization transactions last 5 minutes, authorization codes 60 seconds, and access/ID tokens 10 minutes. Codes are single-use, bound to client, exact redirect URI and S256 PKCE. `state` is returned unchanged; validating it is the client's responsibility. `nonce`, when supplied, is carried in the initial ID token.

## Refresh and revoke

Request `offline_access` to receive a refresh token after explicit authorization. Refresh with a form POST:

```text
grant_type=refresh_token&client_id=my-app&refresh_token=REFRESH_TOKEN
```

Each successful refresh returns a replacement refresh token. Save it atomically and discard the previous token. Serialize refresh requests: reuse of any consumed token revokes the entire family, including its access tokens. Refresh sessions have a fixed 30-day expiration from initial issuance; rotation does not extend it. Refreshed ID tokens retain the original `auth_time` and omit `nonce`. Refresh scope changes are unsupported (omit `scope` or supply the original set).

Revoke with `POST /oauth/revoke` using the same form content type and `client_id=my-app&token=TOKEN`. Revocation invalidates the token family. Unknown tokens return success. Keep native refresh tokens in Keychain or equivalent secure storage; browser apps should prefer a backend session rather than storing long-lived tokens in JavaScript.

## Scope and verification

Supported scopes are `openid`, `profile`, `offline_access`. Only code/query responses, ES256 signatures, public subjects and public clients are supported. Implicit/hybrid flows, dynamic registration, confidential-client secrets, federation to third-party providers, logout/SSO, email claims, request objects and claims parameters are not implemented. This is not a claim of OpenID certification or full conformance coverage.

`swift test` covers the authorization-to-token flow with a stub passkey verifier, PKCE and redirect rejection, browser transaction replay, refresh replay/family revocation, parsing, signing and JWKS. Actual browser/passkey hardware validation remains a deployment check. The GitHub Actions workflow runs the Swift tests on Linux using Swift 6.2.

References: [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html), [Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html), [PKCE](https://www.rfc-editor.org/rfc/rfc7636), [Token revocation](https://www.rfc-editor.org/rfc/rfc7009).
