# Passkey OpenID Connect provider

A SwiftNIO identity provider using passkeys for authentication and OpenID Connect authorization code + S256 PKCE for client sign-in.

- Browser-hosted passkey registration, sign-in and explicit authorization.
- Discovery, public JWKS, ES256 ID tokens and opaque access tokens.
- UserInfo, rotating refresh tokens, reuse detection and family revocation.
- Shared DynamoDB storage for login transactions, authorization codes, tokens and revocations.
- A native Apple sample using `ASWebAuthenticationSession` and Keychain.
- A static web sample using browser redirects and WebCrypto validation.

## Configure and run

See [OIDC configuration and client integration](Docs/oidc.md) and [AWS architecture](Docs/architecture.md).

```sh
openssl ecparam -name prime256v1 -genkey -noout -out /tmp/oidc-key.pem
export OIDC_SIGNING_KEY_PEM="$(cat /tmp/oidc-key.pem)"
export OIDC_ISSUER=https://auth.example.com
export RP_ORIGIN=https://auth.example.com
export RP_ID=auth.example.com
export OIDC_CLIENTS_JSON='[{"clientID":"auth-demo-macos","redirectURIs":["com.patmalt.authdemo:/callback"]},{"clientID":"auth-demo-web","redirectURIs":["https://app.example.com/index.html"]}]'
export STORE_DRIVER=dynamodb
export AWS_REGION=us-east-1
export DYNAMODB_CREDENTIALS_TABLE=PasskeyCredentials
export DYNAMODB_OIDC_TABLE=OIDCGrants
swift run AuthService
```

Use your real HTTPS domain, callback URL and AWS credentials/role. Keep the signing key in a secret manager in production. The service listens on port 8080 behind an HTTPS proxy. DynamoDB is the default store; `STORE_DRIVER=memory` is an explicit single-process development mode.

## Routes

| Route | Purpose |
|---|---|
| `GET /`, `GET /health` | Health checks |
| `GET /.well-known/openid-configuration` | OIDC discovery |
| `GET /oauth/jwks` | Public ES256 signing key |
| `GET /oauth/authorize` | Browser authorization page |
| `POST /oauth/login/begin` | Cookie-bound passkey ceremony (`mode=register` for registration) |
| `POST /oauth/login/complete` | Verify assertion and finish authorization |
| `POST /oauth/register/complete` | Verify registration and finish authorization |
| `POST /oauth/token` | Code exchange or refresh |
| `GET/POST /oauth/userinfo` | Bearer-token identity claims |
| `POST /oauth/revoke` | Revoke a token family |

The `/oauth/login/*` and `/oauth/register/*` routes are provider UI internals, not alternative client sign-in APIs. The provider page sends JSON; token and revocation requests use form encoding. OAuth errors use `{ "error": "invalid_grant" }` style responses.

**Breaking migration:** `/register/*`, `/authenticate/*`, `/me`, legacy HMAC JWTs and the `JWT_*` environment variables have been removed. Update downstream services to use OIDC access-token validation through the provider's supported UserInfo endpoint; never treat an ID token as an API access token. There is no general-purpose token introspection or business API audience in this demo.

## Samples

**Web:** edit `Samples/AuthDemoWebApp/config.js`, register the exact callback URL, and host the directory on HTTPS. Add that frontend origin to `CORS_ALLOWED_ORIGINS`. Sign-in and registration occur on the provider origin; the frontend no longer needs to share `RP_ORIGIN`. Access/ID tokens are never saved to browser storage. Only the five-minute PKCE/state/nonce transaction is kept in `sessionStorage`; reload after sign-in requires a fresh sign-in. The web sample deliberately does not request a refresh token.

**macOS:** open `AuthDemoMacApp.xcodeproj` and configure `AUTH_DEMO_ISSUER`, `AUTH_DEMO_CLIENT_ID`, and `AUTH_DEMO_REDIRECT_URI` in the target build settings. The defaults match the configuration above. Sign-in and registration use the system browser; the app no longer needs passkey associated-domain entitlements. Refresh tokens are held in Keychain, and refresh requests are serialized. Use “Restore / Refresh session” to resume after restarting the app.

## Verification

```sh
swift test
node --test Tests/Web/*.test.mjs
swift build --target AuthKit # On macOS
```

Run the checks above locally. Set `DYNAMODB_TEST_ENDPOINT` plus local AWS credentials to include DynamoDB integration tests; those tests create and delete uniquely named test tables. No CI workflow is configured.

Browser/passkey hardware and signed app Keychain flows still need to be exercised with your real domains and registered callbacks. This project is not OpenID certified.
