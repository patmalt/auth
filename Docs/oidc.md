# OIDC configuration and migration

The service is now exclusively an OpenID Connect provider. Clients use authorization code + S256 PKCE. Passkeys are created and verified on the provider's hosted authorization page; clients never exchange a passkey assertion directly for a custom JWT.

## Required configuration

| Variable | Meaning |
|---|---|
| `OIDC_ISSUER` | HTTPS origin without a path, query, fragment or trailing slash |
| `OIDC_SIGNING_KEY_PEM` | Persistent P-256 signing private key, injected from secrets storage |
| `OIDC_CLIENTS_JSON` | Array of `{ "clientID": "...", "redirectURIs": ["..."] }` |
| `RP_ORIGIN` | Exactly `OIDC_ISSUER` |
| `RP_ID` | WebAuthn relying party ID valid for the provider origin |
| `RP_NAME` | Name displayed when creating passkeys |
| `STORE_DRIVER` | `dynamodb` (default), or explicit local-only `memory` |
| `AWS_REGION` | Region for both credentials and grants |
| `DYNAMODB_CREDENTIALS_TABLE` | Existing credential table, default `PasskeyCredentials` |
| `DYNAMODB_OIDC_TABLE` | Shared grant table, default `OIDCGrants` |
| `CORS_ALLOWED_ORIGINS` | Comma-separated browser client origins |

Static registration supports public clients only (`token_endpoint_auth_method=none`). Exact redirect URI matching includes scheme, host, port, path and query. HTTPS callbacks, explicitly registered loopback HTTP IP callbacks, and reverse-DNS custom native schemes are supported. Use separate client IDs for web and native apps.

Invalid/missing OIDC configuration fails startup. Keep issuer, RP configuration, client registry and signing key identical on all instances. Synchronize server clocks. There is no per-instance fallback from DynamoDB to memory.

## Shared grants

`DynamoDBGrantStore` persists every login transaction, code, access token, refresh-token generation and token-family revocation in the shared table. Security-sensitive reads use strong consistency. Transactions check random record revisions and application-level expiration before applying writes atomically.

- Starting a passkey ceremony replaces the transaction only if its previous revision is current.
- Completion consumes the login transaction once, across all instances.
- Code redemption consumes the code and creates the access/refresh/family records in one transaction.
- Refresh consumes the previous generation, stores a used-token tombstone, creates replacement tokens, and advances the family revision in one transaction.
- Every issuance checks/updates the same family record as revocation. Concurrent revocation cannot be overwritten by a stale refresh.
- Used refresh records are retained until the original session expiration. Reuse revokes the family and all its access tokens, on every instance.
- UserInfo reads both the access-token record and the shared family status.
- Revocation compares and replaces the family revision, retrying conflicts within a bounded loop.

DynamoDB TTL removes expired records eventually; it never decides whether a token is valid. The application and write conditions reject expired records immediately. Random codes and tokens appear only as SHA-256 hashes in record keys. Grant records contain identity data and should use normal AWS encryption and least-privilege access controls. Never log token request/response bodies or authorization query strings.

Multiple instances and process restarts are supported with DynamoDB. `STORE_DRIVER=memory` intentionally loses sessions on restart and cannot support multiple processes. Regional strong consistency/transactions are required; this is not a multi-region active-active Global Tables design. Signing-key overlap/rotation is not implemented: replacing the key can make still-valid ID tokens unverifiable.

## Client flow and validation

1. Fetch `/.well-known/openid-configuration` at the configured issuer. Verify its exact issuer and permitted HTTPS endpoints. Fetch public signing keys from `jwks_uri`.
2. Generate independent cryptographically random state, nonce and PKCE verifier; calculate unpadded `BASE64URL(SHA256(verifier))`.
3. Open `authorization_endpoint` with `response_type=code`, registered `client_id` and exact `redirect_uri`, `scope=openid profile`, state, nonce, challenge, and `code_challenge_method=S256`. Native apps use `ASWebAuthenticationSession`.
4. On the provider page, the user signs in or creates a passkey and explicitly authorizes the displayed client/scopes. Registration refuses an already registered username using a conditional credential write.
5. On callback, verify exact callback destination, unique response parameters, state, issuer and transaction age. Consume locally retained state/nonce/verifier once. Reject errors before exchanging any code.
6. POST form data to `token_endpoint`: `grant_type=authorization_code`, `client_id`, `redirect_uri`, `code`, `code_verifier`.
7. Validate the ID token's ES256 signature against the matching public `kid`, exact issuer, audience/authorized party, subject, expiry, issue/not-before times, and original nonce. The samples support this provider's single-string-audience profile.
8. Call UserInfo with the opaque access token and verify its subject matches the validated ID token.

Public subjects use the stored WebAuthn user ID. `profile` releases `preferred_username`; a username is not a verified email. ID tokens assert identity and are not API bearer credentials. The former HMAC JWT format is no longer issued or accepted.

Authorization transactions last 5 minutes, codes 60 seconds, access and ID tokens 10 minutes. The provider uses a Secure, HttpOnly, SameSite=Lax browser transaction cookie, same-origin JSON checks, CSP, exact WebAuthn origin validation and required user verification.

## Refresh and sign-out

Native clients request `offline_access` along with `openid profile` and authorize that access on the hosted page. Refresh with form fields `grant_type=refresh_token`, `client_id`, and `refresh_token`. Each success replaces the refresh token; store it securely and serialize refreshes. The session ends 30 days after initial code redemption; rotation does not extend it. Refreshed ID tokens preserve `auth_time`, omit nonce and must match the existing subject.

`OIDCClient` is an actor that owns token state, networking, validation and Keychain access. A separate `@MainActor` browser-session bridge presents `ASWebAuthenticationSession`. An operation guard prevents actor reentrancy from overlapping refresh/sign-in/sign-out operations across suspension points.

The native sample removes a consumed refresh token from Keychain before sending the request and stores its replacement after validation. Network loss during refresh requires sign-in again rather than replaying the consumed token. This trades seamless recovery for avoiding ambiguous reuse. Never retry a refresh blindly.

Sign-out clears local state and POSTs `client_id` and `token` to the revocation endpoint. Revocation invalidates the entire family. This is local sign-out plus token revocation, not OIDC RP-initiated or back-channel logout; no reusable provider SSO cookie is created. The web sample requests no refresh token and holds its access token only in memory.

## Removed interfaces

`/register/begin`, `/register/complete`, `/authenticate/begin`, `/authenticate/complete` and `/me` return 404. The standalone registration/authentication SDK and HMAC JWT service have been removed. Registration remains a provider capability behind the OIDC browser transaction. The old challenge table and `JWT_*` settings are no longer used. Existing passkey credential records remain compatible; old sessions must sign in again.

Supported scopes: `openid`, `profile`, `offline_access`. Unsupported features include implicit/hybrid grants, confidential clients, dynamic registration, federation, email claims, request objects, arbitrary claims requests, general token introspection and general-purpose resource audiences. The implementation is not OpenID certified.

References: [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html), [Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html), [PKCE](https://www.rfc-editor.org/rfc/rfc7636), [Revocation](https://www.rfc-editor.org/rfc/rfc7009), [DynamoDB transactions](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html).
