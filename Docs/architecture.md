# AWS deployment

Run AuthService on EC2 or ECS behind an HTTPS reverse proxy or load balancer. All instances share the same AWS region, DynamoDB tables, OIDC issuer, registered clients and persistent P-256 signing key. Routing does not require sticky sessions.

## Tables

- `PasskeyCredentials`: existing partition key `username` (String), no sort key. Existing records are compatible.
- `OIDCGrants`: partition key `pk` (String), no sort key. Enable TTL on `ttl` (Number, epoch seconds). Application checks and transaction conditions enforce expiration independently of TTL cleanup.

[oidc-storage.yaml](../Infrastructure/oidc-storage.yaml) creates the grant table with on-demand billing, server-side encryption and point-in-time recovery. Its output is the table name for `DYNAMODB_OIDC_TABLE`.

The former passkey challenge table is no longer used. Do not delete it until the migration is verified and any desired rollback window has ended. Old JWT sessions will stop working when clients/server are upgraded.

## IAM

Give the server role `dynamodb:GetItem`, `dynamodb:PutItem` and `dynamodb:UpdateItem` for the credentials table. For the grant table, allow `dynamodb:GetItem`, `dynamodb:PutItem`, `dynamodb:DeleteItem`, and `dynamodb:ConditionCheckItem` for the corresponding transactional operations. DynamoDB authorizes transactions using the permissions for each item action. Restrict resources to the two table ARNs. Normal production operation needs no scans, table creation, or table deletion.

The DynamoDB Local integration tests create/delete disposable tables using dummy credentials; those permissions belong only in the test environment.

## Configuration and rollout

1. Create the grant table and role policy; inject the same signing key into all instances from your secret manager. Keep it out of images and git.
2. Register the exact web and native callback URLs in `OIDC_CLIENTS_JSON` and configure both samples with the same issuer/client IDs.
3. Terminate TLS at the issuer origin and forward requests to port 8080. `RP_ORIGIN` must equal `OIDC_ISSUER`; `RP_ID` must be valid for that origin. Serve registration/sign-in from this origin.
4. Set `CORS_ALLOWED_ORIGINS` to the web client origin. Provider login/register completion separately requires the provider's own Origin and transaction cookie.
5. Deploy the updated server and sample clients together. The old custom routes and JWT format are removed. Existing passkeys remain usable through hosted OIDC sign-in.
6. Verify registration, code redemption, refresh, UserInfo and revocation while requests are spread across at least two instances; restart an instance and verify that the session remains usable.

Do not cache authorization pages or token responses. Strip authorization query strings and token bodies from application/proxy logs. Keep machine clocks synchronized. Use a single region; eventual replication through Global Tables does not provide the cross-region transaction semantics required here. Signing-key overlap and rotation remain future work.

See [OIDC documentation](oidc.md) for configuration, validation and token lifetime details.
