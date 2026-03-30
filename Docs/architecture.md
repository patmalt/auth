# Passkey Auth Service Architecture

## S3

- Hosts web assets in private bucket with the name of the root domain `example.com`

## EC2

- Security groups
  - `auth-alb-sg`
    - Inbound
      - HTTPS 443 0.0.0.0/0
      - HTTP 80 0.0.0.0/0
    - Outbound
      - All 0.0.0.0/0
  - `auth-ecs-sg`
    - Inbound
      - TCP 8080 `auth-alb-sg`
      - HTTP 80 `auth-alb-sg`
    - Outbound
      - All 0.0.0.0/0

## CloudFront

- Distribution for the root domain `example.com`. 
- Origin pointing to web assets S3 bucket.
- Behavior to redirect HTTP to HTTPS.
- Add invalidations when assets need to be updated.

## Route53

- Hosted zone for root domain (`example.com`).
- `CNAME` records for ACM certificates.
- `A` record for root domain (`example.com`) with a value of the Cloudfront distribution.
- `A` record for Application Load Balancer with a value of ALB from the ECS Cluster's Service.

## AWS Certificate Manager (ACM)

- Certificate for root domain where an app will be served (`example.com`). Add CNAME record to Route53.
- Certificate for domain where the auth service will be served (`auth.example.com`). Add CNAME record to Route53.

## Secrets Manager

- Secret containing the JWT_SECRET.
- Plaintext: `{"JWT_SECRET":"__VALUE__"}`

## IAM Roles

- `auth-ecs-exec-role`
  - `AmazonECSTaskExecutionRolePolicy`
  - `auth-ecs-exec-policy`
    - `Allow` `secretsmanager:GetSecretValue` Secrets Manager ARN
- `auth-ecs-role`
  - `Allow` `dynamodb:*` DynamoDB tables ARNs
  - `Allow` `logs:CreateLogStream` `logs:PutLogEvents` `*`

## DynamoDB

- `PasskeyCredentials`
  - Partition key: `username`
  - Attributes: `credential_id`, `user_id`, `public_key_x963`, `sign_count`
- `PasskeyChallenges`
  - Partition key: `username`
  - Attributes: `challenge`, `user_id`, `kind`, `expires_at`
  
## Elastic Container Repository

- Repository containing docker images.

## Elastic Container Service

### Task Definitions

- AWS Fargate
- Linux/ARM64
- Task role `auth-ecs-role`
- Task execution role `auth-ecs-exec-role`
- Latest image from ECR repository
- Port Mapping
  - 8080 TCP auth-8080-tcp HTTP
- Environment variables
  - `RP_ID=example.com`
  - `RP_NAME=Auth Demo`
  - `RP_ORIGIN=https://example.com`
  - `STORE_DRIVER=dynamodb`
  - `AWS_REGION=us-east-1`
  - `DYNAMODB_CREDENTIALS_TABLE=PasskeyCredentials`
  - `DYNAMODB_CHALLENGES_TABLE=PasskeyChallenges`
  - `JWT_ISSUER=auth-service`
  - `JWT_AUDIENCE=auth-clients`
  - `JWT_SECRET` from Secrets Manager ARN
  - `AUTH_LOG_LEVEL=info` (set `debug` temporarily when you need more request detail in CloudWatch)
    
### Cluster

- Service
  - Task definition from above.
  - Networking
    - all subnets
    - Security groups `auth-ecs-sg`
    - Public IP
  - Load balancing
    - Listeners
      - HTTPS:443
    - Load balancer
      - `auth-alb`
        - Forward to target group `auth-alb-tg`
        - ACM certificate for auth domain `auth.example.com`
        - Securty group `auth-alb-sg`
    - Target group
      - `auth-alb-tg`
        - IP `HTTP:8080`


## JWT shape

The issued JWT includes:

- `sub`: `username:credential_id`
- `username`
- `credential_id`
- `iss`
- `aud`
- `iat`
- `exp`
