---
name: cognitox
description: Manage a local AWS Cognito emulator (cognitox). Use when the user needs to create user pools, manage users, test authentication flows, or set up Cognito resources for local development. Triggers on mentions of Cognito, user pools, authentication testing, or cognitox.
license: MIT
compatibility: Requires cognitox running on localhost:9229 (start with cargo run or docker run -p 9229:9229 cognitox)
metadata:
  author: unvalley
  version: "0.1.0"
  repository: https://github.com/unvalley/cognitox
---

# cognitox

Interact with the cognitox AWS Cognito emulator running on localhost.

## When to use

- User asks to create or manage Cognito user pools, clients, users, or groups
- User wants to test authentication flows locally
- User mentions "cognitox", "cognito emulator", or "local cognito"
- User needs to set up a test environment for Cognito-dependent code

## API basics

cognitox implements the full AWS Cognito Identity Provider API. All requests go to `POST http://localhost:9229/` with two headers:

```
Content-Type: application/x-amz-json-1.1
X-Amz-Target: AWSCognitoIdentityProviderService.<OperationName>
```

## Common workflows

### Create a user pool and client

```bash
# Create pool
POOL=$(curl -s http://localhost:9229/ \
  -H "Content-Type: application/x-amz-json-1.1" \
  -H "X-Amz-Target: AWSCognitoIdentityProviderService.CreateUserPool" \
  -d '{"PoolName": "my-pool"}')
POOL_ID=$(echo "$POOL" | jq -r '.UserPool.Id')

# Create client
CLIENT=$(curl -s http://localhost:9229/ \
  -H "Content-Type: application/x-amz-json-1.1" \
  -H "X-Amz-Target: AWSCognitoIdentityProviderService.CreateUserPoolClient" \
  -d "{\"UserPoolId\": \"$POOL_ID\", \"ClientName\": \"my-client\", \"ExplicitAuthFlows\": [\"ALLOW_USER_PASSWORD_AUTH\", \"ALLOW_REFRESH_TOKEN_AUTH\"]}")
CLIENT_ID=$(echo "$CLIENT" | jq -r '.UserPoolClient.ClientId')

echo "Pool: $POOL_ID  Client: $CLIENT_ID"
```

### Register and authenticate a user

```bash
# Sign up
curl -s http://localhost:9229/ \
  -H "Content-Type: application/x-amz-json-1.1" \
  -H "X-Amz-Target: AWSCognitoIdentityProviderService.SignUp" \
  -d "{\"ClientId\": \"$CLIENT_ID\", \"Username\": \"alice\", \"Password\": \"P@ssw0rd!\", \"UserAttributes\": [{\"Name\": \"email\", \"Value\": \"alice@example.com\"}]}"

# Confirm (admin)
curl -s http://localhost:9229/ \
  -H "Content-Type: application/x-amz-json-1.1" \
  -H "X-Amz-Target: AWSCognitoIdentityProviderService.AdminConfirmSignUp" \
  -d "{\"UserPoolId\": \"$POOL_ID\", \"Username\": \"alice\"}"

# Authenticate
curl -s http://localhost:9229/ \
  -H "Content-Type: application/x-amz-json-1.1" \
  -H "X-Amz-Target: AWSCognitoIdentityProviderService.InitiateAuth" \
  -d "{\"ClientId\": \"$CLIENT_ID\", \"AuthFlow\": \"USER_PASSWORD_AUTH\", \"AuthParameters\": {\"USERNAME\": \"alice\", \"PASSWORD\": \"P@ssw0rd!\"}}"
```

### Connect from AWS SDKs

```javascript
// JavaScript
const { CognitoIdentityProviderClient } = require("@aws-sdk/client-cognito-identity-provider");
const client = new CognitoIdentityProviderClient({
  region: "local",
  endpoint: "http://localhost:9229",
  credentials: { accessKeyId: "local", secretAccessKey: "local" },
});
```

```python
# Python
import boto3
client = boto3.client("cognito-idp", region_name="local",
    endpoint_url="http://localhost:9229",
    aws_access_key_id="local", aws_secret_access_key="local")
```

```rust
// Rust
let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
    .region(Region::new("local"))
    .credentials_provider(Credentials::new("local", "local", None, None, "demo"))
    .endpoint_url("http://localhost:9229")
    .load().await;
let client = aws_sdk_cognitoidentityprovider::Client::new(&config);
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `COGNITOX_PORT` | `9229` | Server port |
| `RUST_LOG` | `info` | Log level |
| `COGNITOX_DATA_FILE` | *(unset)* | Path to persist state across restarts |

## Built-in UIs

- **Hosted UI**: `http://localhost:9229/login?response_type=code&client_id=<id>&redirect_uri=<uri>&scope=openid`
- **Admin Console**: `http://localhost:9229/admin/`

## Important notes

- All 119 cognito-idp operations are implemented
- `USER_SRP_AUTH` is not supported; use `USER_PASSWORD_AUTH` instead
- Confirmation codes are returned in API responses but not sent via email/SMS
- Data is in-memory by default; set `COGNITOX_DATA_FILE` for persistence
- CORS is fully open — this is a local development tool only

## Checking server status

```bash
curl -s http://localhost:9229/health
# Returns: {"status":"ok"}
```

For the full API coverage, see [references/COVERAGE.md](references/COVERAGE.md).
