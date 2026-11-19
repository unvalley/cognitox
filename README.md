# cognitox

<div align="center">
<img width="100px" height="100px" src="./public/icon-512-rounded.png" />
</div>
<br />

Amazon Cognito User Pools emulator for local development.

> **Warning**: cognitox is designed for **local development and testing only**.
> It is not suitable for production use. CORS is fully open (`Allow-Origin: *`) and
> there is no authentication on the admin endpoints.

## Quick Start

### With Docker (GHCR)

```bash
# Pull pre-built image from GitHub Container Registry
docker pull ghcr.io/unvalley/cognitox:latest
docker run --rm -p 9229:9229 -v cognitox-data:/data ghcr.io/unvalley/cognitox:latest
```

### With Docker (local build)

```bash
docker build -t cognitox .
docker run --rm -p 9229:9229 -v cognitox-data:/data cognitox
```

### With Cargo

```bash
cargo binstall cognitox
cognitox
```

If a pre-built binary is not available for your platform, install from source:

```bash
cargo install cognitox
cognitox
```

The admin console and Preact UI are embedded into the binary, so `cargo install` gives you a fully self-contained emulator — no extra assets to ship.

## Usage

Point the SDK endpoint to cognitox:

```javascript
// JavaScript / TypeScript
import { CognitoIdentityProviderClient } from "@aws-sdk/client-cognito-identity-provider";

const client = new CognitoIdentityProviderClient({
  region: "local",
  endpoint: "http://localhost:9229",
  credentials: { accessKeyId: "local", secretAccessKey: "local" },
});
```

```python
# Python (boto3)
import boto3

client = boto3.client(
    "cognito-idp",
    region_name="local",
    endpoint_url="http://localhost:9229",
    aws_access_key_id="local",
    aws_secret_access_key="local",
)
```

### Hosted UI

cognitox includes a built-in Hosted UI for login and signup flows.

```
// example
http://localhost:9229/login?response_type=code&client_id=<client-id>&redirect_uri=http://localhost:3000/callback&scope=openid
```

The `/oauth2/token` endpoint supports authorization code, refresh token, and
client credentials grants. Confidential clients can authenticate with an
`Authorization: Basic ...` header (`client_secret_basic`) or form fields
(`client_secret_post`), as described in the [Cognito token endpoint documentation](https://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html).
Public clients must send `client_id` in the form body and can use the
authorization code and refresh token grants.

The `/oauth2/userInfo` endpoint requires an access token with the `openid`
scope and rejects revoked tokens with HTTP 401. Disabling a user revokes their
access and refresh tokens, which remain invalid after the account is re-enabled.
User Pools API authentication and refresh requests grant the
`aws.cognito.signin.user.admin` scope; use the OAuth endpoints for `openid` access.

### Admin Console

A management UI for browsing user pools, users, clients, and groups:

```
http://localhost:9229/admin/
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `COGNITOX_PORT` | `9229` | Server port |
| `RUST_LOG` | `cognitox=info,tower_http=info` | Log filter (e.g. `debug` or `cognitox=debug,tower_http=info`) |
| `COGNITOX_STORAGE_MODE` | `persistent` | Storage mode: `persistent` (file-backed) or `memory` (no persistence). |
| `COGNITOX_DATA_FILE` | `cognitox-data.json` | Path to persist emulator state (JSON snapshot) when storage mode is `persistent`. |
| `COGNITOX_ISSUER_BASE_URL` | `http://localhost:<COGNITOX_PORT>` | Base URL for the JWT `iss` claim, which is `<base>/<user pool id>` as in Cognito, and for OpenID discovery. |
| `COGNITOX_SEED_FILE` | *(unset)* | JSON file of user pools and clients to create at startup with fixed IDs. See [Seeding](#seeding). |

### Persistence

By default, state is persisted to `cognitox-data.json` in the working directory and survives restarts. The emulator auto-saves every 500ms when changes are detected, and flushes on graceful shutdown (Ctrl+C or SIGTERM). For Docker, mount `/data` as shown above so the snapshot survives container replacement.

To use a different file:

```bash
COGNITOX_DATA_FILE=./my-data.json cargo run
```

To opt out of persistence and run purely in-memory:

```bash
COGNITOX_STORAGE_MODE=memory cargo run
```

### Seeding

Cognito assigns user pool and client IDs itself, so they cannot be written into application config ahead of time. A seed file creates them with fixed IDs at startup. Each user pool is a `CreateUserPool` request plus `Id` and `Clients`; each client is a `CreateUserPoolClient` request without `UserPoolId`, plus `ClientId` and an optional `ClientSecret`. Entries that already exist, such as ones restored from the snapshot, are left as they are.

```json
{
  "UserPools": [
    {
      "Id": "us-east-1_LocalPool",
      "PoolName": "local",
      "Clients": [
        {
          "ClientId": "localwebclient",
          "ClientSecret": "local-web-secret",
          "ClientName": "web",
          "AllowedOAuthFlows": ["code"],
          "AllowedOAuthFlowsUserPoolClient": true,
          "AllowedOAuthScopes": ["openid", "email"],
          "CallbackURLs": ["http://localhost:3000/callback"]
        }
      ]
    }
  ]
}
```

```bash
COGNITOX_SEED_FILE=./seed.json cargo run
```

## Behavior that follows Cognito

cognitox aims to fail locally where Cognito would fail in AWS:

- **App client auth flows** -- a client created without `ExplicitAuthFlows` gets Cognito's default (`ALLOW_CUSTOM_AUTH`, `ALLOW_USER_SRP_AUTH`, `ALLOW_REFRESH_TOKEN_AUTH`). `USER_PASSWORD_AUTH` and the admin password flow answer `InvalidParameterException` until the client lists `ALLOW_USER_PASSWORD_AUTH` / `ALLOW_ADMIN_USER_PASSWORD_AUTH`.
- **Password policy** -- the user pool's `PasswordPolicy` is enforced wherever a password is set, with `InvalidPasswordException` and Cognito's messages. A pool without one uses Cognito's default: 8 characters with upper case, lower case, a number, and a symbol.
- **MFA** -- a user's MFA preference, or a pool with `MfaConfiguration: ON`, adds the `SOFTWARE_TOKEN_MFA`, `SMS_MFA`, `EMAIL_OTP`, `SELECT_MFA_TYPE`, or `MFA_SETUP` challenge to sign-in.
- **Errors** -- client errors are HTTP 400 with Cognito's `__type` and message (`NotAuthorizedException: Incorrect username or password.`), plus the `x-amzn-errortype` and `x-amzn-requestid` headers.
- **Tokens** -- ID tokens carry the user's attributes, `cognito:groups`, and `cognito:roles`; access and ID tokens share `origin_jti` and `event_id`, and `RevokeToken` voids the tokens of one sign-in.
- **Resource defaults and updates** -- a user pool or app client created with only a name reads back with Cognito's defaults (`DescribeUserPool` returns the default policies, `SchemaAttributes`, `Arn`, and so on). `UpdateUserPool` and `UpdateUserPoolClient` replace the configuration: a setting the request leaves out returns to its default, so send the full configuration as you would to Cognito. `ListUserPools` requires `MaxResults`.

## API Coverage

cognitox routes all 119 cognito-idp operations, with **101 (85%) currently spec-aligned**. The remaining 18 have known partial functionality or limitations (see below).
See [COVERAGE.md](COVERAGE.md) for the full list with links to each handler. If you find any missing or incorrectly implemented operations, please open an issue.

## Spec Drift Check

See [spec/README.md](spec/README.md).

## Known Limitations

- **Auth flows** -- `USER_SRP_AUTH`, `USER_PASSWORD_AUTH`, `ADMIN_USER_PASSWORD_AUTH` (`ADMIN_NO_SRP_AUTH`), `REFRESH_TOKEN_AUTH`, and the choice-based `USER_AUTH` flow (password, SRP, email and SMS one-time codes) are supported. `CUSTOM_AUTH` needs Lambda triggers and returns `NotImplementedException`, as do passkey (`WEB_AUTHN`) sign-in and device SRP.
- **Lambda triggers** -- not supported (no pre/post auth hooks)
- **Email/SMS delivery** -- nothing is sent. Confirmation, password reset, and MFA codes are six digits, as Cognito's are; they are persisted in the data file and emitted only at debug log level (`RUST_LOG=cognitox=debug`).
- **Account lockout** -- failed sign-in attempts are not rate limited; only a challenge session ends after repeated wrong answers.
- **Advanced security features** -- risk configuration is stored but not evaluated

## Development

```bash
scripts/check.sh   # rustfmt, spec drift, clippy, and tests: the same gates as CI
```

See [AGENTS.md](AGENTS.md) for the architecture, conventions, and the workflow
for changing an operation.

## License

MIT
