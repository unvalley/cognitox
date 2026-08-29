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
| `COGNITOX_ISSUER_BASE_URL` | `http://localhost:<COGNITOX_PORT>` | Base URL used as the JWT `iss` claim and in OpenID discovery. |

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

## API Coverage

cognitox routes all 119 cognito-idp operations, with **101 (85%) currently spec-aligned**. The remaining 18 have known partial functionality or limitations (see below).
See [COVERAGE.md](COVERAGE.md) for the full list with links to each handler. If you find any missing or incorrectly implemented operations, please open an issue.

## Spec Drift Check

See [spec/README.md](spec/README.md).

## Known Limitations

- **Auth flows** -- `USER_PASSWORD_AUTH`, `REFRESH_TOKEN_AUTH`, `ADMIN_USER_PASSWORD_AUTH`, and `ADMIN_NO_SRP_AUTH` are supported. `USER_SRP_AUTH` and `USER_AUTH` return `NotImplementedException`.
- **Lambda triggers** -- not supported (no pre/post auth hooks)
- **Email/SMS delivery** -- nothing is sent. SignUp / ForgotPassword / ResendConfirmationCode return `CodeDeliveryDetails` only; the actual confirmation code is persisted in the data file and emitted only at debug log level for local troubleshooting.
- **Password policy per pool** -- the per-pool `PasswordPolicy` is stored and returned but not enforced. A fixed global rule (length 6–256) is applied to all passwords.
- **MFA enforcement** -- MFA operations are implemented but not enforced during auth
- **Advanced security features** -- risk configuration is stored but not evaluated

## License

MIT
