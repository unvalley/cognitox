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
docker run -p 9229:9229 ghcr.io/unvalley/cognitox:latest
```

### With Docker (local build)

```bash
docker build -t cognitox .
docker run -p 9229:9229 cognitox
```

### With Cargo

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
| `COGNITOX_PORT` | `9229` | Server port (`PORT` is also accepted for backward compatibility) |
| `RUST_LOG` | `info` | Log level (`debug` for verbose output) |
| `COGNITOX_DATA_FILE` | *(unset)* | Path to persist emulator state (JSON snapshot). If set, state survives restarts. `DATA_FILE` is also accepted for backward compatibility. |

### Persistence

By default, all data is in-memory and lost on restart. To persist state:

```bash
COGNITOX_DATA_FILE=./cognitox-data.json cargo run
```

The emulator auto-saves every 500ms when changes are detected, and flushes on graceful shutdown (Ctrl+C).

## API Coverage

cognitox has all 119 API operations but some have partial functionality or known limitations (see below).
See [COVERAGE.md](COVERAGE.md) for the full list with links to each handler. If you find any missing or incorrectly implemented operations, please open an issue.

## Spec Drift Check

See [spec/README.md](spec/README.md).

## Known Limitations

- **SRP authentication** (`USER_SRP_AUTH`) -- partially implemented
- **Lambda triggers** -- not supported (no pre/post auth hooks)
- **Email/SMS delivery** -- confirmation codes are returned in API responses but not sent
- **Password policy per pool** -- only global min/max length is enforced
- **MFA enforcement** -- MFA operations are implemented but not enforced during auth
- **Advanced security features** -- risk configuration is stored but not evaluated

## License

MIT
