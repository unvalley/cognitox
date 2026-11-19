# Demos

Example applications that run against cognitox.

| Directory | Description |
|-----------|-------------|
| [aws-sdk-js/](aws-sdk-js/) | Full user lifecycle using `@aws-sdk/client-cognito-identity-provider` |
| [aws-sdk-python/](aws-sdk-python/) | Full user lifecycle using `boto3` |
| [aws-sdk-rust/](aws-sdk-rust/) | Full user lifecycle using `aws-sdk-cognitoidentityprovider` |
| [cognito-identity-js/](cognito-identity-js/) | SRP sign-in, new-password challenge, TOTP MFA, and sign-out with `amazon-cognito-identity-js` |
| [oauth-app/](oauth-app/) | OAuth 2.0 Authorization Code flow web app |

## Prerequisites

Start cognitox first:

```bash
cargo run   # or: docker run -p 9229:9229 cognitox
```

## AWS SDK for JavaScript

```bash
cd aws-sdk-js
pnpm install
pnpm run demo
```

## amazon-cognito-identity-js

The browser library behind Amplify's classic auth signs in with
`USER_SRP_AUTH`, so this demo doubles as a check of the emulator against a
real SRP client. It exits non-zero if a step fails.

```bash
cd cognito-identity-js
pnpm install
pnpm run demo
```

cognitox sends no email. To also run the steps that need an emailed code
(confirming sign-up, resetting a password), start the server with debug
logging to a file and point the demo at it:

```bash
RUST_LOG=cognitox=debug NO_COLOR=1 cargo run > cognitox.log 2>&1 &
COGNITOX_LOG=../../cognitox.log pnpm run demo
```

## AWS SDK for Python

```bash
cd aws-sdk-python
pip install -r requirements.txt
python demo.py
```

## AWS SDK for Rust

```bash
cd aws-sdk-rust
cargo run
```

## OAuth App

```bash
cd oauth-app
pnpm install
# Create a pool and client first (see justfile demo-setup), then:
CLIENT_ID=<your-client-id> pnpm dev
# Open http://localhost:3000
```
