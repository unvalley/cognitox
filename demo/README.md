# Demos

Example applications that run against cognitox.

| Directory | Description |
|-----------|-------------|
| [aws-sdk-js/](aws-sdk-js/) | Full user lifecycle using `@aws-sdk/client-cognito-identity-provider` |
| [aws-sdk-python/](aws-sdk-python/) | Full user lifecycle using `boto3` |
| [aws-sdk-rust/](aws-sdk-rust/) | Full user lifecycle using `aws-sdk-cognitoidentityprovider` |
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
