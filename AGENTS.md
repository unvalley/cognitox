# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AWS Cognito User Pools emulator for local development. Implements the Cognito Identity Provider API (`cognito-idp`) to allow testing without connecting to AWS.

## Commands

```bash
# Build
cargo build

# Run server (default port 9229)
cargo run

# Run all tests
cargo test

# Run specific test file (see tests/ for available files)
cargo test --test hosted_ui_test

# Run single test
cargo test test_create_user_pool

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt
```

## Architecture

### Request Flow

```
HTTP POST / (x-amz-target header)
  → api/cognito_idp.rs (dispatch_operation)
    → action/{user,user_pool}/*.rs (handler functions)
      → storage.rs (in-memory state)
```

### Key Modules

- **api/cognito_idp.rs**: Routes requests based on `X-Amz-Target` header (e.g., `AWSCognitoIdentityProviderService.SignUp`)
- **api/extractor.rs**: `AmzJson<T>` extractor that accepts both `application/json` and `application/x-amz-json-1.1`
- **action/**: Each Cognito API operation is a separate file with a `handler` function
- **storage.rs**: Thread-safe in-memory storage using `Arc<RwLock<_>>`
- **types.rs**: Domain types (UserPool, User, UserStatus, etc.)
- **error.rs**: `AppError` enum that maps to Cognito error responses

### Adding a New API Operation

1. Create `src/action/{category}/{operation_name}.rs` with:
   ```rust
   pub async fn handler(storage: &Storage, body: Value) -> Result<Value>
   ```
2. Add `pub mod operation_name;` to `src/action/{category}.rs`
3. Add match arm in `api/cognito_idp.rs` `dispatch_operation`
4. Update `COVERAGE.md`

### Testing

Tests use `tower::ServiceExt::oneshot` to test handlers directly without starting a server. See `tests/common/mod.rs` for the `TestClient` helper.

## Implementation Coverage

See `COVERAGE.md` for the list of implemented/unimplemented Cognito operations. All 119 cognito-idp operations are routed; currently 101/119 (85%) are spec-aligned.

## Git Workflow

**Commit message format:**
- Use Conventional Commits for all commits.
- Format: ``type(scope): summary`` (or ``type: summary`` when scope is not needed)
- Examples: ``feat(user): add ConfirmDevice handler``, ``fix(api): validate access token``, ``docs: update coverage notes``

**Before committing:**
1. Run `cargo fmt` to format the code
2. Run `cargo clippy -- -D warnings` to check for lint errors
3. Run `cargo test` to ensure all tests pass

**Important:** Commit your changes but **DO NOT push**. The user will review and push manually.
