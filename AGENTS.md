# AGENTS.md

Guidance for coding agents working in this repository. `CLAUDE.md` is a
symlink to this file.

## Project Overview

cognitox is an Amazon Cognito User Pools emulator for local development. It
implements the Cognito Identity Provider JSON API (`cognito-idp`), the OAuth
2.0 / OpenID Connect endpoints, and a Hosted UI, so applications can be tested
without AWS. The server is Rust (edition 2024, toolchain pinned in
`rust-toolchain.toml`); the admin console and Preact Hosted UI live in `ui/`.

## Commands

```bash
# Every gate CI enforces: spec drift, rustfmt, clippy, tests
scripts/check.sh
scripts/check.sh --fix   # run cargo fmt instead of failing on formatting
scripts/check.sh --ui    # also type-check the UI

# Build / run (port 9229). Memory mode leaves no cognitox-data.json behind.
cargo build
COGNITOX_STORAGE_MODE=memory cargo run

# Tests
cargo test                        # all
cargo test --test oauth2_test     # one integration file in tests/
cargo test test_create_user_pool  # tests whose name contains the string

# Lint / format
cargo clippy --all-targets -- -D warnings
cargo fmt

# Spec drift check against the AWS API model (see spec/README.md)
cargo run --quiet --bin request_response_spec_diff

# UI (Node + pnpm; not needed to build or test the Rust server)
pnpm --dir ui install --frozen-lockfile
pnpm --dir ui run check   # tsc --noEmit
pnpm --dir ui run build   # writes ui/dist/, embedded at the next cargo build
```

The `justfile` wraps the same commands (`just --list`); `just` is optional.

## Architecture

### Request Flow

```
POST /   X-Amz-Target: AWSCognitoIdentityProviderService.<Operation>
  → api/cognito_idp.rs   handle_request → Action::from_str → dispatch_action
    → action/{user,user_pool,group}/<operation>.rs   handler(storage, body)
      → storage.rs   in-memory state, optionally persisted to a snapshot
```

`src/api.rs` (`create_router`) also serves `/oauth2/*`, `/.well-known/*`,
and `/logout` (`api/oauth2.rs`); `/login`, `/signup`, `/confirm`,
`/forgot-password`, and `/reset-password` (`api/hosted_ui.rs`); the embedded
SPAs at `/ui/*`, `/admin/*`, and `/assets/*`; and `/health`.

### Key Modules

- **api/cognito_idp.rs**: the `define_action_registry!` invocation is the only
  list of operations. It generates the `Action` enum, `Action::ALL`,
  `FromStr` (matched against the `X-Amz-Target` suffix), and dispatch.
- **api/extractor.rs**: `AmzJson<T>` accepts both `application/json` and
  `application/x-amz-json-1.1`.
- **action/**: one file per operation, each exposing
  `pub async fn handler(storage: &Storage, body: Value) -> Result<Value>`.
  `action/io.rs` has `parse_request` / `to_response_value`;
  `action/user/helpers.rs` and `action/user/auth_flow.rs` hold shared user and
  auth logic (design notes: `docs/auth-flow-design.md`).
- **storage.rs**: `Storage`, cheap to clone, backed by `Arc<RwLock<_>>`
  stores. Persistent mode autosaves every 500 ms when dirty and on shutdown.
- **types.rs**: domain types (`UserPool`, `User`, `UserStatus`, ...), all
  persisted in snapshots.
- **error.rs**: `AppError`, mapped to Cognito `{"__type", "message"}` errors;
  `OAuthError` for the OAuth endpoints.
- **jwt.rs**: RS256 token issuance and JWKS.
- **bin/request_response_spec_diff.rs**: the spec drift tool.
- **build.rs**: copies `ui/dist/` into `$OUT_DIR/ui/` for `rust-embed`, or
  writes a placeholder page when the UI has not been built.

### Changing or Adding an Operation

Follow `.claude/skills/cognito-operation/SKILL.md`. In short: a handler file
with a `struct Request`, `pub mod` in `src/action/<category>.rs`, a line in
`define_action_registry!`, tests, the `COVERAGE.md` row and counts, the spec
drift baseline, then `scripts/check.sh`.

### Testing

- Unit tests sit next to the code in `#[cfg(test)] mod tests` and call
  handlers directly with `Storage::new()`, which is in-memory.
- Integration tests in `tests/` drive the router with
  `tower::ServiceExt::oneshot`, without starting a server. `tests/common/mod.rs`
  provides the `TestClient` helper.
- `tests/coverage_doc_test.rs` checks `COVERAGE.md` against the registry and
  the coverage numbers quoted in `README.md` and `src/main.rs`.
- `tests/request_spec_drift_test.rs` runs the spec drift tool.
- `tests/docker_test.rs` is ignored by default and needs Docker:
  `cargo test --test docker_test -- --ignored`.

## Implementation Coverage

`COVERAGE.md` is the source of truth: `[x]` rows are spec-aligned, `[ ]` rows
are routed but partial. README "Known Limitations" lists behavioral gaps
(SRP and `USER_AUTH` flows, Lambda triggers, email/SMS delivery, per-pool
password policy, MFA enforcement).

## Gotchas

- `cargo run` defaults to persistent storage and reads and writes
  `cognitox-data.json` in the working directory, so state from an earlier run
  carries over. The snapshot is a JSON envelope around a base64 MessagePack
  payload; inspect state through the API or `/admin/`, not by editing it.
- Persisted types must keep loading older snapshots: give new non-`Option`
  fields in `types.rs` a `#[serde(default)]`.
- Nothing is emailed or texted. Confirmation codes are logged at debug level
  (`RUST_LOG=cognitox=debug`).
- The spec drift tool parses handler source as text. Keep `struct Request`
  and response fields one per line (details in the skill).
- `.env` is loaded at startup and by `just`; `.env.example` lists the
  variables.

## Git Workflow

**Commit message format:**
- Use Conventional Commits for all commits.
- Format: ``type(scope): summary`` (or ``type: summary`` when scope is not needed)
- Examples: ``feat(user): add ConfirmDevice handler``, ``fix(api): validate access token``, ``docs: update coverage notes``

**Before committing:** run `scripts/check.sh --fix`. It formats the code, then
runs the spec drift check, `cargo clippy --all-targets -- -D warnings`, and
`cargo test`, and stops at the first failure.

**Important:** Commit your changes but **DO NOT push**. The user will review and push manually.
