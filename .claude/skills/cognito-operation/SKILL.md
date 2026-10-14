---
name: cognito-operation
description: Implement, fix, or spec-align a cognito-idp API operation in cognitox (handler, registry, tests, COVERAGE.md, spec drift baseline). Use when changing a handler under src/action/, flipping a COVERAGE.md row from [ ] to [x], or adding an operation AWS has introduced.
---

# Working on a cognito-idp operation

Work from the repository root: the spec drift tool resolves the handler paths
in `COVERAGE.md` relative to the current directory.

## 1. Locate

- Handler: the `[cognitox](src/action/...)` link on the operation's row in
  `COVERAGE.md`. Categories are `user/`, `user_pool/`, and `group/`.
- Registry: the `define_action_registry!` invocation in
  `src/api/cognito_idp.rs` maps `Variant => category::module::handler`.
  The variant name is matched verbatim against the `X-Amz-Target` suffix, so
  it must equal the AWS operation name exactly (`GetCSVHeader`, not
  `GetCsvHeader`).
- Reference: `https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_<Operation>.html`
  (`Action::doc_url()`), and the request/response field lists for the
  operation in `spec/request_field_expected.json`.
- Shared auth logic lives in `src/action/user/auth_flow.rs`; read
  `docs/auth-flow-design.md` before touching `InitiateAuth`,
  `RespondToAuthChallenge`, or their `Admin*` variants.

## 2. Request and response shape

```rust
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: String,
    limit: Option<i32>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?; // crate::action::io
    // ...
    Ok(json!({
        "UserPool": pool_json,
    }))
}
```

The drift tool (`src/bin/request_response_spec_diff.rs`) reads handler files
as text, not through the compiler:

- Request fields come from the struct literally named `Request`; every `[x]`
  handler must define one.
- Response fields come from `struct Response`, else from the first
  `Ok(json!({ ... }))` in the file, else from `let mut response = json!({ ... })`
  plus later `response["Key"] = ...` lines.
- One field per line: struct fields end in `,`; top-level JSON keys start
  their line as `"Key": ...`, so a one-line `json!({ "Key": v })` reports no
  fields. Names are compared case- and underscore-insensitively, so
  `mfa_options` matches `MFAOptions`.

Keep that shape, or the drift check will misreport fields.

## 3. Errors, storage, types

- Return `AppError` (`src/error.rs`). Its `IntoResponse` impl maps each variant
  to a Cognito `__type` and HTTP status. Add a variant only when no existing
  one maps to the exception the AWS reference documents.
- Read and write state only through `Storage` methods (`src/storage.rs`).
- Persisted types live in `src/types.rs`. Snapshots of earlier versions must
  still load, so new non-`Option` fields need `#[serde(default)]`.

## 4. Tests

- Unit tests go in the handler's `#[cfg(test)] mod tests`, calling
  `handler(&Storage::new(), json!({ ... }))` directly. `Storage::new()` is
  in-memory.
- HTTP-level tests go in `tests/*.rs`, using `TestClient` from
  `tests/common/mod.rs`.
- Cover the success path and each documented exception you implement.

## 5. Coverage documentation

When an operation becomes spec-aligned (`[ ]` to `[x]`) or a new one is
added:

1. Update the row in `COVERAGE.md`. A new operation also needs `pub mod` in
   `src/action/<category>.rs` (alphabetical) and a registry line.
2. Update the numbers in the `COVERAGE.md` header, in the API Coverage
   paragraph of `README.md`, and, if the total changed, in the doc comment in
   `src/main.rs`. `tests/coverage_doc_test.rs` fails until all three agree with
   the checklist.
3. Remove the operation from README "Known Limitations" if it is listed there.

## 6. Spec drift baseline

```bash
cargo run --quiet --bin request_response_spec_diff
```

Only `[x]` rows are checked. A newly flipped row, a renamed handler file, or
changed fields makes the check fail against `spec/request_field_baseline.json`.
Fix the fields first. If what remains is intentional, refresh the baseline
and review the diff:

```bash
cargo run --quiet --bin request_response_spec_diff -- --update-baseline
git diff spec/request_field_baseline.json
```

Do not refresh the baseline to hide drift you did not intend.

## 7. Verify and commit

```bash
scripts/check.sh
```

Commit with a Conventional Commit scoped to the category, for example
`feat(user): support ClientMetadata in SignUp` or
`fix(user_pool): return LimitExceededException from CreateUserPoolDomain`.
