# Spec Drift Check

Spec drift checks compare Amazon Cognito request/response fields with each
action's `Request` / `Response` structure (and JSON response shape fallback).

```bash
# Compare against baseline (used in CI)
cargo run --quiet --bin request_response_spec_diff

# Refresh baseline after reviewing changes
cargo run --quiet --bin request_response_spec_diff -- --update-baseline
```

## Files

| File | Description |
|------|-------------|
| `request_field_baseline.json` | Committed baseline of known field drift |
| `request_field_expected.json` | Expected fields from the AWS API spec |
