# cognitox

<div align="center">
  <img width="80%" src="./public/icon-512-rounded.png" />
</div>

AWS Cognito User Pools emulator for local development.


## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `9229` | Server port |
| `RUST_LOG` | `info` | Log level |
| `DATA_FILE` | *(unset)* | Optional path to persist emulator state as a JSON snapshot file |

## API Coverage

See [COVERAGE.md](COVERAGE.md) for full list.

## Spec Drift Check

Spec drift checks compare AWS Cognito request/response fields with each
action's `Request` / `Response` structure (and JSON response shape fallback).

```bash
# Compare against baseline (used in CI)
cargo run --quiet --bin request_response_spec_diff

# Refresh baseline after reviewing changes
cargo run --quiet --bin request_response_spec_diff -- --update-baseline
```

## License

MIT
