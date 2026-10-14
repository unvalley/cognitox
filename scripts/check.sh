#!/usr/bin/env bash
#
# Runs the same gates as `.github/workflows/ci.yml` (rustfmt, spec drift,
# clippy, tests), plus the UI type check from `.github/workflows/ui.yml` when
# asked. Stops at the first failing step.
#
# Usage: scripts/check.sh [--ui] [--fix]
#   --ui   also run `pnpm run check` in ui/ (needs `pnpm --dir ui install`)
#   --fix  run `cargo fmt` instead of `cargo fmt --check`

set -euo pipefail

with_ui=false
fix=false
for arg in "$@"; do
    case "${arg}" in
        --ui) with_ui=true ;;
        --fix) fix=true ;;
        -h | --help)
            sed -n '3,9p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "error: unknown argument '${arg}' (try --help)" >&2
            exit 2
            ;;
    esac
done

cd "$(dirname "$0")/.."

step() {
    echo
    echo "==> $*"
    "$@"
}

if "${fix}"; then
    step cargo fmt
else
    step cargo fmt --check
fi
step cargo run --quiet --bin request_response_spec_diff
step cargo clippy --all-targets -- -D warnings
step cargo test
if "${with_ui}"; then
    step pnpm --dir ui run check
fi

echo
echo "All checks passed."
