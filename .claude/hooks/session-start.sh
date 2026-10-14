#!/bin/bash
#
# SessionStart hook for Claude Code cloud sessions: installs the pinned Rust
# toolchain, prebuilds every cargo target, and installs UI dependencies so
# `scripts/check.sh [--ui]` runs without a cold start. Local sessions skip it.

set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
    exit 0
fi

# SessionStart stdout is added to the agent's context; keep install logs out.
exec 1>&2

cd "${CLAUDE_PROJECT_DIR:-$(dirname "$0")/../..}"

# The rustup proxy installs the toolchain and components pinned in
# rust-toolchain.toml on first use.
cargo --version

cargo fetch --locked
cargo build --locked --all-targets
cargo clippy --locked --all-targets --quiet

if command -v pnpm >/dev/null 2>&1; then
    pnpm --dir ui install --frozen-lockfile
fi
