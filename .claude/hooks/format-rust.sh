#!/bin/bash
#
# PostToolUse hook: rustfmt the Rust file Claude just edited so `cargo fmt
# --check` in CI never fails on agent edits. Never blocks the edit.

input="$(cat)"
command -v jq >/dev/null 2>&1 || exit 0
file="$(printf '%s' "${input}" | jq -r '.tool_input.file_path // empty')"

case "${file}" in
    *.rs) ;;
    *) exit 0 ;;
esac
[ -f "${file}" ] || exit 0

rustfmt --edition 2024 "${file}" >/dev/null 2>&1 || true
exit 0
