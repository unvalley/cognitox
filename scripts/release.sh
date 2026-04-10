#!/usr/bin/env bash
#
# Bumps the cognitox [package] version in Cargo.toml to match the given tag,
# refreshes Cargo.lock, commits (if anything changed), and creates an
# annotated git tag.
#
# Idempotent: if Cargo.toml is already at the requested version (e.g. the
# initial release, or a re-run), the script skips the bump commit and just
# creates the tag. If the tag already exists, the script fails loudly.
#
# Usage: scripts/release.sh <tag>
#   e.g. scripts/release.sh v0.1.1
#
# Called from `.github/workflows/prepare-release.yml`. Can also be run locally
# before pushing a tag by hand.

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <tag>" >&2
    exit 1
fi

tag="$1"
version="${tag#v}"

if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]]; then
    echo "error: '${version}' does not look like a semver version (expected X.Y.Z[-prerelease])" >&2
    exit 1
fi

cd "$(dirname "$0")/.."

if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
    echo "error: tag ${tag} already exists" >&2
    exit 1
fi

# Rewrite the first `version = "..."` line inside [package].
awk -v v="${version}" '
    BEGIN { in_pkg = 0; bumped = 0 }
    /^\[package\]/ { in_pkg = 1; print; next }
    /^\[/ && !/^\[package\]/ { in_pkg = 0 }
    in_pkg && !bumped && $1 == "version" {
        sub(/"[^"]+"/, "\"" v "\"")
        bumped = 1
    }
    { print }
' Cargo.toml > Cargo.toml.new

if ! grep -q "^version = \"${version}\"$" Cargo.toml.new; then
    echo "error: failed to rewrite version in Cargo.toml" >&2
    rm -f Cargo.toml.new
    exit 1
fi
mv Cargo.toml.new Cargo.toml

# Keep Cargo.lock's workspace-member entry in sync so `cargo publish --locked`
# works downstream.
cargo update --workspace

if git diff --quiet -- Cargo.toml Cargo.lock; then
    echo "Cargo.toml is already at ${version}; skipping bump commit."
else
    git add Cargo.toml Cargo.lock
    git commit -m "chore: release ${tag}"
fi

git tag -a "${tag}" -m "${tag}"

echo "Prepared ${tag}. Next: git push origin HEAD --follow-tags"
