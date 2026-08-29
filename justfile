# Cognitox - AWS Cognito Emulator
# Run `just --list` to see all available commands

set dotenv-load

# Default recipe - show available commands
default:
    @just --list

# =============================================================================
# Development
# =============================================================================

# Run the server in development mode
dev:
    cargo run

# Run the server with auto-reload (requires cargo-watch)
watch:
    cargo watch -x run

# Run the UI dev server (hot reload)
ui-dev:
    cd ui && pnpm run dev

# Run both servers in parallel (requires tmux or run in separate terminals)
dev-all:
    @echo "Run these commands in separate terminals:"
    @echo "  Terminal 1: just dev"
    @echo "  Terminal 2: just ui-dev"

# =============================================================================
# Build
# =============================================================================

# Build the Rust server (debug)
build:
    cargo build

# Build the Rust server (release)
build-release:
    cargo build --release

# Build the UI
ui-build:
    cd ui && pnpm run build

# Build everything (Rust + UI)
build-all: ui-build build

# Build everything for release
build-all-release: ui-build build-release

# =============================================================================
# Test
# =============================================================================

# Run all Rust tests
test:
    cargo test

# Run tests with output
test-verbose:
    cargo test -- --nocapture

# Run a specific test
test-one NAME:
    cargo test {{NAME}}

# Run TypeScript type checking for UI
ui-check:
    cd ui && pnpm run check

# Run all checks (spec drift + Rust tests + UI type check)
check-all: spec-check test ui-check

# Check request/response drift against AWS API baseline
spec-check:
    cargo run --quiet --bin request_response_spec_diff

# Update request/response baseline after reviewing diffs
spec-baseline-update:
    cargo run --quiet --bin request_response_spec_diff -- --update-baseline

# =============================================================================
# Lint & Format
# =============================================================================

# Run clippy linter
lint:
    cargo clippy -- -D warnings

# Format Rust code
fmt:
    cargo fmt

# Check formatting without modifying
fmt-check:
    cargo fmt -- --check

# =============================================================================
# UI
# =============================================================================

# Install UI dependencies
ui-install:
    cd ui && pnpm install --frozen-lockfile

# Clean UI build artifacts
ui-clean:
    rm -rf ui/dist ui/node_modules

# Preview production UI build
ui-preview:
    cd ui && pnpm run preview

# =============================================================================
# Clean
# =============================================================================

# Clean Rust build artifacts
clean:
    cargo clean

# Clean everything (Rust + UI)
clean-all: clean ui-clean

# =============================================================================
# Release (crates.io)
# =============================================================================
#
# The preferred path is GitHub Actions (`.github/workflows/release.yml`,
# workflow_dispatch "Release"). These recipes are for local verification and
# emergency manual publishes.

# Rebuild the UI so real assets — not build.rs placeholders — get embedded.
publish-prepare: ui-build
    @echo "UI assets rebuilt at ui/dist/"

# Full pre-flight: UI build, fmt check, clippy, tests, and a publish dry-run.
publish-check: publish-prepare fmt-check lint test
    cargo publish --dry-run --locked --allow-dirty

# Publish to crates.io manually. Prefer the GitHub Actions release workflow.
# --allow-dirty is required because ui/dist/ is gitignored.
publish: publish-check
    cargo publish --locked --allow-dirty

# =============================================================================
# Docker
# =============================================================================

# Build Docker image
docker-build:
    docker build -t cognitox .

# Run Docker container
docker-run:
    docker run -p 9229:9229 cognitox

# =============================================================================
# Setup
# =============================================================================

# Initial project setup
setup: ui-install
    @echo "Setup complete!"
    @echo ""
    @echo "To start development:"
    @echo "  just dev        # Start Rust server"
    @echo "  just ui-dev     # Start Preact dev server (in another terminal)"
    @echo ""
    @echo "To build for production:"
    @echo "  just build-all-release"

# =============================================================================
# Demo
# =============================================================================

# Create a demo user pool and client (requires running server)
demo-setup:
    #!/usr/bin/env bash
    set -e

    echo "Creating demo user pool..."
    POOL_RESPONSE=$(curl -s -X POST http://localhost:9229/ \
        -H "Content-Type: application/x-amz-json-1.1" \
        -H "X-Amz-Target: AWSCognitoIdentityProviderService.CreateUserPool" \
        -d '{"PoolName": "demo-pool"}')

    POOL_ID=$(echo $POOL_RESPONSE | grep -o '"Id":"[^"]*"' | cut -d'"' -f4)
    echo "Created user pool: $POOL_ID"

    echo "Creating user pool client..."
    CLIENT_RESPONSE=$(curl -s -X POST http://localhost:9229/ \
        -H "Content-Type: application/x-amz-json-1.1" \
        -H "X-Amz-Target: AWSCognitoIdentityProviderService.CreateUserPoolClient" \
        -d "{\"UserPoolId\": \"$POOL_ID\", \"ClientName\": \"demo-client\", \"CallbackURLs\": [\"http://localhost:3000/callback\"], \"AllowedOAuthFlows\": [\"code\"], \"AllowedOAuthScopes\": [\"openid\", \"email\", \"profile\"]}")

    CLIENT_ID=$(echo $CLIENT_RESPONSE | grep -o '"ClientId":"[^"]*"' | cut -d'"' -f4)
    echo "Created client: $CLIENT_ID"

    echo ""
    echo "Demo setup complete!"
    echo ""
    echo "Hosted UI (Rust):   http://localhost:9229/login?response_type=code&client_id=$CLIENT_ID&redirect_uri=http://localhost:3000/callback&scope=openid"
    echo "Hosted UI (Preact): http://localhost:9229/ui/?response_type=code&client_id=$CLIENT_ID&redirect_uri=http://localhost:3000/callback&scope=openid"
    echo "Admin Console:      http://localhost:9229/admin/"
