# Build stage
FROM rust:1.85-alpine AS builder

RUN apk add --no-cache musl-dev perl make

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Create dummy main.rs to cache dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    echo "pub fn dummy() {}" > src/lib.rs

# Downgrade time crate to be compatible with Rust 1.85
RUN cargo update time@0.3.46 --precise 0.3.36 || true

# Build dependencies (this layer will be cached)
RUN cargo build --release && \
    rm -rf src

# Copy actual source code
COPY src ./src

# Build the actual binary
RUN touch src/main.rs src/lib.rs && \
    cargo build --release

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/target/release/cognito-emulator /app/cognito-emulator

# Default port
ENV PORT=9229

EXPOSE 9229

HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --quiet --spider http://127.0.0.1:${PORT}/health || exit 1

USER nobody

CMD ["/app/cognito-emulator"]
