# UI build stage
FROM node:24-alpine AS ui-builder

RUN corepack enable && corepack prepare pnpm@9.15.9 --activate

WORKDIR /app/ui

COPY ui/package.json ui/pnpm-lock.yaml ui/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

COPY ui/ ./
RUN pnpm run build

# Dependency planner
FROM rust:1.94.1-alpine AS chef
RUN apk add --no-cache musl-dev perl make && \
    cargo install cargo-chef --locked
WORKDIR /app

FROM chef AS planner
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
RUN cargo chef prepare --recipe-path recipe.json

# Dependency builder (cached unless Cargo.toml/Cargo.lock change)
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
COPY --from=ui-builder /app/ui/dist ./ui/dist
RUN cargo build --release --bin cognitox

# Runtime
FROM alpine:3.21

WORKDIR /app

COPY --from=builder /app/target/release/cognitox /app/cognitox

# Writable data directory for the persistent storage snapshot. WORKDIR /app is
# root-owned, so without this the non-root process cannot write its snapshot and
# logs a persist error every autosave cycle.
RUN mkdir -p /data && chown nobody:nobody /data
VOLUME ["/data"]

ENV COGNITOX_PORT=9229 \
    COGNITOX_DATA_FILE=/data/cognitox-data.json
EXPOSE 9229

USER nobody

CMD ["/app/cognitox"]
