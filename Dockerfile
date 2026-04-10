# UI build stage
FROM node:24-alpine AS ui-builder

RUN corepack enable && corepack prepare pnpm@latest --activate

WORKDIR /app/ui

COPY ui/package.json ui/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY ui/ ./
RUN pnpm run build

# Dependency planner
FROM rust:1.94.1-alpine AS chef
RUN apk add --no-cache musl-dev perl make && \
    cargo install cargo-chef --locked
WORKDIR /app

FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo chef prepare --recipe-path recipe.json

# Dependency builder (cached unless Cargo.toml/Cargo.lock change)
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY --from=ui-builder /app/ui/dist ./ui/dist
RUN cargo build --release --bin cognitox

# Runtime
FROM alpine:3.21

WORKDIR /app

COPY --from=builder /app/target/release/cognitox /app/cognitox

ENV PORT=9229
EXPOSE 9229

USER nobody

CMD ["/app/cognitox"]
