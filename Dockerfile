# UI build stage
FROM node:24-alpine AS ui-builder

WORKDIR /app/ui

COPY ui/package.json ui/package-lock.json ./
RUN npm ci

COPY ui/ ./
RUN npm run build

# Dependency planner
FROM rust:1.93.1-alpine AS chef
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
RUN cargo build --release --bin cognito-emulator

# Runtime
FROM alpine:3.20

WORKDIR /app

COPY --from=ui-builder /app/ui/dist /app/ui/dist
COPY --from=builder /app/target/release/cognito-emulator /app/cognito-emulator

ENV PORT=9229
EXPOSE 9229

USER nobody

CMD ["/app/cognito-emulator"]
