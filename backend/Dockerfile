# ============================================================================
# Multi-stage build for IDaaS Rust backend (api_server)
#
# Stages:
#   1. chef     — install cargo-chef for dependency caching
#   2. planner  — analyze workspace and generate dependency recipe
#   3. builder  — build deps (cached layer) then compile the binary
#   4. runtime  — minimal image with just the binary + CA certs
#
# Dependency caching cuts rebuild times from ~15min to ~30s for code-only
# changes. Only Cargo.toml/Cargo.lock changes invalidate the dep layer.
#
# Build context: repo root (docker build -f backend/Dockerfile .)
# ============================================================================

# ── Stage 1: Chef ───────────────────────────────────────────────────────────
FROM rust:1.88-slim AS chef

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-chef --locked
WORKDIR /app

# ── Stage 2: Planner ───────────────────────────────────────────────────────
FROM chef AS planner

COPY backend/Cargo.toml backend/Cargo.lock ./
COPY backend/crates ./crates
COPY backend/protos ./protos

RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 3: Builder ───────────────────────────────────────────────────────
FROM chef AS builder

# Build dependencies first — this layer is cached until Cargo.toml/lock change
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Copy source and build only the api_server binary
COPY backend/Cargo.toml backend/Cargo.lock ./
COPY backend/crates ./crates
COPY backend/protos ./protos

RUN cargo build --release --bin api_server

# ── Stage 4: Runtime ───────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN groupadd -g 10001 appuser && \
    useradd -u 10001 -g appuser -s /bin/false -M appuser && \
    mkdir -p /app /data && \
    chown -R appuser:appuser /app /data

WORKDIR /app

COPY --from=builder /app/target/release/api_server /usr/local/bin/api_server

USER appuser

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

CMD ["api_server"]
