# OSS-Scanner build environment for YARA-X.
#
# Network access is available only during `docker build` and disabled during
# scanning, so all system packages, Rust components, crate dependencies, and
# baseline build artifacts are fetched and compiled here.

FROM rust:latest

ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_TERM_COLOR=never \
    RUSTFLAGS="-C force-frame-pointers=yes"

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    clang \
    git \
    libmagic-dev \
    libssl-dev \
    pkg-config \
    protobuf-compiler \
    python3 \
    python3-dev \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add rustfmt clippy

# Scanner contract: repository checkout lives at /src inside the image.
COPY . /src
WORKDIR /src

# Download every crate in Cargo.lock (including optional features) while
# network access is still enabled.
RUN cargo fetch --locked

# Build workspace binaries and test targets (with debug symbols from the dev
# profile and frame pointers from RUSTFLAGS) so offline runs reuse the cache.
RUN cargo build --locked --features=magic-module,rules-profiling \
    && cargo build --locked --bin yr --features=magic-module,rules-profiling \
    && cargo test --locked --no-run --features=magic-module,rules-profiling \
    && cargo test --locked --no-run -p yara-x \
        --features=magic-module,msi-module,olecf-module,vba-module,rules-profiling \
    && cargo test --locked --no-run -p yara-x --features=pulley,magic-module

# Verify tests work in offline mode without failing the image build on a flaky test.
RUN (cargo test --locked --offline --features=magic-module,rules-profiling \
    && CARGO_BIN_EXE_yr=/src/target/debug/yr \
        cargo test --locked --offline -p yara-x-cli --bin yr) \
    || echo "WARNING: cargo test reported failures"
