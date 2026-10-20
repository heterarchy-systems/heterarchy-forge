# syntax=docker/dockerfile:1
# Multi-stage build for the standalone Forge HTTP+SSE backend binary.
#
# Scope statement (updated 2026-10-02, Linux execution lane): the build
# stage compiles the backend on Linux with the pinned toolchain AND runs the
# forge-execution suite natively under bubblewrap, proving real Linux
# process execution, output capture and confinement inside this image. The
# runtime image ships bubblewrap so admitted executions stay confined; a
# missing bubblewrap still fails closed (`SandboxUnavailable`) — no
# sandbox/grant bypass exists.
#
# The host `.cargo/config.toml` points at a macOS-specific SSD target dir, so
# it is deliberately not copied; the container keeps its own target dir.

FROM rust:1.98.0-slim AS build
WORKDIR /build
ENV CARGO_TARGET_DIR=/build/target
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY vendor ./vendor
COPY xtask ./xtask
COPY crates ./crates
# Confinement backend + git for the native execution-suite run below.
RUN apt-get update \
    && apt-get install -y --no-install-recommends bubblewrap git procps \
    && rm -rf /var/lib/apt/lists/*
# The vendored policy crate resolves through [patch.crates-io] and must stay
# in the build context; `--locked` proves the build reproduces Cargo.lock.
RUN cargo build --locked --release -p forge-backend
# Native Linux execution evidence: the runner/sandbox/output suite runs the
# real bubblewrap-confined processes with network isolation enabled.
# The marker envs are the repository's own outer-sandbox declaration: tests
# that cannot run nested inside this container skip themselves (declared
# skips are visible in the log), exactly as the Rust-CI profile does.
RUN --security=insecure HETERARCHY_FORGE_RUST_CI_SANDBOX=v1 \
    HETERARCHY_FORGE_RUST_CI_TEST_POLICY=outer-rust-ci-v1 \
    cargo test --locked -p forge-execution --all-targets
# Run confinement regressions directly, outside the nested-Rust-CI declaration.
RUN --security=insecure mkdir /forge-confinement-host \
    && cp -a /usr/local/cargo /forge-confinement-host/.cargo \
    && cp -a /usr/local/rustup /forge-confinement-host/.rustup \
    && FORGE_TEST_RUST_CI_HOME=/forge-confinement-host \
       cargo test --locked -p forge-execution sandbox_linux::tests -- --ignored --nocapture \
    && rm -rf /forge-confinement-host
# Full admitted HTTP chain on Linux: source admission under WriterLease →
# approved process execution → output/terminal readback → Verification —
# the real_execution suite over a real loopback listener, natively in this
# container.
RUN --security=insecure HETERARCHY_FORGE_RUST_CI_SANDBOX=v1 \
    HETERARCHY_FORGE_RUST_CI_TEST_POLICY=outer-rust-ci-v1 \
    cargo test --locked -p forge-backend --test real_execution

# Same Debian release as the build stage: the dynamic binary must find a
# compatible glibc (rust:1.98-slim is Debian 13 trixie).
FROM debian:trixie-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl bubblewrap git \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system forge \
    && useradd --system --gid forge --home-dir /state --shell /usr/sbin/nologin forge \
    && mkdir -p /state \
    && chown forge:forge /state
COPY --from=build /build/target/release/forge-backend /usr/local/bin/forge-backend
USER forge
WORKDIR /state
# No environment-variable compatibility layer: the existing strict JSON
# config contract is the only configuration surface.
# Shell form is required here: exec-form cannot carry the `||` fallback.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/forge-backend"]
CMD ["serve", "/config/forge-backend.json"]
