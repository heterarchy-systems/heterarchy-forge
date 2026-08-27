# Convenience root runner delegating to the canonical Rust harness.
#
# Canonical authority remains `cargo xtask <command>`; these targets exist so
# day-to-day verification has one short entrypoint.

RUSTUP ?= rustup
RUST_TOOLCHAIN := 1.92.0
CARGO := $(RUSTUP) run $(RUST_TOOLCHAIN) cargo

.PHONY: ci rules fmt check test doctor deps supply-chain extended perf msrv clean

ci:
	$(CARGO) xtask ci

rules:
	$(CARGO) xtask rules

fmt:
	$(CARGO) xtask fmt

check:
	$(CARGO) xtask check

test:
	$(CARGO) xtask test

doctor:
	$(CARGO) xtask doctor

deps:
	$(CARGO) xtask deps

supply-chain:
	$(CARGO) xtask supply-chain

extended:
	$(CARGO) xtask extended

perf:
	$(CARGO) xtask perf

msrv:
	$(CARGO) xtask msrv

clean:
	$(CARGO) clean
