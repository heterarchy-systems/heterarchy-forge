# Convenience root runner delegating to the canonical Rust harness.
#
# Canonical authority remains `cargo xtask <command>`; these targets exist so
# day-to-day verification has one short entrypoint.

RUSTUP ?= rustup
RUST_TOOLCHAIN := 1.98.0
# `rustup run` selects Cargo but leaves child compiler lookup to PATH.
RUST_TOOLCHAIN_BIN := $(shell "$(RUSTUP)" which --toolchain "$(RUST_TOOLCHAIN)" rustc | sed 's:/rustc$$::')
ifeq ($(strip $(RUST_TOOLCHAIN_BIN)),)
$(error pinned Rust toolchain $(RUST_TOOLCHAIN) is unavailable)
endif
CARGO := PATH="$(RUST_TOOLCHAIN_BIN):$${PATH}" "$(RUSTUP)" run $(RUST_TOOLCHAIN) cargo
CI_TARGET_DIR := target/ci-$(RUST_TOOLCHAIN)

.PHONY: ci rules fmt check test doctor deps supply-chain extended perf msrv harness package clean

ci:
	CARGO_TARGET_DIR="$${CARGO_TARGET_DIR:-$(CI_TARGET_DIR)}" $(CARGO) xtask ci

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

harness:
	$(CARGO) xtask harness

# This remains a sealed server-discovered target when invoked through FORGE.
# The actual package output location is selected only by the Rust-CI runtime.
package:
	$(CARGO) xtask package

clean:
	$(CARGO) clean
