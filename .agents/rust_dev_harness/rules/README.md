# Rust Rules Router

2026-08-26 pure Rust shared policy is split into three additive rule families:

```text
rules/
├─ README.md
├─ normal_dev_rules/
├─ type_dev_rules/
└─ async_dev_rules/
```

## Composition

```text
ordinary Rust change
→ normal_dev_rules + type_dev_rules

async/concurrent Rust change
→ normal_dev_rules + type_dev_rules + async_dev_rules
```

## Responsibilities

### `normal_dev_rules/`

Owns repository/workspace and runtime-independent engineering structure:

- crate/effect authority and dependency direction;
- Cargo workspace/toolchain/MSRV/features;
- deterministic state-machine behavior;
- optional FFI/interop boundary;
- error/panic discipline;
- testing/verification;
- performance/memory/build evidence;
- observability/operations;
- module file layout, responsibility-driven decomposition, visibility boundaries, and unit/integration test organization.

### `type_dev_rules/`

Owns compile-time semantic and soundness policy:

- domain newtypes/invariants;
- enums/state/sum types;
- `Option`/`Result`/outcomes;
- traits/generics/bounds;
- ownership/borrowing/lifetimes;
- smart pointers/interior mutability;
- `Send`/`Sync` type-level promises;
- conversions/parsing/casts;
- public API type evolution;
- unsafe type invariants.

### `async_dev_rules/`

Adds runtime concurrency/lifecycle policy:

- executor/runtime selection;
- task ownership/supervision;
- cancellation/timeout/select;
- bounded concurrency/backpressure;
- shared-state runtime usage;
- blocking vs CPU parallelism;
- local-task/runtime placement;
- async shutdown/testing/observability.

## 2026 module/test organization baseline

For new code and intentional module refactors, prefer the current Rust Book path model `foo.rs` + `foo/bar.rs`. `foo/mod.rs` remains supported but is the older style; preserve it where an established repository convention requires it rather than performing cosmetic churn.

Module decomposition is based on responsibility/authority/change reason, not arbitrary source-file line counts. Unit tests stay within the production module tree (`#[cfg(test)] mod tests` or an adjacent child `tests.rs` when large). Package-root `tests/` is for external crate/application integration contracts. Visibility should remain as narrow as possible: private → `pub(super)` → `pub(crate)` → `pub`.

Detailed policy: `normal_dev_rules/09-module-layout-rules.md`.

## Routing principle

Type rules are not optional. Every Rust project uses normal + type. Async is conditional because synchronous libraries/applications should not be forced to adopt an async runtime.

When a concern overlaps, the type family owns what the value **is allowed to mean/be**, while the async family owns **where/how it executes concurrently**.

## Authority

Repository-local `PROJECT_PROFILE.md`, Cargo/rust-toolchain configuration, source/tests and executed xtask/CI are final authority for a concrete project. Shared Jobs rules are reusable policy/reference and do not silently override an intentional documented project contract.
