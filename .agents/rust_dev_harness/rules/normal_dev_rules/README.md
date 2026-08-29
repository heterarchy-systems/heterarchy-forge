# Normal Rust Development Rules

Reusable **baseline non-type/non-async Rust engineering rules**. These rules always compose with `../type_dev_rules/`; async/concurrent changes additionally compose with `../async_dev_rules/`.

Read `00-overview.md` first, then the files matching the change:

- `01-boundary.md`: crate/domain/effect authority and dependency direction
- `02-workspace-crate-rules.md`: Cargo workspace, toolchain, MSRV, features, dependency policy
- `03-deterministic-state-machine-rules.md`: deterministic transition/state-machine calculations
- `04-ffi-interop-boundary-rules.md`: optional FFI/interop boundary
- `05-error-panic-rules.md`: typed errors, panic discipline, invariant failures
- `06-testing-verification-rules.md`: unit, integration, property, corpus, feature-matrix, and runtime verification
- `07-performance-memory-rules.md`: runtime/build performance, allocation, RSS, scaling
- `08-observability-operations-rules.md`: structured diagnostics and operational evidence

Type modeling, ownership/borrowing, traits/generics, `Option`/`Result`, conversions, public type evolution, `Send`/`Sync` type semantics and unsafe type invariants live in `../type_dev_rules/` and are baseline for every Rust project.

## Composition

```text
ordinary Rust
→ normal_dev_rules + type_dev_rules

async/concurrent Rust
→ normal_dev_rules + type_dev_rules + async_dev_rules
```

No rule family replaces another. Async rules add execution/lifecycle/concurrency policy; type rules own compile-time representation and soundness policy.

## 2026 baseline

- Rust 1.98.0 research baseline; repository-owned stable/MSRV policy remains authority.
- Rust Edition 2024 / workspace resolver 3.
- Stable-first development.
- Shared workspace lint policy; `unsafe_code = "forbid"` by default.
- Explicit crate/effect authority.
- Bounded resource/concurrency design.
- Evidence-gated correctness, compatibility, performance, and operations.
- No permanent dual authority or silent fallback after cutover.

## Project specialization

Project-specific runtime, feature matrix, unsafe/FFI approvals, dependency policy, public API compatibility, async execution model and verification gates belong in repository-local `PROJECT_PROFILE.md`, adapted from `../../PROJECT_PROFILE.template.md`.

Repository-local profile/config/source and executed verification are final authority for a concrete project.
