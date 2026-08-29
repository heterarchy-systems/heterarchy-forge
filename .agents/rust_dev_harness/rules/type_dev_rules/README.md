# Rust Type Development Rules

2026-08-26 shared Rust **type policy**. Research baseline: Rust 1.98.0, Rust API Guidelines, Rust Reference/Nomicon safety model.

These rules are baseline for every Rust project and compose with `../normal_dev_rules/`. Async/concurrent code additionally applies `../async_dev_rules/`.

```text
ordinary Rust
→ normal_dev_rules + type_dev_rules

async/concurrent Rust
→ normal_dev_rules + type_dev_rules + async_dev_rules
```

## Rule map

1. `01-domain-newtype-invariant-rules.md` — semantic newtypes, validated construction, representation hiding
2. `02-enum-state-sum-type-rules.md` — finite alternatives, state payloads, exhaustive matching, typestate
3. `03-option-result-outcome-rules.md` — absence vs failure vs richer outcomes
4. `04-trait-generic-bound-rules.md` — capabilities, generics, associated types, `impl Trait`/`dyn Trait`, sealed traits
5. `05-ownership-borrow-lifetime-rules.md` — owned/borrowed semantics, cloning, `'static`, `Cow`, `Pin`
6. `06-smart-pointer-interior-mutability-rules.md` — `Box`/`Rc`/`Arc`, `Cell`/`RefCell`, locks, cycles
7. `07-send-sync-thread-safety-type-rules.md` — auto traits, thread-safety promises, unsafe impl policy
8. `08-conversion-parsing-cast-rules.md` — `From`/`TryFrom`/`AsRef`/`FromStr`, numeric/lossy casts
9. `09-public-api-type-evolution-rules.md` — private representation, non-exhaustive/sealed APIs, SemVer, public dependency leakage
10. `10-unsafe-type-invariant-rules.md` — local unsafe proof obligations and safe abstraction requirements

## Core principles

- Invalid states should be difficult or impossible to construct through safe public APIs.
- Types convey domain meaning; raw primitives/strings/boolean switches are not stable core vocabulary when stronger semantics exist.
- Ownership, borrowing, `Send`/`Sync`, lifetimes and pointer wrappers are semantic design choices, not compiler appeasement tools.
- Trait bounds are kept as narrow as the operation requires.
- Conversion APIs encode whether conversion is infallible, fallible, borrowed, parsing, or lossy.
- Public fields, enum variants, trait implementability, generic bounds and auto traits are compatibility commitments.
- `unsafe` is a proof boundary. Safe callers must not be able to violate the abstraction's invariant.

## Boundary with async rules

This directory owns the **type-level** meaning of `Send`/`Sync`, ownership and thread safety. `async_dev_rules/` owns runtime placement, task spawning, LocalSet/local tasks, cancellation, channel/lock usage and scheduler behavior.

Do not move a type from local-only semantics to `Arc<Mutex<_>>` merely to make an async runtime accept it; first decide whether cross-thread sharing is actually part of the design.

## Verification

Compiler + Clippy are primary evidence. Public libraries additionally consider SemVer/API compatibility evidence. Unsafe/concurrent type invariants require stronger evidence such as Miri, Loom/fault/stress tests or domain-specific proofs according to risk.

Repository-local `PROJECT_PROFILE.md` declares public API stability, unsafe approvals, thread-safety expectations and any justified exceptions.
