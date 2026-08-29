# 00 — Rust Engineering Overview

Rust shared policy is split into three additive rule families:

```text
normal_dev_rules
+ type_dev_rules
+ async_dev_rules when applicable
```

## Baseline

Every Rust project applies both:

- `normal_dev_rules/` — workspace, authority, deterministic logic, FFI, error/panic, testing, performance and operations;
- `type_dev_rules/` — domain types, enums, `Option`/`Result`, traits/generics, ownership/borrowing, smart pointers/interior mutability, `Send`/`Sync`, conversions, public type evolution and unsafe type invariants.

Async/concurrent code additionally applies `async_dev_rules/`.

## Engineering principles

- Model invariants and authority explicitly.
- Prefer compiler-enforced distinctions over comments and caller convention.
- Keep effectful runtime concerns out of pure domain calculations.
- Do not add ownership wrappers, concurrency traits or async machinery merely to satisfy an implementation detail.
- Stable/public APIs are compatibility contracts, including auto traits and trait bounds.
- `unsafe` is a localized proof obligation, not a normal implementation shortcut.
- Measure before optimizing; preserve correctness and soundness first.
- A required verification gate that did not run is not PASS.

Research baseline: Rust 1.98.0 released 2026-08-20; repository-local toolchain/MSRV policy remains authoritative.
