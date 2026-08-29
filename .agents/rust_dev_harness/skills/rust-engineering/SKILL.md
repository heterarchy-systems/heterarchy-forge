---
name: rust-engineering
description: Production Rust engineering methodology for application, library, service, runtime, CLI and systems work. Applies normal + type rules to every Rust change and adds async rules when concurrency/runtime behavior is involved.
version: 3.0.0
researched_at: 2026-08-26
---

# Rust Engineering

Canonical pure Rust methodology skill.

## 1. Read project authority

1. repository-local `PROJECT_PROFILE.md`
2. `rules/normal_dev_rules/README.md`
3. `rules/type_dev_rules/README.md`
4. `rules/async_dev_rules/README.md` when async/concurrency is touched
5. Cargo workspace manifests/config, rust-toolchain, local agent rules, tests and live source

Do not replace repository authority with stale shared examples.

## 2. Classify the change

Identify:

- crate/application/domain/effect boundary affected;
- public vs internal API;
- type/invariant changes;
- ownership/lifetime/thread-safety changes;
- FFI/unsafe involvement;
- sync vs async/runtime execution;
- persistence/network/filesystem/process effects;
- feature/MSRV/dependency compatibility;
- performance or operational claims.

## 3. Type-first contract

Before implementation, define the semantic value contract:

```text
raw/external representation
→ checked parse/conversion
→ domain/newtype/enum/outcome
→ application operation
→ typed result/error/event
```

Review in this order when relevant:

1. newtype/invariant and valid construction;
2. enum/state/outcome shape;
3. ownership/borrowing/lifetime;
4. trait/generic bounds and pointer/interior-mutability choices;
5. `Send`/`Sync` and thread-local semantics;
6. conversion/parsing/casting behavior;
7. public API/SemVer evolution;
8. unsafe proof obligation.

Do not add `Clone`, `Arc`, `Mutex`, `Send`, `Sync`, `'static`, generic bounds, or unsafe impls merely to make one implementation/runtime compile.

## 4. Effect and authority boundary

Keep pure/domain calculations separate from effects where practical. Resolve clocks/randomness/config/runtime observations outside deterministic core decisions and pass them explicitly as typed inputs.

One production concern has one authority after cutover. Compatibility oracles may exist temporarily, but silent permanent dual implementations/fallbacks do not.

## 5. Async/concurrency — when applicable

Async is for concurrency/waiting, not CPU parallelism by default.

Define:

- runtime/executor owner;
- task owner/join/supervision;
- cancellation/deadline propagation;
- queue/in-flight/connection bounds;
- lock/channel/shared-state semantics;
- blocking bridge;
- CPU executor/worker strategy;
- local-task/thread-affinity needs;
- shutdown and leak evidence.

Type-level `Send`/`Sync` soundness remains governed by type rules even when an async executor imposes additional task bounds.

## 6. Dependencies and features

Add dependencies only for a concrete capability. Keep default features/minimal feature sets intentional. Review build scripts, proc macros, native dependencies and public dependency leakage according to risk.

Feature combinations are either composable and verified together or explicitly constrained by project profile.

## 7. Unsafe / FFI

Safe Rust is the default. When unsafe is approved, localize it, document the exact invariant/proof and ensure safe callers cannot violate it. FFI adds ABI, lifetime, panic/unwind, ownership, thread-affinity and real-runtime verification requirements.

## 8. Verification ladder

```text
focused regression
→ cargo xtask rules
→ cargo xtask fmt
→ cargo xtask check
→ cargo xtask test
→ cargo xtask ci
→ deeper gates as applicable
```

Deeper gates may include dependency/supply-chain checks, docs, feature matrices, Miri, fuzz/property/corpus tests, Loom/Shuttle/stress/fault tests, ABI/integration tests and SemVer consumer evidence.

No unexecuted gate is PASS.

## 9. Performance

Measure before optimizing. Distinguish algorithmic complexity, allocations/copies, contention, syscalls/I/O, serialization, executor overhead, RSS and build/check latency.

Do not add unsafe, atomics, manual memory tricks or broad monomorphization solely for speculative speed.

## 10. Completion

Report:

- affected authority/type/API boundaries;
- public/MSRV/feature/ABI implications;
- async/runtime implications if any;
- unsafe proof boundary if any;
- exact gates executed and unverified lanes;
- performance evidence for performance claims.

Research baseline: Rust 1.98.0 (2026-08-20); the repository's declared toolchain/MSRV remains concrete authority.
