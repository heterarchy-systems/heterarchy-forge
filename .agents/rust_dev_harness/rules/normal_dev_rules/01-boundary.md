# 01 — Boundary and Authority Rules

## Required

- Separate domain calculation, runtime orchestration, external effects, persistence, transport, and adapters by explicit ownership rather than convenience imports.
- Core/domain crates depend inward on domain abstractions and values; integration/runtime crates depend on the core, not the reverse.
- Rust code must not read clocks, randomness, environment variables, process identity, global mutable state, filesystem/network state, or persistence implicitly when those observations affect a deterministic decision. Pass such values explicitly or isolate them in an effect boundary.
- An application may intentionally let Rust own I/O, persistence, lifecycle, networking, or process control. This shared harness does not assume an external host. The repository-local project profile declares those authorities.
- Adapter/transport crates convert representations and invoke domain/application APIs; they do not duplicate policy or create a second source of truth.
- Public boundaries use explicit typed input/output and preserve domain error meaning.
- Dependency cycles between core/domain/application/infrastructure crates are design failures unless a narrowly documented technical constraint proves otherwise.

## Preferred direction

```text
interface / transport / adapters
            ↓
application / orchestration
            ↓
domain / deterministic core
```

Infrastructure may implement inward-facing traits/ports, but domain code must not import concrete infrastructure merely to reach an effect.

## Async boundary

When a boundary becomes asynchronous:

- do not make pure computation `async` only because its caller is async;
- keep I/O waiting and runtime orchestration at the effect/application boundary;
- read `../async_dev_rules/README.md` for task ownership, cancellation, blocking, channels, locks, and concurrency budgets.

## Optional FFI / interop

If Rust exposes or consumes an FFI/language boundary, `05-ffi-interop-boundary-rules.md` applies. FFI is optional; it is not part of the identity of this pure Rust harness.

## Authority rule

Moving code between crates, runtimes, threads, executors, or languages does not implicitly transfer product policy or source-of-truth authority. Authority changes require an explicit architecture/profile decision and verification that the previous competing authority is retired when appropriate.