# 04 — FFI and Interop Boundary Rules

This rule is optional. It applies only when a pure Rust project exposes or consumes a language/native ABI boundary. Python/PyO3 is one possible adapter, not the identity of this harness.

## Required

- Keep the domain/core crate independent of the foreign runtime and its object model unless the foreign ABI itself is the product contract.
- Put conversion, ownership transfer, ABI/runtime integration, and foreign error translation in a narrow adapter crate/module.
- Decode and validate foreign input at the boundary, convert it into typed Rust values, invoke the authoritative Rust API, and preserve domain error meaning on return.
- Stable interop contracts use explicit schemas/types. Do not make loosely structured maps/dictionaries the canonical contract when a stronger representation exists.
- Keep the boundary coarse-grained enough to avoid chatty per-item crossings when batching or streaming is semantically valid.
- Define memory ownership, lifetimes, thread-safety, callback/reentrancy behavior, and panic behavior explicitly at the boundary.
- Rust panics must not cross an FFI boundary as undefined foreign behavior. Convert/catch only at an approved adapter boundary when required by the ABI contract; do not use panic-catching as ordinary domain error handling.
- `unsafe` required by FFI remains narrow, documented with safety invariants, and isolated from safe domain code.
- Measure conversion/copy/serialization and boundary-call costs as part of end-to-end performance.

## Type / safety composition

Apply `../type_dev_rules/` for ownership/lifetime, conversion, thread-safety, public layout, and unsafe invariants. FFI does not weaken those type rules.

## Async / blocking interop

If the foreign runtime is async or the Rust side performs blocking/CPU work:

- do not block an async executor/event loop accidentally;
- define which runtime owns scheduling and shutdown;
- avoid creating hidden nested runtimes inside library calls;
- use a reviewed blocking/CPU bridge and explicit concurrency budget;
- read the async rules for blocking/task ownership/cancellation.

## Python / PyO3 when applicable

- The PyO3 adapter remains conversion/runtime glue; domain policy stays in Rust domain/application crates.
- Do not hold Python runtime/GIL access across long Rust CPU-only work when the approved PyO3 API permits detaching/releasing it safely.
- Python async callers use an explicit approved integration strategy; do not synchronously block the Python event loop to wait for long Rust work.
- Real adapter tests verify Python-visible type, identity, ordering, error, cancellation/timeout behavior when applicable, and semantic compatibility.

## Error mapping

- Preserve machine-readable domain error categories.
- Do not collapse all failures into one string-only exception/status.
- Do not expose secrets, credentials, unnecessary source content, or local absolute paths.

## Verification

Interop claims require real boundary tests. Pure Rust unit tests alone do not prove ABI/runtime correctness.
