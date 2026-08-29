# 05 — Error and Panic Rules

## Required

- Expected runtime/input failures return typed errors; they do not panic for malformed input, rejected state, capacity pressure, stale revisions, timeouts, cancellation, unavailable dependencies, or ordinary I/O failure.
- Production code avoids `unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!`, and `dbg!` as control flow.
- Tests may use narrow `unwrap`/`expect` when failure is intentionally equivalent to test failure and the message/context remains understandable.
- Preserve error sources and structured context at boundaries; do not erase causality into an opaque string too early.
- Domain/library APIs expose stable semantic error variants/categories. Application/binary boundaries may add richer operational context without leaking infrastructure details back into the domain.
- Distinguish validation, invariant, capacity/resource, stale/conflict, cancellation/timeout, dependency/I/O, compatibility, and adapter/interop failures when callers need different handling.
- Impossible internal states require a nearby invariant explanation and focused evidence. `unreachable!`/panic is not a substitute for modeling a reachable state.
- Do not log and then silently discard an error unless the ignore policy is explicit and tested/observable where operationally relevant.

Type-level absence/failure/outcome semantics are defined by Rust type rule 03. This normal rule owns error taxonomy, propagation, panic policy and operational behavior.

## Panic boundary

Panics represent bugs, violated internal invariants, or deliberately unrecoverable process-level conditions—not ordinary domain errors.

- Library code SHOULD avoid panics on caller-controlled input unless the API contract explicitly documents a panic precondition and a fallible alternative would be unreasonable.
- Spawned task/thread panics must not disappear unnoticed; parent/supervisor code must observe and classify join failures.
- Panics must not cross FFI boundaries uncontrolled.

## Async / cancellation

Cancellation and timeout are normal control outcomes in async systems when the API permits them. Do not report them as invariant bugs merely because a future did not complete.

Read async rule 03 for cancellation/timeout/select and async rule 08 for shutdown/error lifecycle.

## Completion

Do not claim an error path is handled until focused tests, integration evidence, or an explicitly documented unverified gap supports the claim.
