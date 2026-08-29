# 08 — Async Error, Panic, and Graceful Shutdown Rules

## Required

Async component lifecycle is explicit and testable.

- Expected cancellation, timeout, channel closure, peer disconnect, capacity rejection, and dependency unavailability are typed/structured outcomes, not automatic panics.
- Spawned task errors and panics must reach the owning parent/supervisor.
- Do not ignore `JoinError`/equivalent task-join failure without an explicit policy.
- A panic in one child task must not silently leave sibling/resource tasks running indefinitely unless the supervisor contract intentionally permits it.

## Graceful shutdown phases

A long-lived component SHOULD define these phases explicitly:

1. **signal** — receive/propagate shutdown or cancellation;
2. **stop admission** — stop accepting new work;
3. **drain/cancel** — finish bounded in-flight work or cooperatively cancel it according to policy;
4. **close resources** — close channels/connections/listeners and release permits;
5. **join** — await owned child tasks/threads;
6. **report** — return shutdown result and expose incomplete/forced termination if any.

Do not declare shutdown complete merely because the top-level cancellation signal was sent.

## Explicit shutdown API

Because Rust `Drop` cannot generally await asynchronous cleanup, components that own async tasks/resources SHOULD expose an explicit async shutdown/close method when completion matters.

`Drop` may provide a best-effort synchronous safety net, but it must not be the only mechanism for required asynchronous draining or joining.

## Cancellation propagation

- Parent/component shutdown propagates to owned child tasks.
- Children release resources/permits and return in bounded time according to the contract.
- If a child cannot be cancelled safely, document whether shutdown waits for completion, abandons the result, or escalates to process-level termination.
- Long blocking/CPU jobs follow `06-blocking-cpu-parallelism-rules.md`; abrupt async abort may not stop them.

## Forced shutdown

If a graceful phase has a deadline:

- define what happens when the deadline expires;
- distinguish graceful completion from forced abort/abandonment;
- preserve enough state/telemetry for reconciliation of possibly incomplete external effects;
- do not retry/duplicate effects blindly during restart.

## Channel/resource closure

- Define who drops the final sender/receiver/owner.
- Shutdown must not deadlock because producers are waiting on a full queue whose consumer already stopped.
- Request/response callers waiting on oneshot/equivalent replies must receive a defined closure/cancellation result.

## Verification

Test at least the applicable paths:

- clean shutdown with no work;
- shutdown with in-flight work;
- shutdown under queue saturation;
- child error/panic propagation;
- cancellation during I/O;
- timeout/forced shutdown;
- no owned task/resource remains live after successful shutdown evidence.

## Forbidden

- signal-only 'graceful shutdown' with no join/drain evidence.
- detached child tasks owned by a component that claims deterministic lifecycle.
- swallowing child panics/errors into logs while reporting successful component completion.
- relying on `Drop` for required async cleanup.