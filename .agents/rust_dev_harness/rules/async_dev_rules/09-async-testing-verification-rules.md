# 09 — Async and Concurrency Testing Rules

## Required

Async/concurrent correctness requires evidence for timing, cancellation, ownership, overload, and scheduling behavior—not only happy-path output.

## Deterministic async tests

- Avoid wall-clock sleeps as synchronization.
- Use virtual/paused/controllable time when the runtime supports it.
- Inject a clock abstraction when runtime virtual time is insufficient or the domain must remain runtime-neutral.
- Timeouts in tests may bound a hung test, but they are not proof that synchronization is correct.
- Prefer observable state, channels, barriers, notifications, joins, or explicit hooks over arbitrary sleep durations.

## Required behavior tests when applicable

- task owner joins children on success/error/shutdown;
- cancellation releases permits/locks/resources;
- timeout does not corrupt protocol/domain state;
- queue saturation applies the documented backpressure policy;
- channel sender/receiver drop semantics are correct;
- no task creation path exceeds the intended concurrency bound;
- graceful shutdown drains/cancels/joins as designed;
- blocking/CPU jobs do not stall executor progress beyond the approved budget;
- child errors/panics are observed by the supervisor.

## Schedule/interleaving testing

Ordinary tests exercise only a tiny subset of possible interleavings.

Use stronger tools proportionally to risk:

- **Loom** or equivalent model/interleaving exploration for small low-level synchronization primitives, atomics, channels, lock ordering, and custom concurrency code.
- **Shuttle** or equivalent controlled/randomized scheduling for larger concurrent components where exhaustive state exploration is impractical.
- **Miri** where unsafe/aliasing/thread-safety assumptions need interpreter-based UB checking.
- stress/soak/fault tests for integration/runtime behavior that depends on OS/network/resource pressure.

Failures from controlled schedulers SHOULD preserve/replay the seed/schedule when the tool supports it.

## Cancellation safety tests

For operations used under `select!`, timeout, abort, or dropped futures:

- cancel at multiple meaningful checkpoints;
- retry/resume only according to the documented contract;
- verify no lost/duplicated observable data/effects;
- verify queues/permits/locks/resources are released;
- verify partially completed external effects are reconciled/idempotent when required.

## Runtime-specific example: Tokio

When Tokio is selected, virtual time (`start_paused`, pause/advance or equivalent) SHOULD be used for deterministic timer/backoff/deadline tests where possible.

Tokio-specific task tests should reflect real semantics such as `JoinHandle` detachment and `JoinSet` ownership rather than mocked assumptions.

## Test isolation

- Avoid global runtime/singleton state that makes tests order-dependent.
- Do not require serial execution merely to hide shared-state bugs unless the shared singleton is itself the product contract.
- Use bounded test resources and deterministic ports/temp paths when applicable.

## CI tiering

Fast PR CI SHOULD cover deterministic cancellation/shutdown/backpressure tests.

Loom/Shuttle/Miri/stress/soak suites may live in extended/high-risk/scheduled gates when cost is significant, but a required extended gate that did not run is reported as unverified.

## Forbidden

- `sleep(100ms)` as the primary proof that another task 'probably ran'.
- nondeterministic flaky tests accepted as normal concurrency behavior.
- ignoring a concurrency-test failure because it is hard to reproduce.
- testing only successful completion while production relies on cancellation/timeout/shutdown.