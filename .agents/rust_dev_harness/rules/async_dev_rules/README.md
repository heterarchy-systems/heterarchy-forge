# Async and Concurrency Development Rules

Reusable async/concurrency rules for the pure Rust harness.

These rules are additive to the two baseline families:

```text
async/concurrent Rust
→ ../normal_dev_rules/
+ ../type_dev_rules/
+ this async_dev_rules/
```

Read this README whenever a change introduces/modifies `async fn`, `.await`, an executor/runtime, spawned tasks, channels/queues/semaphores, async locks, cancellation/timeouts/select, blocking bridges/CPU parallelism, local tasks/thread affinity, graceful shutdown, or concurrency tests/observability.

## Core model

```text
I/O waiting / many concurrent sockets / timers
→ async runtime

CPU-heavy parallel computation
→ bounded CPU executor / Rayon / dedicated pool

small blocking or thread-affine work
→ bounded blocking bridge / dedicated thread

pure domain calculation
→ synchronous Rust function by default
```

Async is a concurrency tool, not a requirement for all Rust functions.

## Routing

| Change area | Rule |
| --- | --- |
| Runtime/executor and async boundary | rule 01 — Execution Model and Runtime |
| Spawn/task lifetime/supervision | rule 02 — Task Ownership and Structured Concurrency |
| Cancellation/timeout/select/race | rule 03 — Cancellation, Timeout, and Select |
| Queue/channel/task/connection limits | rule 04 — Bounded Concurrency and Backpressure |
| Mutex/RwLock/channel/shared state | rule 05 — Shared State, Locks, and Channels |
| Blocking calls / CPU-heavy work / Rayon | rule 06 — Blocking and CPU Parallelism |
| Runtime `Send`/`Sync` requirements / local task placement | rule 07 — Send, Sync, and Local Tasks |
| Errors/panics/graceful shutdown | rule 08 — Async Errors and Shutdown |
| Async/concurrency tests | rule 09 — Async Testing and Verification |
| Tracing/runtime performance | rule 10 — Async Observability and Performance |

Type-level ownership/borrowing and `Send`/`Sync` soundness live in `../type_dev_rules/`; this directory owns executor/task/lifecycle behavior.

## 2026 default policy

- Prefer structured task ownership over free-floating spawn.
- Detached/fire-and-forget tasks are exceptional and explicitly reviewed.
- Cancellation is an API/lifecycle concern.
- Every queue and concurrency path has an explicit or externally proven bound.
- Do not hold blocking lock guards across `.await`.
- Do not run significant CPU/blocking work on async executor worker threads.
- `spawn_blocking` is a bounded bridge, not an unlimited CPU scheduler.
- Do not force a type to become `Send`/`Sync` solely to satisfy the selected executor.
- Deterministic async tests use virtual/controlled time rather than arbitrary sleeps.
- Low-level concurrency uses stronger schedule/interleaving verification when ordinary tests are insufficient.

## Runtime choice

Tokio is a common production default when its ecosystem fits, but this shared harness is runtime-neutral. Repository-local `PROJECT_PROFILE.md` declares the approved runtime/executor and runtime-specific primitives.
