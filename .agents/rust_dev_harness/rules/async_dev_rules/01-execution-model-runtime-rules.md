# 01 — Execution Model and Runtime Rules

## Required

Choose the execution model from workload semantics, not fashion.

- Use async primarily for I/O waiting, timers, sockets, high-concurrency request handling, and orchestration of work that frequently yields.
- Keep pure domain/calculation functions synchronous unless they genuinely await an effect.
- Use OS threads/scoped threads for thread-affine or independently blocking work when a dedicated thread is the clearer ownership model.
- Use a bounded CPU-parallel executor such as Rayon or a project-approved dedicated pool for substantial CPU-bound parallel work.
- Do not perform long blocking calls or substantial CPU work directly on async executor worker threads.
- Do not create nested runtimes inside reusable library functions to hide an async/sync boundary.

## Runtime ownership

- The application/runtime boundary chooses and configures the executor.
- Reusable domain/core libraries SHOULD remain runtime-agnostic unless runtime primitives are part of the library contract.
- Reusable async libraries SHOULD avoid spawning background tasks that outlive an API call unless the returned component explicitly owns those tasks and exposes lifecycle/shutdown semantics.
- Runtime handles, thread counts, blocking-pool limits, timer behavior, and local-task requirements belong in repository-local configuration/profile rather than hidden globals.

## Tokio when selected

Tokio is a common production runtime, but it is not mandatory for this shared harness.

When Tokio is selected:

- choose multi-thread vs current-thread runtime intentionally;
- enable only required Tokio features;
- do not assume `tokio::spawn` is structured concurrency;
- isolate blocking/CPU-heavy work per `06-blocking-cpu-parallelism-rules.md`;
- use Tokio-specific synchronization only when its async semantics are actually needed.

## Sync ↔ async boundaries

- Prefer one clear boundary over repeated blocking/async conversions deep in the call graph.
- A synchronous API over async internals requires an explicit runtime/lifecycle ownership design; do not silently start a new runtime per call.
- An async API over synchronous work must classify the work as tiny/nonblocking, blocking I/O, or CPU-heavy and route it accordingly.

## Forbidden

- Marking a function `async` only because its caller is async.
- Hidden executor creation in low-level/domain code.
- Significant blocking/CPU work on executor workers without an approved boundary.
- Runtime selection that exists only because a dependency happened to use that runtime.