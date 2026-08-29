# 06 — Blocking and CPU Parallelism Rules

## Required

Async executor worker threads must remain available to poll other futures.

- Do not perform substantial blocking I/O, synchronous waits, long filesystem calls, process waits, or CPU-heavy loops directly inside async tasks.
- Classify synchronous work before bridging it: tiny/nonblocking, bounded blocking I/O, CPU-heavy parallel work, or long-lived dedicated-thread work.
- Every blocking/CPU bridge has an explicit concurrency limit and shutdown policy.
- Avoid nested parallelism that oversubscribes cores or multiplies thread pools without measured benefit.

## `spawn_blocking` when Tokio is selected

Use `spawn_blocking` for bounded synchronous work that eventually finishes and for blocking APIs that cannot be made async reasonably.

Important semantics:

- the default blocking pool can grow large because it also serves blocking I/O use cases;
- many CPU-heavy `spawn_blocking` jobs therefore require a semaphore/other explicit limit;
- once a blocking job has started, aborting its handle does not reliably stop the underlying work;
- runtime shutdown can wait on started blocking work, so long-running jobs require their own cooperative stop/deadline design.

Do not use `spawn_blocking` as the default unlimited CPU executor.

## CPU-heavy work

For substantial CPU-bound parallelism:

- prefer Rayon or another repository-approved bounded CPU executor/pool;
- size/measure parallelism against available cores and the rest of the process workload;
- avoid crossing async↔CPU boundaries per tiny item when batching can reduce scheduling/copy overhead;
- long CPU jobs SHOULD support cooperative cancellation/checkpoints when the caller needs bounded cancellation/shutdown latency;
- preserve deterministic results/order where the public contract requires it.

## Dedicated threads

Use a dedicated thread when work is:

- long-lived blocking;
- thread-affine;
- tied to a synchronous event loop/runtime;
- clearer as an owned component than repeated blocking-pool jobs.

Prefer scoped threads when lexical borrowing/lifetime ownership fits the job and the thread does not need to outlive the scope.

## Blocking locks

Short synchronous lock sections are allowed under `05-shared-state-lock-channel-rules.md`, but waiting on a heavily contended blocking mutex inside executor workers can still starve unrelated tasks. Measure contention and restructure when it becomes material.

## Verification

Measure:

- executor responsiveness/tail latency;
- blocking queue/pool usage;
- CPU pool utilization;
- task/worker oversubscription;
- cancellation/shutdown latency;
- end-to-end throughput, not just kernel speed.

## Forbidden

- busy-waiting in async tasks.
- large CPU loops that rely on rare `.await` points for fairness.
- unbounded `spawn_blocking` from untrusted/request-driven input.
- assuming abort stops already-running blocking work.
- creating multiple independent CPU pools with no process-level resource plan.