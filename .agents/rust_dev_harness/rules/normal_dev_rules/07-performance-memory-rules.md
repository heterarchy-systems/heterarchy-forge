# 07 — Performance, Memory, and Build-Time Rules

## Required

- Correctness and verified semantics come before optimization.
- Measure a baseline before claiming improvement and compare the same workload/build profile/environment after the change.
- Runtime evidence uses relevant metrics: wall/CPU time, throughput, tail latency, allocation/copy pressure, peak RSS, scaling, contention, queue depth and I/O where applicable.
- Caller-controlled collections, queues, buffers, spawned work, caches and generic specialization growth are bounded, streamed, backpressured, or justified.
- Prefer algorithmic improvement, batching, single-pass processing, reduced allocation/copying, data-layout improvement and fewer boundary crossings before unsafe/lock-free/SIMD/custom-allocator complexity.
- Do not introduce unsafe, custom allocators, lock-free structures, handwritten parsers, architecture-specific SIMD or non-default schedulers without measured need and stronger correctness evidence.
- Record workload/corpus, input sizes, build profile, CPU/OS/toolchain versions and threshold rationale when materially relevant.

## Type-system performance

Type architecture can affect performance and build cost:

- excessive cloning/shared ownership can add runtime allocation/reference-counting cost;
- very broad generics/monomorphization can increase code size and compile time;
- dynamic dispatch can trade optimization for smaller/stabler code boundaries;
- representation/layout changes require measurement, not intuition;
- typestate/type-level machinery should earn its compile-time/API complexity.

Do not weaken semantic type safety merely for speculative speed.

## Async / concurrency performance

Measure task count/spawn rate, scheduling delay, long polls/blocking sections, contention, queue depth/saturation, cancellation/shutdown latency, blocking-pool use and CPU oversubscription where relevant.

A faster worker that creates unbounded queues, starvation or worse tail latency is not an improvement.

## CPU parallelism

CPU-heavy work should not monopolize async worker threads. Parallelism has an explicit budget and avoids nested oversubscription. Blocking bridges are not default unlimited CPU schedulers.

## Build / developer performance

When compile time matters, inspect clean vs incremental builds, common `cargo check` latency, high-churn crate boundaries, proc-macro/build-script cost, evidenced generic/monomorphization pressure, feature/dependency surface and codegen/resource pressure.

Use Cargo timing/build evidence before redesigning crate/type boundaries solely for perceived compile speed.

## Regression budget

- Thresholds come from historical evidence plus reviewed noise margin.
- Prefer controlled runners for hard absolute ceilings.
- Local/noisy measurements may be informational rather than release-authoritative.
- Environment multipliers must not silently expand release budgets.

## Completion

A microbenchmark alone does not prove end-to-end improvement. Report local hotspot evidence and caller/system-observed effects when optimization crosses runtime, FFI, storage, network or scheduler boundaries.
