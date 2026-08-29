# 10 — Async Observability and Performance Rules

## Required

Async performance includes scheduler/resource behavior, not only handler wall time.

Observe and measure the signals relevant to the system:

- task count and spawn rate
- task lifetime and owned component/run identity
- queue/channel depth, saturation, send/receive wait
- semaphore/connection/pool utilization
- timeout, retry, cancellation, and forced-shutdown rates
- long polls / non-yielding work / suspected executor blocking
- lock and resource contention
- blocking-pool and CPU-pool utilization
- tail latency and throughput under realistic concurrency
- shutdown/drain latency

## Structured tracing

Prefer structured tracing/spans when causal context crosses awaits/tasks.

- Carry request/job/task/component identity explicitly or through approved instrumentation.
- Do not depend on OS thread ID as the causal identity of async work.
- Parent/child task relationships SHOULD be observable for important long-lived components.
- Task errors/panics must be attributable to an owner/supervisor.
- Do not place secrets or unbounded payloads in spans/events.

When Tokio is selected, Tokio tracing/console-compatible instrumentation may be used for diagnosis when scheduler/task behavior is material. Runtime-specific diagnostic tooling is optional evidence, not domain authority.

## Performance diagnosis order

When async latency/throughput degrades, check in this order before speculative low-level optimization:

1. unbounded or saturated queues;
2. blocking/CPU work on executor threads;
3. excessive task spawning / tiny-task overhead;
4. lock/semaphore/resource contention;
5. too-chatty I/O or boundary crossings;
6. nested retries/timeouts;
7. oversubscribed blocking/CPU pools;
8. allocation/copy pressure;
9. algorithm/data-structure cost.

The exact order may change with evidence, but scheduler/resource pathologies must not be ignored simply because a CPU flamegraph has a visible hotspot.

## Concurrency benchmark policy

- Benchmark with realistic concurrency levels and input distributions, not only single-request microbenchmarks.
- Include saturation/overload points when they are part of production risk.
- Compare median and tail behavior where user/system latency matters.
- Report the concurrency setting, queue/buffer sizes, runtime worker configuration, CPU-pool configuration, build profile, and machine/runtime version when relevant.
- Avoid benchmarks whose only result is 'more tasks is faster'; identify the point where contention/oversubscription reverses the gain.

## Starvation / fairness

- Long non-yielding futures can starve unrelated work on cooperative executors.
- Do not add manual `yield_now` calls as a default fix for CPU-heavy design; move/classify the work correctly first.
- If fairness/priority is required, make it an explicit scheduling/admission contract and test/observe it.

## Operational alarms

Critical async services SHOULD consider thresholds for:

- sustained queue saturation;
- permit/pool exhaustion;
- abnormal cancellation/timeout rate;
- shutdown exceeding budget;
- executor/blocking-pool starvation indicators;
- rapidly growing task count.

Thresholds require workload evidence and should not be copied blindly between projects.

## Forbidden

- calling a path optimized when kernel time fell but end-to-end tail latency or queue growth worsened.
- hiding overload by increasing queue capacity without a capacity model.
- relying only on thread-based logs to debug task causality.
- adding scheduler/runtime tuning before measuring blocking, contention, queueing, and CPU oversubscription.