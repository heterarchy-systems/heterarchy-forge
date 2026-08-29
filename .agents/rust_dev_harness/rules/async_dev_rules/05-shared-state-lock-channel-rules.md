# 05 — Shared State, Lock, and Channel Rules

## Required

Choose shared-state mechanisms from ownership and await semantics, not habit.

## Simple synchronous data

For short, low-contention critical sections that do not cross `.await`, a synchronous mutex is acceptable even inside async code.

- Keep the critical section small.
- Do not perform I/O, blocking work, or `.await` while holding the guard.
- Prefer wrapping the lock in a type whose public mutation methods are synchronous so guards cannot accidentally escape into async code.
- Measure contention before replacing a simple mutex with a more complex design.

## Async mutex

Use an async mutex only when exclusive ownership genuinely must be held across `.await` and restructuring/message passing is not clearer.

- Async mutexes are not a universal upgrade over `std::sync::Mutex`.
- Review hold duration, cancellation behavior while waiting, fairness requirements, and shutdown behavior.
- Avoid one global async mutex around a high-throughput resource when pipelining/sharding/ownership would remove serialization.

## Owned async resource

For stateful I/O resources that require exclusive async access—such as a protocol client/socket writer—prefer an owner task plus bounded message passing when it improves ownership and throughput.

```text
producer tasks
     ↓ bounded channel
resource-owner task
     ↓
I/O resource
```

The owner task must follow the task-ownership, backpressure, cancellation, and shutdown rules.

## Channels

- Choose channel semantics intentionally: mpsc, oneshot/request-response, broadcast, watch/latest-value, or another project-approved primitive.
- Prefer bounded mpsc/work queues.
- Document closure semantics: what sender/receiver drop means and how pending callers learn shutdown.
- Avoid using a channel as an implicit database or permanent history.
- Do not clone senders/receivers indiscriminately when it obscures who can keep a channel alive.

## RwLock / sharding / atomics

- `RwLock` is not automatically faster than `Mutex`; choose it only when the read/write workload justifies it.
- Sharding can reduce contention but increases consistency/ordering complexity; use measured need.
- Atomics/lock-free structures require a much stronger correctness burden and concurrency-specific tests.

## Forbidden

- holding a blocking lock guard across `.await`.
- switching to an async mutex only to silence `Send`/compiler errors without reviewing deadlock/serialization.
- global shared mutable state when ownership can be local to a component/task.
- unbounded channels used to avoid dealing with backpressure.
- multiple locks with undocumented acquisition order in deadlock-sensitive code.