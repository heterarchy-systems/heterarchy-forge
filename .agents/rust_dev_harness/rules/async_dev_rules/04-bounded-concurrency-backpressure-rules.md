# 04 — Bounded Concurrency and Backpressure Rules

## Required

Every concurrency path has an explicit resource budget or a proven external bound.

This includes:

- spawned tasks/futures
- channel/queue capacity
- open sockets/connections
- in-flight requests
- semaphore permits
- batch size
- retries and retry queues
- blocking jobs
- CPU-parallel jobs
- buffered streams

## Backpressure

- Prefer bounded channels/queues.
- When a queue is full, define what happens: wait, reject, shed, coalesce, spill to durable storage, or apply another explicit policy.
- Backpressure SHOULD propagate toward the producer rather than allowing hidden memory growth.
- Queue capacity is an engineering contract derived from memory, latency, throughput, burst tolerance, and downstream service capacity—not a random large number.
- Monitor saturation and queue depth for production paths where overload matters.

## Spawn/admission loops

A loop must not create unbounded independent work from untrusted/unbounded input.

Use one or more of:

- semaphore/admission permits
- bounded work queue
- bounded stream concurrency
- connection/request limit
- task-set size limit
- explicit worker capacity

Acquire/allocate capacity at a point that prevents already-admitted work from exceeding the intended bound.

## Unbounded channels

Unbounded channels are forbidden by default.

An exception requires a documented invariant proving the producer/output is already bounded for the lifetime of the queue, plus evidence that memory cannot grow without limit under failure or downstream slowdown.

## Retry interaction

- Retries consume the same bounded capacity model as first attempts.
- Do not create retry storms with an independent unbounded retry task/queue.
- Apply bounded attempts, backoff/jitter where appropriate, and an end-to-end deadline/budget.
- Capacity failures should be observable and classified separately from invariant bugs.

## Overload behavior

Tests SHOULD cover saturation behavior for critical services:

- producers block/reject as designed;
- memory remains bounded;
- shutdown does not deadlock on a full channel;
- timeouts/cancellation release permits/resources;
- dropped consumers/producers have defined semantics.

## Forbidden

- task-per-item spawn from unlimited input without admission control.
- unbounded queues justified only by 'tasks are cheap'.
- hidden buffering across multiple layers whose combined bound is unknown.
- semaphore permits or queue slots that can leak on error/cancellation.