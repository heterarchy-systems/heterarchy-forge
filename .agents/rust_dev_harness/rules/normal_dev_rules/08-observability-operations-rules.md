# 08 — Observability and Operations Rules

## Required

- Diagnostics are observational; they do not become hidden policy authority or a substitute for explicit state.
- Prefer structured fields for operation/task identity, decision/event kind, revision, duration, retry count, queue depth, saturation, error category, and runtime/resource state when useful.
- Do not log secrets, provider tokens, raw credentials, private keys, unnecessary payload/source content, or irrelevant absolute paths.
- Keep high-cardinality values out of metrics labels unless explicitly reviewed.
- Preserve causality so requests/jobs/tasks can be connected to the effects they caused without relying on thread identity alone.
- Health/readiness/liveness surfaces belong to runtime/integration authority and reflect real conditions rather than static configuration.
- Logging/tracing failures must not change domain decisions unless telemetry is explicitly part of the product contract.

## Typed diagnostics

Prefer stable typed error/status/operation categories internally, then serialize them deliberately for logs/metrics/traces. Do not make arbitrary diagnostic strings the only machine-readable representation of operational state.

Public diagnostic/error types follow the Rust type/public API rules when consumers depend on them.

## Async / concurrency observability

When async/concurrent systems are material, observe signals relevant to reliability:

- task lifecycle and owned component/run identity;
- queue/channel depth and saturation;
- semaphore/connection/pool utilization;
- retry and timeout rate;
- cancellation/shutdown progress and latency;
- long poll / suspected blocking / scheduler starvation where diagnosable;
- lock/contention hotspots;
- blocking/CPU-pool usage and oversubscription.

Prefer structured tracing/spans over ad-hoc string logs where causal async context matters.

## Failure visibility

- Child task/thread errors and panics reach an owner/supervisor or explicit error sink; silent detached failure is forbidden by default.
- Repeated recoverable errors may be rate-limited/aggregated while preserving counts and diagnostic context.
- Expected cancellation/client disconnect is not automatically logged at the same severity as invariant violations.

## Verification

- Review/redaction-test new diagnostic paths that can contain sensitive input.
- Verify structured error/status fields used by operators or automation.
- For async systems, verify shutdown/cancellation does not leave misleading healthy state or invisible long-lived tasks.
