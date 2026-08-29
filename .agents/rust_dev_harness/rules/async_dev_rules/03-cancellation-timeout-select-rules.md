# 03 — Cancellation, Timeout, and Select Rules

## Required

Async cancellation is part of API and lifecycle design.

- Assume an async operation may stop after any `.await` if its future is dropped/cancelled.
- Any future used under `select!`, timeout, abort, race, or parent cancellation MUST be reviewed for cancellation safety.
- APIs SHOULD document whether an operation is cancellation-safe, safe only at defined checkpoints, or not cancellation-safe when callers can reasonably race/cancel it.
- Do not lose caller-visible data, queue position, protocol state, partial writes, or invariants merely because a competing branch completed first.
- Resource cleanup must remain correct when cancellation occurs between awaits.
- Long-running cooperative tasks SHOULD expose explicit cancellation checkpoints rather than relying only on abrupt abort.

## Timeout policy

- A timeout is a cancellation policy, not just a timer value.
- Define what is cancelled at timeout: one attempt, one request, one child task group, or the whole operation.
- Define whether partial side effects may already have happened and how the caller discovers/reconciles them.
- Avoid stacking independent timeouts at multiple layers without a clear end-to-end budget/deadline policy.
- Prefer propagating an absolute/reviewed deadline or remaining budget where multiple layers share one latency contract.

## `select!` / race

Use `select!` as an orchestration primitive, not ordinary business control flow.

Appropriate uses include:

- shutdown vs work
- I/O vs timeout/deadline
- multiple event sources
- bounded races where losing branches are safe to cancel

Before adding a branch, review:

- cancellation safety of every losing future;
- branch fairness/priority assumptions;
- whether a branch can starve another;
- ownership of values/futures across loop iterations;
- whether a loop recreates or accidentally drops progress every iteration.

If biased/priority selection is used, the priority order becomes a correctness/performance contract and must be tested.

## Cooperative cancellation

For component/service lifetime, prefer an explicit cancellation signal/token or equivalent mechanism that lets children:

1. observe shutdown,
2. stop accepting new work,
3. finish/rollback/abandon work according to policy,
4. release resources,
5. return to the owner which awaits completion.

Abrupt task abort is appropriate only when cleanup through destructors is sufficient and cancellation safety has been reviewed.

## Forbidden

- assuming dropping a join handle cancels a task.
- using timeout/select around a non-cancellation-safe operation without a recovery/restart contract.
- retrying after timeout when the previous side effect may still be in flight without idempotency/reconciliation.
- treating cancellation as an unexpected panic-level error by default.