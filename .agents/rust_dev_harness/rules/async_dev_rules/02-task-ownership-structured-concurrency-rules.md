# 02 — Task Ownership and Structured Concurrency Rules

## Required

Every spawned task has an explicit owner and lifecycle.

- Prefer lexical/future composition when concurrency does not require independent spawned tasks.
- When spawning is necessary, retain a join/supervision handle or register the task in an owning task set/tracker/supervisor.
- Detached/fire-and-forget tasks are forbidden by default.
- A task may outlive the function that created it only when a longer-lived component explicitly represents and owns that temporal scope.
- Parent/component shutdown must account for all owned child tasks.
- Child task errors and panics must be observed by the owner; dropping a join handle is not error handling.
- Task creation from unbounded input requires a concurrency budget and backpressure rule.

## Structured concurrency discipline

Model task relationships as a tree where practical:

```text
component / parent
├── child task A
├── child task B
└── child task C
```

- Children SHOULD finish before the owning parent/component declares shutdown complete.
- Parent cancellation/error SHOULD propagate a stop request to children and wait for their termination according to the shutdown contract.
- Child results/errors flow back to an owner/supervisor rather than disappearing into logs.
- Unstructured concurrency is allowed only at intentionally designed long-lived boundaries such as top-level service supervisors, and those boundaries must still own shutdown/error policy.

## Tokio when selected

Accepted ownership patterns include, depending on scope:

- awaited `JoinHandle`
- `JoinSet` for a dynamically sized group whose tasks share a lifecycle
- a task tracker/supervisor plus cooperative cancellation token for component/service lifetime

Important semantics:

- dropping a Tokio `JoinHandle` detaches the task; it does not cancel it;
- dropping a `JoinSet` aborts tasks owned by the set;
- abort requests still require joining/waiting when the caller needs proof that cancellation completed.

## Fire-and-forget exception

A detached task requires all of the following:

- explicit code comment/design justification;
- bounded resource usage;
- no required result/error propagation to the caller;
- independently owned shutdown/lifecycle;
- operational visibility for failures;
- proof that component/process teardown cannot leak a required effect.

## Forbidden

- raw `spawn` with the handle immediately discarded in ordinary application code.
- using task detachment as a shortcut around lifetime/ownership design.
- declaring graceful shutdown complete while owned child tasks are still running without an explicit handoff.
- assuming a runtime automatically propagates parent cancellation to spawned children.