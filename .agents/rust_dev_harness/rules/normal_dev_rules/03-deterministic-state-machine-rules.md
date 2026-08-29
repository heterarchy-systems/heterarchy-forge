# 03 — Deterministic State-Machine Rules

## Required

- Transition/state-machine functions are pure calculations over explicit typed input whenever the domain permits it.
- No implicit clock reads, random generation, environment reads, filesystem/network reads, process identity reads, runtime handles, or persistence access inside deterministic transitions.
- Time, randomness, revisions, selected policies, and runtime observations that influence a decision are resolved outside and passed as typed input.
- Preserve stable ordering for any observable traversal, scheduling, planning, hashing, serialization, or decision output.
- Validate duplicates, unknown references, self-reference, cycles, capacity bounds, revision/staleness, and transition legality in one authoritative place for the policy.
- Return revisions, events, decisions, commands-to-effects, or plans as typed data; the effect/application layer performs external writes.
- Re-running the same algorithm/version with the same explicit inputs must produce the same observable deterministic result.

State representation itself follows `../type_dev_rules/02-enum-state-sum-type-rules.md`; this rule owns transition determinism, not the entire type policy.

## Concurrency interaction

- Do not introduce async locks, channels, task spawning, clocks, or executor state into a deterministic transition merely to parallelize orchestration.
- CPU parallelization must preserve contractual observable ordering/results unless approximation or nondeterminism is explicitly part of the contract.
- Parallel execution has an explicit worker budget and measured benefit.
- Concurrent callers do not justify shared mutable global state inside the transition engine.

## Authority

Compatibility oracles may compare an older implementation and Rust during a bounded migration, but final production authority for a migrated policy must be singular.

## Forbidden

- hidden global mutable state inside core policy;
- nondeterministic iteration order in observable output;
- adapter/runtime shortcuts that bypass core validation;
- permanent dual authority;
- sleeps, retry loops, network calls, or persistence side effects inside a pure transition.
