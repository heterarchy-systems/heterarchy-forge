# 02 — Enum, State, and Sum-Type Rules

## Finite alternatives

Use `enum` when a value is one of a finite set of semantically distinct alternatives, especially when each alternative carries different data.

Prefer:

```rust
enum JobState {
    Queued { queued_at: InstantId },
    Running { worker: WorkerId },
    Failed { error: FailureKind },
    Completed { output: OutputId },
}
```

over one struct containing a status string plus many unrelated `Option<T>` fields.

## Exhaustiveness

- Internal closed-state machines should normally use exhaustive `match` so new variants force compile-time review.
- Avoid `_` wildcard arms when newly added variants must trigger an audit.
- Use wildcard matching only when forward-compatible behavior is intentionally correct for the caller.

## Public evolution

For public library APIs, downstream exhaustive matching can freeze enum evolution. Use `#[non_exhaustive]` when adding variants in compatible releases is part of the intended API evolution model.

Do not add `#[non_exhaustive]` automatically to every enum; closed public enums can be a deliberate contract.

## State payloads

Put data only on the state that owns it. Avoid values that are meaningless in some variants and require runtime comments such as "only valid when status == X".

## Typestate

Typestate/generic-state APIs are appropriate when compile-time transition legality provides substantial value, such as builders/protocols/resources with a small stable state graph.

Do not turn every application workflow into a large generic typestate graph. Excessive typestate can amplify generic complexity, compile time, diagnostics and public API surface. Runtime enums remain appropriate when states are dynamic, persisted, data-driven, extensible or cross process boundaries.

## Flags

When flags are combinable rather than mutually exclusive, do not encode them as a mutually-exclusive enum. Use an explicit flags/set representation such as a reviewed bitflags type when appropriate.

## Stringly state

Do not use raw status strings as stable internal domain state when the set is known. Parse external strings at the boundary into a typed enum.

## Serialization

Serialized enum representation is a compatibility contract when persisted or sent over a wire. Keep wire names/tags separate from internal variant naming when independent evolution matters.
