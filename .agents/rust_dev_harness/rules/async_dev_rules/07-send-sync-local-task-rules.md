# 07 — Send, Sync, and Local Task Rules

This rule owns **runtime/task placement**. The sibling Rust type rule for Send/Sync owns the semantic and soundness meaning of the `Send` and `Sync` auto traits.

## Spawn contracts

On multi-thread runtimes, spawned tasks commonly require `Send + 'static` because the executor may move futures between worker threads.

- Treat compile-time failure as design feedback about ownership/runtime placement.
- Move owned handles/data into long-lived tasks deliberately.
- Do not leak memory or promote state to process-global ownership merely to satisfy `'static`.
- Do not change a type's thread-safety contract merely because the default spawn API requires `Send`.

## Local tasks

If work is intentionally thread-local or contains valid non-`Send` values:

- use the runtime's local-task/current-thread facility when locality is part of the design;
- keep the local executor/scope owner explicit;
- document thread affinity for UI/FFI/native/runtime handles;
- do not use local spawning to hide blocking work, lock misuse, or unsound lifetime handling.

When Tokio is selected, `LocalSet` / `spawn_local` are examples, not universal requirements.

## Shared ownership

- `Arc<T>` supplies thread-safe reference counting, not inner synchronization.
- `Arc<Mutex<T>>` is not a default async architecture; apply the shared-state rule and type-level smart-pointer rule.
- Prefer immutable shared state, one-owner state machines, or owned message passing when they simplify authority.
- Clone cheap handles deliberately; do not clone large payloads solely to satisfy task ownership.

## Scoped synchronous parallelism

When child threads must borrow parent data and complete before a lexical scope ends, scoped threads can preserve borrowing instead of forcing unnecessary `'static` ownership.

## Verification

Runtime placement tests cover local vs multi-thread executor behavior where it matters. Unsafe/low-level thread-safety claims are verified under the type rule with Miri/Loom/stress/fault evidence as appropriate.

## Forbidden

- changing correct local semantics into global synchronization solely to use a multi-thread spawn API;
- leaks/process-global singletons as lifetime workarounds;
- assuming a mutex automatically makes an underlying external/FFI resource thread-safe;
- duplicating `unsafe impl Send/Sync` policy here instead of the type-safety rule.
