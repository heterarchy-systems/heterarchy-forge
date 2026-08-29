# 07 — Send, Sync, and Thread-Safety Type Rules

## Auto traits are semantic promises

`Send` and `Sync` describe whether values/references may safely cross or be shared across thread boundaries. Treat them as part of the type's semantic contract, not as compiler obstacles to remove.

- `Send`: ownership may safely move to another thread.
- `Sync`: shared references `&T` may safely be used from multiple threads.

A type does not need to be `Send`/`Sync` merely because the application currently uses a multi-thread runtime.

## Preserve intentional locality

`Rc`, `Cell`, `RefCell`, thread-affine handles, GUI/runtime handles and other local-only values may correctly be non-`Send`/non-`Sync`.

Do not wrap a local design in `Arc<Mutex<_>>`, copy data into globals, or redesign ownership solely to satisfy a spawn API. If locality is semantically intended, use a local executor/task model or an explicit owner task/thread when appropriate.

## `unsafe impl Send/Sync`

Manual `unsafe impl Send` or `unsafe impl Sync` is a high-risk safety claim.

It requires:

- the exact invariant that makes cross-thread movement/sharing safe;
- review of all interior/raw-pointer/FFI state reachable through the type;
- proof that safe public methods cannot violate that invariant;
- review of destructor/thread-affinity behavior;
- stronger verification proportional to risk (Miri, Loom/stress/fault tests, real FFI/runtime evidence as applicable).

Never add an unsafe auto-trait impl merely because a dependency/runtime requires the bound.

## `'static` is separate

`'static`, `Send`, and `Sync` are independent concepts. Do not conflate them.

A `'static` bound usually means the value contains no borrowed data shorter than the required lifetime; it does not make the value thread-safe. A `Send` type does not automatically satisfy `'static`.

## `PhantomData`

`PhantomData` affects variance, drop checking and auto-trait/ownership interpretation. Use it to model real logical ownership/lifetime relationships. Do not add/remove phantom markers merely to manipulate `Send`/`Sync` without understanding the safety consequence.

## Raw pointers

Raw pointers do not by themselves express ownership, aliasing, validity, lifetime, or synchronization. A wrapper around raw pointers must state and preserve those invariants explicitly.

## Public API compatibility

Whether a public type is `Send`, `Sync`, `Unpin` or otherwise auto-trait-compatible can be observable to downstream code. Changes in auto-trait behavior are reviewed as API compatibility changes for stable/public libraries.

## Async boundary

This file owns **type-level thread-safety promises**. The sibling async rule `07-send-sync-local-task-rules.md` owns executor/task placement, local-task usage and runtime behavior.
