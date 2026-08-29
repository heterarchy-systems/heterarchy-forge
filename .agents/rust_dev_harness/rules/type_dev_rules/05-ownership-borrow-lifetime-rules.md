# 05 — Ownership, Borrowing, and Lifetime Rules

## Ownership is semantic

Choose owned values, shared borrows and mutable borrows according to who must retain or mutate the value, not according to what makes the borrow checker quietest.

- `&T` when a caller only needs read access for the call/lifetime.
- `&mut T` when exclusive mutation is part of the operation.
- owned `T` when the callee must retain, transfer, store, move across an ownership boundary, or independently control lifetime.

Do not clone values merely to bypass an ownership-design problem. A clone is acceptable when duplication is semantically correct and its cost/lifetime is understood.

## Inputs and outputs

Use borrowed input views (`&str`, `&[T]`, references to domain types) when the callee does not retain ownership. Return owned values when returning a borrow would unnecessarily expose internal storage/lifetime or lock ownership.

Do not return references tied to lock guards or internal containers when that leaks synchronization/storage representation into the public API.

## Lifetimes

Lifetimes encode real relationships between borrowed values. Prefer elision where the relationship is obvious; explicit named lifetimes are for relationships the compiler/API reader actually needs to understand.

Do not add `'static` as a generic fix. `'static` means the value contains no shorter-lived borrowed references (or a reference truly lasts for the program); it does not mean "keep this object alive forever".

If a spawned task requires `'static`, restructure ownership/move data deliberately rather than converting everything into process-global or leaked state.

## Borrow scope

Keep borrows and lock guards as short as practical. Compute owned/intermediate values before entering effectful or async boundaries when that simplifies lifetime coupling.

## `Cow`

Use `Cow` when an API genuinely benefits from a common borrowed-or-owned representation and avoids meaningful copying. Do not introduce `Cow` merely as an abstraction flourish; a direct borrowed or owned type is usually clearer.

## Self-referential and pinned data

Self-referential structures are high-complexity. Prefer owned data, stable indices/handles, arenas or redesigned ownership before introducing self-references.

`Pin` is used only when immovability is part of the safety/semantic contract. It is not a general-purpose "make this reference safe" wrapper.

## Async/thread boundary

When ownership crosses tasks or threads, also read the `Send`/`Sync` type rule and async runtime rules. Do not make a local ownership model globally shared solely because a multi-thread executor is the current implementation choice.
