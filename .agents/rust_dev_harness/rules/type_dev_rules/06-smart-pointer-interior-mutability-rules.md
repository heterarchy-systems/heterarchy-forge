# 06 — Smart Pointer and Interior Mutability Rules

## Choose the ownership mechanism deliberately

- `Box<T>`: unique ownership/indirection, recursive size breaking, trait-object ownership where needed.
- `Rc<T>`: shared ownership inside one thread.
- `Arc<T>`: shared ownership that may cross threads; it does **not** make the inner value safely mutable by itself.
- `Cell<T>` / `RefCell<T>`: single-thread interior mutability when mutation through shared ownership is part of the design.
- `Mutex<T>` / `RwLock<T>`: synchronized mutable state when shared concurrent mutation is truly required.

Do not default to `Arc<Mutex<T>>` just because it makes ownership or runtime bounds easier to satisfy.

## Single owner first

Prefer one clear owner and explicit borrowing/message passing over shared mutable ownership when the domain naturally has one authority. Shared ownership is a semantic choice with lifecycle, contention and debugging cost.

## Interior mutability

Use interior mutability only when the public semantics require mutation behind shared references or shared ownership.

`RefCell` moves borrow checking to runtime and can panic on violation; keep its scope local and ensure the invariant is easy to reason about.

## Cycles

`Rc`/`Arc` strong-reference cycles leak. Use `Weak` for non-owning/back-reference edges and make cycle-breaking/ownership direction explicit.

## Locks

The type choice does not determine async correctness. Lock duration, lock ordering, `.await` interaction, poisoning/error policy and contention are governed by async/concurrency rules when applicable.

Do not expose lock guards as stable public API unless guard lifetime/locking semantics are intentionally part of the contract.

## Atomics

Use atomics for a concrete lock-free/synchronization need with a documented memory-ordering invariant. Do not replace a clear lock with atomics merely for perceived performance.

Unsafe or nontrivial atomic protocols require concurrency-focused verification proportional to risk.

## `Deref`

Implement `Deref`/`DerefMut` only for genuine smart-pointer/reference-like types. Do not use them as general implicit-conversion mechanisms for domain wrappers.

## Public representation

Avoid leaking `Arc`, `Rc`, `Mutex`, `RwLock`, `RefCell`, or implementation-specific pointer wrappers through public domain APIs unless shared ownership/synchronization is itself part of the contract.
