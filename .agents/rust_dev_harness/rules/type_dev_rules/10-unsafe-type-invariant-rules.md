# 10 — Unsafe Type Invariant Rules

## Default

Shared Rust policy keeps `unsafe_code = "forbid"` by default. A repository that genuinely needs unsafe code must declare the approved boundary and compensating verification in `PROJECT_PROFILE.md` and local lint configuration.

`unsafe` is a proof obligation, not a performance toggle or a way to bypass borrow/type errors.

## Localize the proof

Keep unsafe operations in the smallest practical module/function and expose a safe abstraction where possible.

For every unsafe boundary document:

- the invariant being relied on;
- who establishes the invariant;
- who must preserve it;
- pointer validity/alignment/lifetime requirements;
- aliasing/mutation rules;
- initialization/layout/thread-safety requirements;
- what safe callers are allowed to do.

Safe public methods must not allow callers to violate the internal safety invariant.

## `unsafe fn` and unsafe constructors

Use `unsafe fn` only when **the caller must uphold a safety precondition that cannot be enforced by the callee**. If the callee can validate or construct the invariant safely, expose a safe checked API instead.

Do not mark an operation unsafe merely because its implementation uses an unsafe block internally.

## Unsafe trait implementations

`unsafe impl` (including `Send`/`Sync` or unsafe traits) asserts that all required safety contracts hold for the type. State the proof explicitly and review reachable interior state, destruction, concurrency, FFI and aliasing behavior.

## High-risk primitives

Raw pointers, `NonNull`, `MaybeUninit`, unions, manual allocation, FFI pointers, `transmute`, unchecked indexing/conversion and manual drop/ownership transfer require precise validity reasoning.

- Never assume zeroed bytes form a valid arbitrary `T`.
- Do not create references before pointer validity/alignment/aliasing/lifetime requirements hold.
- Do not read uninitialized memory.
- Do not construct multiple owners for one allocation accidentally.
- Prefer standard-library safe/checked APIs over custom pointer arithmetic when available.

## Layout / FFI

Ordinary Rust type layout is not a stable ABI promise. Use `repr(C)` / `repr(transparent)` only when the layout contract is required and review niche/enum/padding/alignment implications.

Interop changes also apply the normal FFI boundary rule and, in mixed-language repositories, the dedicated cross-language harness.

## Verification

Unsafe changes require stronger evidence than ordinary safe refactors according to risk:

- compiler + Clippy baseline;
- focused tests and boundary tests;
- Miri for aliasing/validity/UB-sensitive paths where supported;
- fuzz/property/corpus tests for hostile input/conversion paths;
- Loom/stress/fault tests for synchronization protocols;
- real ABI/platform/runtime tests for FFI and layout contracts.

Passing Miri or tests does not prove all unsafe code sound; the written invariant/proof remains required.

## Forbidden

- undocumented unsafe blocks/impls;
- broad crate-wide unsafe allowance when one small module is sufficient;
- unsafe introduced only for an unmeasured optimization;
- safe API that can manufacture invalid internal state;
- permanent suppression of soundness warnings without a reviewed proof.
