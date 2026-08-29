# 04 — Trait, Generic, and Bound Rules

## Traits model capabilities

Create a trait when it expresses a meaningful behavior/capability that multiple implementations, callers, mocks/adapters, or extension points need. Prefer inherent methods when there is no real polymorphic boundary.

Do not create one-method traits merely to make every concrete type "abstract".

## Bounds

- Put trait bounds as close as practical to the operation that requires them.
- Do not add `Clone`, `Send`, `Sync`, `'static`, `Default`, `Debug`, serialization, or ordering bounds to a whole type merely because one method needs them.
- Avoid duplicating derived trait bounds on data-structure type definitions when implementations can constrain only the relevant impl/method.
- Every additional public generic bound is part of API compatibility.

## Associated types vs generic parameters

Use an associated type when an implementation has one natural type choice for that relationship. Use a generic parameter when the caller/operation genuinely selects among multiple types.

Choose for semantic clarity rather than minimizing characters.

## Static vs dynamic polymorphism

- Generics / `impl Trait` provide static dispatch and are good when concrete type identity does not need to be erased.
- `dyn Trait` is appropriate for heterogeneous/runtime-selected implementations or explicit type erasure.
- Do not choose generic monomorphization blindly for code-size/build-time-sensitive boundaries, or `dyn Trait` blindly to avoid generics.
- Public trait-object use requires dyn compatibility and object-lifetime review.

## Sealed traits

If downstream crates must not implement a trait because future methods/invariants need to remain under crate control, use a sealed-trait pattern and document that intent.

Do not seal an ecosystem extension trait when third-party implementation is a deliberate capability.

## Supertraits and marker traits

Keep supertraits minimal. A marker trait should represent a real compile-time property/capability, not act as a naming alias for an arbitrary collection of bounds.

## Common traits

Types should implement common standard traits (`Debug`, equality/order/hash, conversions, iterator traits, etc.) when semantics are correct and useful. Do not derive traits whose semantics would be misleading or freeze an unwanted API contract.

## Blanket implementations

Blanket impls and broad generic impls consume coherence space and can constrain future API evolution. Review overlap/orphan/coherence implications before publishing them in stable libraries.

## Async boundary

The type policy does not force `Send + Sync + 'static` globally. Runtime/task placement rules decide when those bounds are actually required.
