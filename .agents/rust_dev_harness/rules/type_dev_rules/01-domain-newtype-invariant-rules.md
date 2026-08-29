# 01 — Domain, Newtype, and Invariant Rules

Research baseline: Rust 1.98.0 (2026-08-20) and current Rust API Guidelines type-safety/dependability guidance.

## Core rule

Use the type system to preserve meaning **after a value crosses a validation boundary**. A domain type should make the valid interpretation obvious and make accidental interchange difficult.

## Newtypes

Use a newtype when two values share the same representation but have different meaning or invariants, for example:

- IDs from different namespaces;
- revisions / sequence numbers;
- byte counts vs item counts;
- durations or domain-specific time units;
- money/currency/percentage values;
- bounded capacities, offsets, ports, shard identifiers or policy values.

Do not create a wrapper for every primitive mechanically. A newtype earns its cost when it prevents a real class of mistakes, hides representation, owns validation, or stabilizes a public contract.

## Constructors and representation

- Public construction establishes the type invariant before the value enters trusted core code.
- Keep fields private when callers must not manufacture invalid state directly.
- Prefer a safe checked constructor returning `Result`/`Option` when validation can fail.
- Use an `unsafe` constructor only when the caller genuinely must uphold a safety invariant that cannot be checked; document the exact preconditions.
- `repr(transparent)` / `repr(C)` are ABI/layout commitments and are not added to ordinary domain types for convenience.
- Do not expose transport/storage representation merely because the underlying value is a `String`, integer, UUID-like value, JSON object, or database key.

## Meaningful arguments

Stable APIs should communicate meaning through types rather than unexplained primitives or boolean flag lists.

Prefer a named enum/newtype/options object when a `bool`, raw integer, `Option<T>`, or string token would force callers to remember hidden semantics.

## Validity

Prefer, in order:

```text
static type restriction
→ checked constructor / parser
→ one authoritative runtime validation boundary
```

Do not validate the same invariant independently in multiple layers and allow the rules to drift.

## Trait derivation

Derive/implement common traits when they are semantically correct, not automatically.

- `Debug` should normally exist for diagnosable public/domain values.
- `Eq`/`Ord`/`Hash` require meaningful equality/order/hash semantics.
- `Copy` is for genuinely small value-like types whose implicit duplication matches domain meaning.
- `Default` is only correct when a meaningful valid default exists; it must not manufacture placeholder-invalid domain state.

Do not implement `Deref` merely to make a newtype behave like its inner representation. `Deref` is reserved for genuine smart-pointer/reference-like semantics.

## Boundary rule

Parse/validate raw strings, numbers, bytes, maps or wire values at the edge, then keep the validated type inside the application/domain. Do not repeatedly fall back to the raw representation between core functions.

## Relationship to other rules

- finite alternatives/state payloads → `02-enum-state-sum-type-rules.md`
- absence/fallibility → `03-option-result-outcome-rules.md`
- conversions → `08-conversion-parsing-cast-rules.md`
- public representation evolution → `09-public-api-type-evolution-rules.md`
- safety invariants → `10-unsafe-type-invariant-rules.md`
