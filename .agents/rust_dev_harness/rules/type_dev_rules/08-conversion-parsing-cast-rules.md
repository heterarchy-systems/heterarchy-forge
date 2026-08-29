# 08 — Conversion, Parsing, and Cast Rules

## Conversion APIs encode meaning

Choose the conversion trait/method according to semantics:

- `From<T>`: infallible, non-lossy conversion that is a natural value transformation.
- `TryFrom<T>`: conversion can fail because of validation/range/representation constraints.
- `AsRef<T>` / `Borrow<T>`: cheap borrowed view; no ownership conversion.
- `FromStr`: canonical parsing from string text.
- explicit named method: lossy, policy-dependent, unit-changing, truncating, saturating, clamping or otherwise non-obvious conversion.

Prefer implementing `From` rather than implementing `Into` directly so the reciprocal `Into` behavior is provided consistently.

## Fallibility

Do not implement `From` for a conversion that can reject input, silently truncate information, change units unexpectedly, or require policy. Use `TryFrom` or an explicit named operation.

## Numeric casts

`as` casts are allowed when the exact truncation/wrapping/sign/precision semantics are intentional and locally obvious. They are not a validation shortcut.

When a numeric conversion can be out of range and failure matters, use checked conversion (`TryFrom`, checked arithmetic, domain constructor) rather than relying on `as`.

Lossy numeric conversion should be explicit in naming or local proof, especially across persisted/wire/domain boundaries.

## Parsing boundary

Parse raw string/wire values at the boundary into validated domain types. Parsing errors remain typed; do not convert invalid input into zero/default/sentinel values.

`serde` deserialization or protocol decoding creates a representation value; it does not automatically establish every domain invariant. Run the authoritative domain conversion/constructor when additional invariants exist.

## Generic conversion parameters

Accept `impl Into<T>` / generic conversion bounds when callers genuinely benefit from multiple equivalent input forms and API ambiguity remains low. Do not use `Into` everywhere by default; a concrete `T`, `&T`, `&str`, `AsRef`, or explicit constructor is often clearer.

## `Deref` is not conversion

Do not implement `Deref` on domain wrappers just to obtain implicit conversion/coercion to the inner representation. `Deref` is for smart-pointer/reference-like semantics.

## Units and identity

Conversions must not erase distinct units/identity domains accidentally. Convert through typed newtypes and explicit unit/namespace transformations.

## Round-trip contracts

If parse/format or encode/decode round-trip is part of a stable contract, test canonical round trips, rejected inputs, boundary ranges and compatibility cases.
