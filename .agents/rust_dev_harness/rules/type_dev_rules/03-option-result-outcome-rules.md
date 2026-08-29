# 03 — Option, Result, and Outcome Rules

## Semantic distinction

- `Option<T>` means a value may be absent and absence is part of the normal contract.
- `Result<T, E>` means an operation may fail with a modeled error.
- Use a dedicated enum when the domain has more than success/absence/failure and those states carry distinct meaning.

Do not use `Option` to hide an error or `Result` merely to encode an expected branch that deserves a domain enum.

## Nested outcomes

`Result<Option<T>, E>` and `Option<Result<T, E>>` are valid only when both dimensions are independently meaningful. If callers repeatedly misread the nesting, create a named outcome enum.

Avoid `Option<bool>` unless the contract genuinely has three states (`true`, `false`, `unknown/absent`). Prefer a named enum when the third state has domain meaning.

## Error preservation

Do not collapse structured failure into `None`, `false`, empty collections, sentinel integers, or log-only behavior.

Use the normal error/panic rules for error taxonomy and reporting. This rule only defines the type-level distinction between absence and failure.

## Unwrap/expect

`unwrap`/`expect` are not validation mechanisms. They are acceptable only where impossibility is locally established or in tests/examples/tooling where panic is the intended contract. Production fallible paths propagate or handle `Result`/`Option` deliberately.

## Custom result-like types

If a custom outcome can be accidentally ignored and ignoring it is usually a bug, consider `#[must_use]` and clear API naming.

## Partial data

Do not use `Option` fields as a generic "not initialized yet" escape hatch inside a type that is supposed to be valid. Prefer staged construction, separate state variants, or a builder where incomplete state is intentionally scoped.

## API compatibility

Changing `T` to `Option<T>`, changing error type `E`, or altering public outcome variants is an API contract change and is reviewed under public API evolution rules.
