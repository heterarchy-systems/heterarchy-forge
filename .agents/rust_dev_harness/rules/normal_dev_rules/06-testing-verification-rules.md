# 06 — Testing and Verification Rules

## Required layers

Choose layers based on risk/contract; one passing unit test is not broad correctness.

1. **Unit tests** — pure functions, invariants, edge cases, error paths.
2. **Integration tests** — crate/application boundaries and real infrastructure adapters where relevant.
3. **Golden / compatibility tests** — observable compatibility or bounded migration parity.
4. **Property / generative tests** — parsers, codecs, state transitions, ordering, hashing, numerical invariants, serialization/conversion round-trips.
5. **Corpus / fixture tests** — real-world input grammars/protocols/documents/formats.
6. **Feature-matrix verification** — every supported combination or explicit project matrix.
7. **Concurrency/async verification** — cancellation, shutdown, ownership, backpressure, virtual time and interleavings when applicable.
8. **Unsafe/FFI verification** — real boundary tests and stronger soundness checks where safe Rust guarantees do not cover the path.
9. **Public API verification** — consumer/compatibility evidence where published type identity, features, MSRV or SemVer matter.
10. **Runtime/release provenance** — where artifact identity matters, prove the executed runtime loaded the intended build.

## CI tiers

### Fast inner loop

- rust-analyzer/compiler feedback
- focused `cargo check`
- focused tests

### Mandatory CI

- formatting
- workspace check
- reviewed Clippy policy with warnings denied as configured
- supported primary tests
- dependency/source/advisory gates required by profile
- supported feature verification

### Extended / high-risk

Use when applicable:

- broader feature matrix
- Miri for unsafe/aliasing/validity assumptions
- fuzzing + regression corpus
- Loom/Shuttle for concurrency scheduling/synchronization
- downstream/SemVer compatibility checks
- expensive integration/fault/performance suites

A missing optional/deeper tool makes that gate **unverified**, not PASS.

## Quality

- deterministic fixtures/stable seeds where determinism is expected;
- avoid arbitrary wall-clock sleeps; use observable state or controlled time;
- test public ordering/hash/identity/round-trip exactly when contractual;
- declare tolerance/source/version assumptions for approximate algorithms;
- cover failure/cancellation/shutdown paths;
- execute commands before reporting PASS.

## Feature / compatibility policy

- Use all-features only when all features are valid together.
- Verify an explicit matrix for mutually exclusive features.
- Public libraries verify documented MSRV and public API compatibility according to repository release policy.
- Type-level unsafe/thread-safety claims follow the dedicated type rules and stronger evidence requirements.

## Migration / cutover

Compatibility oracles are temporary evidence. After authority cutover, retire the old production implementation unless a product requirement explicitly retains it.

## Completion

Report exactly what ran, passed, failed, and remains unverified.
