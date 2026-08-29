# FORGE Persistence Harness

Repository-local mechanical harness for the `forge-persistence` SQLite/rusqlite boundary.

This asset is **Heterarchy Forge specific**. It is intentionally outside the Alexandria materialization manifest and must not be promoted into the reusable shared Rust harness.

## Entry point

```text
cargo xtask persistence
```

The focused gate performs:

```text
FORGE persistence policy verification
→ cargo check --locked -p forge-persistence --all-targets
→ cargo clippy --locked -p forge-persistence --all-targets -- -D warnings
→ cargo test --locked -p forge-persistence --all-targets
```

`cargo xtask rules` also runs the policy portion, so canonical `cargo xtask ci` cannot silently lose the FORGE-specific persistence contract.

## Mechanically enforced contract

The generic mechanical verifier may safely enforce facts such as:

- `.agents/rust_dev_harness/rules/normal_dev_rules/10-forge-persistence-sql-rules.md` exists and is non-empty;
- this harness asset exists and is non-empty;
- neither local asset is listed in `HARNESS_MANIFEST.tsv`;
- the workspace owns the reviewed `rusqlite` dependency;
- the current `rusqlite` workspace configuration keeps `default-features = false` and the `bundled` feature;
- `forge-persistence` consumes `rusqlite` through workspace dependency inheritance;
- `forge-persistence` does not directly depend on the forbidden ORM/query-framework set defined by the repository-local xtask policy.

## Semantic boundary

Do **not** add brittle source scanning that claims to prove:

- whether DDL has one true authority;
- whether every value is parameter bound;
- whether a module is a god-module;
- whether migration provenance is truthful;
- whether a transaction crosses an external effect;
- whether `prepare_cached()` is justified;
- whether schema/index/FK semantics are correct.

Those requirements belong to the FORGE persistence rule, live types/source, schema/migration tests, Clippy/compiler evidence, and review.

The harness should fail closed for facts it actually knows and remain silent rather than fake-proof semantic architecture.

## Dependency authority

Current repository contract:

```text
database: SQLite
driver: rusqlite
ORM: none
```

Introducing Diesel, Diesel Async, SeaORM, or SQLx directly into `forge-persistence` requires an explicit architecture decision and an intentional update of both the local rule and the xtask harness. It must never happen as an incidental dependency addition.

## CI relationship

`cargo xtask persistence` is the fast focused persistence lane.

`cargo xtask ci` remains the final mandatory baseline and already includes:

```text
rules
fmt
workspace check + Clippy
workspace tests
```

Therefore CI does not need to run the focused persistence compilation/tests a second time. The policy verifier is shared; the focused command exists for persistence development and regression isolation.
