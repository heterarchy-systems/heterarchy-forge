# 10 — FORGE Persistence SQL Rules

This is a **Heterarchy Forge repository-local rule**. It is not part of the reusable shared Rust harness and must not be added to `HARNESS_MANIFEST.tsv`.

Apply this rule whenever a change touches `forge-persistence`, Workspace/Global Registry SQLite schemas, migrations, SQL queries, row codecs, persistence validation, recovery journals, or persistence performance.

## 1. Persistence authority

FORGE keeps `rusqlite` and direct SQLite control as the persistence authority.

Do not introduce or migrate `forge-persistence` to an ORM/query framework merely to hide SQL. In particular, do not add Diesel, Diesel Async, SeaORM, SQLx, a custom ORM, or a custom query DSL without an explicit repository-level architecture decision that replaces this rule and its harness.

The current persistence contract intentionally uses SQLite semantics directly:

- `CHECK` constraints;
- foreign keys;
- indexes and index ordering;
- `PRAGMA` inspection and integrity checks;
- `sqlite_schema` validation;
- explicit transactions and `TransactionBehavior::Immediate` where justified;
- schema-versioned migrations;
- compare-and-set/revision checks;
- fail-closed corruption detection.

An abstraction must not weaken, conceal, or duplicate these authorities.

## 2. One SQL authority per durable contract

The same schema/query contract must not have multiple independently edited SQL definitions.

Bad:

```text
EXPECTED_*_TABLE_SQL
        +
create_schema() copy of the same CREATE TABLE
        +
migration/test copy of the same definition
```

Preferred:

```text
Canonical SQL definition
        ├─ schema creation
        └─ schema validation expectation
```

Long DDL may live in a repository `.sql` artifact and be loaded with `include_str!`, or in one canonical Rust `const &str` when that is clearer. The required property is **single authority**, not a mandatory file extension.

Schema validation is evidence, not a second schema authority.

## 3. SQL placement

### Schema / DDL

Treat `CREATE TABLE`, `CREATE INDEX`, `CHECK`, foreign-key definitions, and schema-level invariants as first-class persistence artifacts.

Do not duplicate long DDL merely to make tests convenient.

### Migrations

Keep migration decision-making in Rust when it requires:

- old-schema introspection;
- conditional transition logic;
- legacy-row detection;
- fail-closed decisions;
- semantic validation;
- data reconstruction;
- transaction orchestration.

Concrete DDL/DML may be stored separately when that removes duplication without hiding the migration contract.

Never invent or infer durable provenance that cannot be reconstructed from authoritative legacy data.

### Fixed queries

Short, stable `SELECT`/`INSERT`/`UPDATE`/`DELETE` statements may remain named Rust constants. Long or independently reviewed queries may move to `.sql` files.

Do not move every SQL statement to a file mechanically.

### Dynamic queries

Values must use SQLite parameter binding (`params!`, `params_from_iter`, or equivalent typed binding).

Do not interpolate user/domain values into SQL with `format!` or string concatenation.

Dynamic identifier formatting is allowed only when the identifier comes from a closed, code-owned static allowlist/`&'static str` authority and SQLite cannot bind that identifier position.

Do not create a custom SQL builder unless a real query-composition need exists and existing capabilities are insufficient.

## 4. Rust persistence boundaries

### Repository / transaction layer

Owns:

- SQL execution;
- explicit transaction boundaries;
- CAS/revision updates;
- bounded query composition;
- `rusqlite` error propagation/adaptation.

No SQLite transaction may be held across Git, filesystem, child-process, UI, or network waits.

### Codec layer

Owns:

```text
SQLite Row
→ checked persistence representation
→ domain type
```

Keep SQLite column indexes, `rusqlite::Row`, PRAGMA details, and SQL storage encoding out of `forge-domain`.

Prefer explicit typed persistence representations over loose tuples when row shape becomes non-trivial.

### Validation layer

Owns persistence-specific evidence such as:

- schema object identity;
- expected columns;
- index ordering;
- foreign-key targets;
- cross-record persistence invariants;
- immutable attribution/provenance checks;
- corruption detection.

Validation must not silently repair corruption or fabricate missing authority.

## 5. Module decomposition

Do not split a persistence source file because it crossed an arbitrary line count.

Split when independent change reasons/authorities have formed, for example:

```text
workspace_checkpoints.rs
workspace_checkpoints/
├── schema.rs
├── migration.rs
├── repository.rs
├── codec.rs
├── validation.rs
└── tests.rs       # only when the unit-test module itself warrants physical separation
```

Use current Rust module layout (`foo.rs` + `foo/bar.rs`) for intentional new/refactored trees unless an established local convention provides a stronger reason otherwise.

Keep visibility as narrow as possible:

```text
private → pub(super) → pub(crate) → pub
```

Never widen production visibility only for tests.

Package-root `tests/` remains integration/external-contract territory; private persistence invariants stay in the production module tree under `#[cfg(test)]`.

## 6. Migration and provenance safety

Schema-version changes are durable compatibility changes.

For checkpoint/restore and other journals, explicitly verify whether legacy rows contain enough authoritative information to construct new required fields.

Forbidden examples:

- treating checkpoint creator as restore initiator without evidence;
- inventing an approval ID;
- fabricating a recovery owner/lease epoch;
- bumping `user_version` without matching schema semantics;
- silently accepting a legacy row that cannot satisfy the new domain invariant.

When provenance cannot be reconstructed, prefer a documented fail-closed migration/recovery path over false attribution.

Pair invariants such as an owner plus lease epoch should be made unrepresentable in the domain where practical and reinforced by SQLite `CHECK` constraints when persisted.

## 7. Schema and integrity verification

Preserve or strengthen relevant checks such as:

- normalized `sqlite_schema` SQL comparison;
- `PRAGMA table_info`;
- `PRAGMA index_info`;
- `PRAGMA foreign_key_list`;
- `PRAGMA foreign_key_check`;
- `PRAGMA quick_check`;
- expected columns/index order/FK targets.

Do not remove these merely because another abstraction can generate tables.

Fresh-schema creation, previous-version migration, corrupt-schema rejection, reopen/restart durability, and transaction rollback are separate evidence lanes.

## 8. Transaction discipline

Review each write path for:

- shortest practical transaction scope;
- atomic CAS/revision semantics;
- rollback on error;
- no external blocking effect inside the SQLite transaction;
- correct use of deferred/immediate behavior based on contention and correctness needs.

Do not optimize lock duration by weakening atomicity.

## 9. Prepared statements and performance

Do not replace `prepare()` with `prepare_cached()` mechanically.

Use statement caching only when measurement shows repeated prepare overhead matters for a sufficiently long-lived connection and the memory tradeoff is acceptable.

Performance work requires before/after evidence. Prioritize algorithmic/query/index improvements and unnecessary allocation/copy removal before speculative low-level tricks.

## 10. FORGE persistence harness

Repository-local mechanical entrypoint:

```text
cargo xtask persistence
```

`cargo xtask rules` must verify that this rule and the FORGE persistence harness are present and remain repository-local rather than Alexandria-manifested.

The mechanical harness verifies stable facts that are safe to automate, including the selected SQLite driver/dependency boundary. It must not pretend to infer responsibility splits, parameter-binding correctness, DDL duplication, migration truth, or transaction semantics from brittle regex/source scans.

Those semantic requirements are enforced by compiler/Clippy evidence, focused persistence tests, migration/schema tests, and code review.

## 11. Required verification for persistence changes

Run focused evidence first, then canonical repository CI.

Minimum focused gate:

```text
cargo xtask persistence
```

Before completion of a persistence change, cover applicable lanes:

```text
fresh database creation
current schema validation
previous-version migration
legacy-row migration behavior
corrupt schema detection
foreign-key validation
reopen/restart durability
CAS/revision conflict
transaction rollback
checkpoint/restore lifecycle when touched
```

Then run:

```text
cargo xtask ci
```

No unexecuted gate is PASS.

## 12. Explicitly forbidden shortcuts

- ORM adoption as a cosmetic SQL-removal exercise.
- Duplicating canonical DDL into creation/expected/test strings.
- A custom ORM/query DSL without demonstrated need.
- Interpolating runtime values into SQL text.
- Removing SQLite schema/integrity validation to simplify code.
- Guessing missing migration provenance.
- Holding SQLite transactions across external effects.
- Splitting files by line-count policy alone.
- Moving unit tests to root `tests/` and widening visibility to reach internals.
- Claiming performance improvement without measurement.

The goal is not to eliminate SQL. The goal is a **single-authority, explicit, typed, testable SQLite persistence boundary** that remains faithful to FORGE's recovery and durability contracts.
