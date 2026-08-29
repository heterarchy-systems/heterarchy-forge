# Rust xtask Harness

Cargo-native mechanical verification harness for pure Rust projects.

`xtask` does not replace methodology. `normal_dev_rules + type_dev_rules` define the baseline policy, `async_dev_rules` adds concurrency policy, and repository-local `PROJECT_PROFILE.md` defines concrete project authority. `xtask` verifies the repeatable machine-checkable portion.

## Canonical shape

```text
harness/
├── README.md
├── Cargo.workspace.example.toml.md
├── rust-toolchain.toml.example.md
├── cargo-config.toml.example.md
├── deny.toml.example.md
└── xtask/
    ├── Cargo.toml.md
    └── src/main.rs.md
```

No separate Makefile layer is canonical. Use `cargo xtask ...`; polyglot root runners may delegate to it.

## Apply

1. Adapt the workspace Cargo template.
2. Declare repository toolchain policy.
3. Configure the `cargo xtask` alias.
4. Create project-owned `deny.toml` when dependency gating is required.
5. Add `xtask/` as a workspace member.
6. Materialize `PROJECT_PROFILE.md`, `rules/{normal_dev_rules,type_dev_rules,async_dev_rules}`, and `skills/rust-engineering/SKILL.md`.
7. Add repository-specific feature/API/unsafe/concurrency/performance gates without weakening shared fail-closed behavior.

## Canonical commands

```text
cargo xtask rules
cargo xtask fmt
cargo xtask check
cargo xtask test
cargo xtask ci
cargo xtask deps
cargo xtask doctor
cargo xtask extended
cargo xtask perf
```

### Mandatory baseline

- `rules`: verifies project profile, normal rules, type rules, async rule assets, canonical skill and Cargo workspace baseline.
- `fmt`: formatting gate.
- `check`: workspace check + reviewed Clippy gate.
- `test`: workspace test gate.
- `ci`: `rules → fmt → check → test`.

Async rules are physically verified as harness assets even for synchronous projects so materialized bundles do not silently lose the optional rule family; `PROJECT_PROFILE.md` determines runtime applicability.

### Deeper gates

- `deps`: project-owned `deny.toml` + `cargo deny check`; missing required tool/config is failure/unverified, never fake PASS.
- `doctor`: diagnoses toolchain/harness/deeper-tool availability; it is not CI PASS.
- `extended`: baseline CI + dependency + documentation verification; Miri/fuzz/Loom/Shuttle/feature/API matrices are project-local extensions.
- `perf`: measurement entrypoint; release performance PASS requires project-owned reviewed budgets/evidence.

## Design rules

- Cargo/rustc are compile/lint authority.
- Parse Cargo/TOML semantically where possible; avoid brittle string matching.
- Canonical docs and actual xtask commands/files must stay aligned.
- Optional/deeper tooling missing is not reported as ordinary PASS.
- Feature policy and public API/SemVer verification remain project-owned where one universal check would be incorrect.
- The shared harness verifies type-policy files exist; the compiler/Clippy/tests/Miri/API tooling provide semantic evidence rather than a brittle custom source-code AST law.
