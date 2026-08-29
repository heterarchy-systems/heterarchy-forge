# 02 — Workspace, Toolchain, and Crate Rules

## Required

- Use an in-repository Cargo workspace when production Rust spans multiple crates or clearly separated authorities.
- Use Rust Edition 2024 for new/current code unless a documented compatibility requirement prevents it.
- Virtual workspaces explicitly use `resolver = "3"`; Edition 2024 projects must preserve Rust-version-aware resolver behavior.
- Declare a repository-owned toolchain policy. Do not let an accidental developer-local compiler define the build.
- If the project supports an MSRV, declare `rust-version` consistently and verify it in CI. If it intentionally tracks current stable only, record that policy instead of inventing an MSRV.
- Put shared package metadata/dependencies/lints in workspace tables where reuse is real; avoid workspace inheritance that obscures crate-specific authority.
- Put shared lint policy in `[workspace.lints]`; member crates opt in with `[lints] workspace = true`.
- Default to `unsafe_code = "forbid"`.
- Use strict Clippy intentionally. Do not enable the entire `restriction` group mechanically; enable reviewed lints with known rationale.
- Add dependencies only for a concrete boundary/capability and enable the smallest required feature set.
- Keep `Cargo.lock` committed for applications/binaries/services. Libraries follow the repository release policy, but CI must still verify reproducible dependency resolution and supported compiler policy.

## Toolchain policy

Repository-local policy SHOULD use `rust-toolchain.toml` when exact/reviewed toolchain pinning is required.

A toolchain update is a reviewed dependency/tooling change, not an invisible workstation change.

## Feature policy

Every crate/workspace must choose one explicit strategy:

1. **Composable features** — verify the supported all-feature build/test surface.
2. **Mutually exclusive or constrained features** — define an explicit feature matrix in the project profile and verify each supported combination.

`--all-features` is not a substitute for a real matrix when features cannot validly coexist.

## Crate boundaries

Prefer crates that represent real ownership/compile/dependency boundaries. Do not split crates only to imitate architecture diagrams; do not keep unrelated high-churn domains in one crate when compile time, dependency isolation, or authority would materially improve by separation.

Typical direction:

```text
crates/
├── <DOMAIN_OR_CORE_CRATE>/
├── <APPLICATION_OR_RUNTIME_CRATE>/
└── <OPTIONAL_ADAPTER_OR_BINARY_CRATE>/
```

## Dependency and supply-chain review

- Review new direct dependencies, features, build scripts, proc macros, native/sys crates, and git dependencies proportionally to risk.
- CI SHOULD include advisory/license/source/ban checks when the repository consumes third-party crates in production.
- Do not treat a committed lockfile as a security audit.
- Prefer crates with maintained provenance, narrowly enabled features, and an understandable transitive dependency impact.

## Mechanical verification

Canonical repository commands should expose stable entry points for:

```text
cargo xtask rules
cargo xtask fmt
cargo xtask check
cargo xtask test
cargo xtask ci
cargo xtask perf
cargo xtask extended
cargo xtask doctor
cargo xtask deps
```

The executable harness and documentation MUST agree. A documented command that is not implemented is a harness defect, not an optional PASS.

Verification SHOULD use Cargo/rustc metadata semantically where possible rather than brittle substring checks of `Cargo.toml`.