# Heterarchy Forge Rust Engineering Harness

This directory is the repository-local materialization of the active Alexandria pure Rust harness:

```text
Jobs/Harness/Engineering Harness/02 Rust/rust_dev_harness/
```

Applied composition:

```text
all Rust work       -> rules/normal_dev_rules
async/concurrency   -> rules/normal_dev_rules + rules/async_dev_rules
methodology         -> skills/rust-engineering/SKILL.md
project authority   -> PROJECT_PROFILE.md
mechanical gates    -> repository root xtask/
```

`PROJECT_PROFILE.template.md` and `harness/` are canonical source templates. `PROJECT_PROFILE.md`, root Cargo/rust-toolchain/deny configuration, root xtask, and live source/tests are the concrete project authority.

`HARNESS_MANIFEST.tsv` records the materialized body SHA-256 and relative path for the 40 shared harness source files. `cargo xtask rules` recomputes each body hash. Retired `profiles/native-compute` material is not active.
