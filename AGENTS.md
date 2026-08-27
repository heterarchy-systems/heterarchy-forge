# Heterarchy Forge Agent Instructions

Heterarchy Forge is a **Rust-only** macOS desktop/runtime project.

## Authority

Read these before changing production code:

1. `.agents/rust_dev_harness/PROJECT_PROFILE.md`
2. `.agents/rust_dev_harness/rules/README.md`
3. `.agents/rust_dev_harness/rules/normal_dev_rules/README.md`
4. `.agents/rust_dev_harness/rules/type_dev_rules/README.md`
5. For async/concurrent work, `.agents/rust_dev_harness/rules/async_dev_rules/README.md`
6. `.agents/rust_dev_harness/skills/rust-engineering/SKILL.md`
7. The normal, type, and async rule files matching the touched boundary
8. Live `Cargo.toml`, `xtask/`, tests, and source code

Repository-local source and tests are the final implementation authority. The harness is a guardrail, not a substitute for inspecting live code.

## FORGE-local persistence SQL policy

- Any change to `forge-persistence`, SQLite schema/migration/query code, row codecs, recovery journals, or persistence performance must additionally read `.agents/rust_dev_harness/rules/normal_dev_rules/10-forge-persistence-sql-rules.md`.
- That rule and `.agents/rust_dev_harness/harness/forge-persistence/README.md` are **repository-local FORGE authority** and must not be added to `ALEXANDRIA_MANIFEST.tsv` or promoted into the reusable Alexandria harness.
- Use `cargo xtask persistence` as the focused persistence gate, then run canonical `cargo xtask ci` before completion.
- Keep `rusqlite`/SQLite direct authority unless an explicit repository architecture decision intentionally replaces this project-specific contract; do not introduce an ORM as a cosmetic SQL-removal shortcut.

## Rust-only invariant

- Production application/runtime code is Rust.
- Mechanical verification is Rust through repository `xtask` once scaffolded.
- Do not introduce Python, JavaScript, TypeScript, Node, Electron, PyO3, or a non-Rust sidecar/runtime as an implementation shortcut.
- Configuration/data files and platform metadata are allowed when required by Cargo, macOS packaging, Slint, MCP, or tooling.
- FFI is not a default architecture. Any future FFI/native boundary must remain a narrow Rust platform adapter with an explicit safety contract.

## Rust engineering discipline

- Use Rust stable, Edition 2024, Cargo resolver 3.
- Default to safe Rust. Workspace policy is `unsafe_code = "deny"` only because Slint 1.17.1 generated code is incompatible with workspace `forbid`; no handwritten unsafe is approved. Any future unsafe/native boundary requires an explicit project-profile exception, normal rule 05 review, and stronger verification before code lands.
- Deny unsafe operations inside `unsafe fn` without an explicit unsafe block and require documented unsafe blocks.
- Prefer explicit typed domain models, newtypes, exhaustive matches, `#[must_use]` outcomes, and typed errors.
- Treat ownership, borrowing, `Send`, and `Sync` failures as architecture feedback; do not solve them with gratuitous `clone`, global `Arc<Mutex<_>>`, leaked lifetimes, or unsafe trait implementations.
- Keep deterministic domain/state transitions separate from I/O and runtime effects even though both layers are Rust.
- Do not hide clocks, randomness, filesystem/network/process access, or global mutable state inside deterministic core logic.
- Long-lived Tokio tasks have an owner, bounded queues/backpressure, cancellation semantics, and a shutdown/join path.
- Slint remains UI-thread-owned and receives typed projections from the runtime; the UI never becomes persistence/policy authority.
- Workspace SQLite owns durable semantic state; runtime memory owns only live capabilities.
- Preserve user work: inspect the dirty worktree first and never reset/clean/revert unrelated changes.
- Dependencies and build scripts are part of the trusted product surface. Keep `Cargo.lock` and use locked/reviewed dependency gates once scaffolded.
- Do not claim a check passed unless it was actually executed.
- Run focused tests first, then canonical `cargo xtask ci`; use `cargo xtask supply-chain` for configured extended/release verification.
- Commit or push only when the user explicitly requests it.

## Codex subagent routing

The repository uses the Balanced Codex agent package:

- Main: Sol XHigh
- Optional Technical Lead: Terra XHigh
- Leaf workers: four Luna Max subagent slots

Routing rules:

- Use the fewest agents that materially improve speed, correctness, or evidence. Zero subagents is valid.
- For clear bounded work, Main may delegate directly to a Luna worker without involving Terra.
- Use `technical_lead` when lifecycle, concurrency, persistence, transaction, recovery, protocol, reliability, security-boundary, or broad integration ambiguity materially affects the task.
- Luna roles are task-scoped perspectives, not permanent crate owners.
- Parallelize only independent workstreams with explicit ownership and merge boundaries; avoid overlapping writers on the same files or authority boundary.
- Prefer `exploration_steward` for read-heavy mapping, `implementation_steward` for accepted bounded implementation, `verification_steward` for independent proof, and `integration_steward` for bounded cross-component follow-through.
- Treat subagent self-reports as claims until the relevant evidence has been inspected or re-run.
- Main remains responsible for synthesis, conflict resolution, consequential architecture decisions, final integration, and deciding whether a phase is complete.
- Escalation ladder for systems ambiguity is Luna -> `technical_lead` -> Main. Architecture/authority decisions may escalate directly to Main.
