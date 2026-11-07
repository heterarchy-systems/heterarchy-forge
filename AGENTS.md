# Heterarchy Forge Agent Instructions

## Current backend loading entrypoint

Read `.agents/rust_dev_harness/BACKEND_PROFILE.md` before the framework-specific work below. The active target is the Rust backend; SSE uses Axum native Sse/Event/KeepAlive, while native Axum WebSocket is conditional on a real duplex requirement. The library profiles and procedures are materialized locally, with provenance in `.agents/rust_dev_harness/LIBRARY_SYNC.json`. Preserve existing runtime/identity/recovery contracts during migration.

For the current user-authorized harness/docs task, ChatGPTtoCodex may perform exact project-scoped edits while the Heterarchy bridge is unavailable. This is not a Forge grant, does not authorize bypassing runtime effect checks, and must not be reported as a Forge ChangeSet or runtime verification.


Heterarchy Forge is a **Rust-only** repository-work runtime. The product is a
GUI-less pure backend: the Slint/`forge-ui`/`forge-desktop` surface is retired
and the default build/run/package path is the headless HTTP backend host. The
user-approved full Linux execution-backend migration remains in progress.
Compilation alone does not establish Linux execution or deployment readiness.

## Authority

Read these before changing production code:

1. `.agents/rust_dev_harness/PROJECT_PROFILE.md`
2. `.agents/rust_dev_harness/rules/README.md`
3. `.agents/rust_dev_harness/rules/normal_dev_rules/README.md`
4. `.agents/rust_dev_harness/rules/type_dev_rules/README.md`
5. For async/concurrent work, `.agents/rust_dev_harness/rules/async_dev_rules/README.md`
6. `.agents/rust_dev_harness/skills/rust-engineering/SKILL.md`
7. For Axum/HTTP backend work, `.agents/rust_dev_harness/profiles/axum-backend/README.md` and `.agents/rust_dev_harness/skills/axum-backend/SKILL.md`
8. For realtime/SSE/WebSocket/long-lived streaming work, `.agents/rust_dev_harness/profiles/realtime-backend/README.md` and `.agents/rust_dev_harness/skills/realtime-backend/SKILL.md`, plus the active transport-specific Axum rule when applicable
9. The normal, type, async, framework, and runtime rule files matching the touched boundary
10. Live `Cargo.toml`, `xtask/`, tests, and source code

Repository-local source and tests are the final implementation authority. The harness is a guardrail, not a substitute for inspecting live code.

## FORGE-local persistence SQL policy

- Any change to `forge-persistence`, SQLite schema/migration/query code, row codecs, recovery journals, or persistence performance must additionally read `.agents/rust_dev_harness/rules/normal_dev_rules/10-forge-persistence-sql-rules.md`.
- That rule and `.agents/rust_dev_harness/harness/forge-persistence/README.md` are **repository-local FORGE authority** and must not be added to `ALEXANDRIA_MANIFEST.tsv` or promoted into the reusable Alexandria harness.
- Use `cargo xtask persistence` as the focused persistence gate, then run canonical `cargo xtask ci` before completion.
- Keep `rusqlite`/SQLite direct authority unless an explicit repository architecture decision intentionally replaces this project-specific contract; do not introduce an ORM as a cosmetic SQL-removal shortcut.

## FORGE-local backend / realtime policy

- Any work on the planned HTTP JSON backend, SSE/WebSocket, live event projection, reconnect/replay, connection admission, or backend transport cutover must additionally read `.agents/rust_dev_harness/harness/forge-backend/README.md`.
- The accepted Forge target is **typed HTTP JSON application/control commands + resumable/coalesced SSE server→UI projection**. WebSocket is inactive unless a separately reviewed true-duplex session requires it.
- Current durable Workspace/Activity/Goal/DAG/Agent/Verification and related persistence authority remains the replay/state source. A socket, SSE connection, WebSocket session, `broadcast` retention, or connection-local sequence must not become durable semantic authority.
- Forge continues to use `rusqlite`/SQLite. The reusable Axum SQLx material is reference-only and inactive for Forge unless an explicit architecture decision changes persistence authority.
- A Harness/profile update does not authorize adding production network dependencies or claiming the planned backend is implemented. Product transport changes require normal source, security, lifecycle, migration-parity, and verification evidence.
- `harness/forge-backend/README.md` is repository-local Forge authority and must not be promoted into the reusable Alexandria manifest.

## Rust-only invariant

- Production application/runtime code is Rust.
- Mechanical verification is Rust through repository `xtask` once scaffolded.
- Do not introduce Python, JavaScript, TypeScript, Node, Electron, PyO3, or a non-Rust sidecar/runtime as an implementation shortcut.
- Configuration/data files and platform metadata are allowed when required by Cargo, MCP, or tooling.
- FFI is not a default architecture. Any future FFI/native boundary must remain a narrow Rust platform adapter with an explicit safety contract.

## Rust engineering discipline

- Use Rust stable, Edition 2024, Cargo resolver 3.
- Default to safe Rust. Workspace policy is `unsafe_code = "forbid"`; no handwritten unsafe is approved. Any future unsafe/native boundary requires an explicit project-profile exception, normal rule 05 review, and stronger verification before code lands.
- Deny unsafe operations inside `unsafe fn` without an explicit unsafe block and require documented unsafe blocks.
- Prefer explicit typed domain models, newtypes, exhaustive matches, `#[must_use]` outcomes, and typed errors.
- Treat ownership, borrowing, `Send`, and `Sync` failures as architecture feedback; do not solve them with gratuitous `clone`, global `Arc<Mutex<_>>`, leaked lifetimes, or unsafe trait implementations.
- Keep deterministic domain/state transitions separate from I/O and runtime effects even though both layers are Rust.
- Do not hide clocks, randomness, filesystem/network/process access, or global mutable state inside deterministic core logic.
- Long-lived Tokio tasks have an owner, bounded queues/backpressure, cancellation semantics, and a shutdown/join path.
- Workspace SQLite owns durable semantic state; runtime memory owns only live capabilities.
- Preserve user work: inspect the dirty worktree first and never reset/clean/revert unrelated changes.
- Dependencies and build scripts are part of the trusted product surface. Keep `Cargo.lock` and use locked/reviewed dependency gates once scaffolded.
- Do not claim a check passed unless it was actually executed.
- Run focused tests first, then canonical `cargo xtask ci`; use `cargo xtask supply-chain` for configured extended/release verification.
- Public `make ci` must run without `.agents`. For local agent work, read the existing ignored Harness and run strict `make harness`; never add `.agents` to source commits, CI inputs, or release artifacts.
- Commit or push only when the user explicitly requests it.

## Codex subagent routing

The repository uses this project-local topology:

- Main / Coordinator: GPT-6 Astra High
- All actual subagents: GPT-5.6 Luna Max
- Roles: `context_steward`, `exploration_steward`, `implementation_steward`, `integration_steward`, `verification_steward`
- No default `technical_lead`; Astra Main owns architecture and authority decisions directly.

Routing rules:

- Use the fewest agents that materially improve speed, correctness, or evidence. Zero subagents is valid.
- Astra Main owns user intent, scope interpretation, architecture/authority decisions, root-cause decisions, contract freeze, work decomposition, acceptance criteria, conflict resolution, and final semantic acceptance.
- Luna roles are task-scoped bounded workers, not permanent crate owners and not independent architecture authorities.
- Prefer `context_steward` for canonical/current context, `exploration_steward` for read-heavy mapping, `implementation_steward` for frozen-contract implementation, `integration_steward` only for stable cross-boundary wiring, and `verification_steward` for independent evidence.
- `context_steward` and `exploration_steward` are read-only. `verification_steward` may create normal ephemeral build/test output but must not modify tracked production source, tests, fixtures, golden files, configuration, expected outputs, or acceptance criteria.
- Parallelize only independent workstreams with explicit ownership and merge boundaries; overlapping writers on the same files or authority boundary are forbidden.
- Forge remains the Goal/DAG, Writer Lease, source/worktree mutation, Approval/Execution, Diff/ChangeSet, Verification/Integration, and Evidence provenance authority. Never duplicate Activity/Goal/DAG merely to bypass a blocker.
- Unknown mutation or execution outcome requires durable read-back before retry.
- Treat Luna self-reports and verifier PASS as evidence claims; Astra Main performs final semantic acceptance.
- Escalate architecture ambiguity, authority ambiguity, concurrency/race, recovery, persistence, security, unsafe/FFI, protocol semantics, cross-boundary lifecycle, tracker ownership, CAS/revision, Approval, Writer Lease, execution provenance, sandbox, or persistent-state ambiguity directly to Astra Main.

@RTK.md

<!-- CODEGRAPH_START -->
## CodeGraph

In repositories indexed by CodeGraph (a `.codegraph/` directory exists at the repo root), reach for it BEFORE grep/find or reading files when you need to understand or locate code:

- **MCP tool** (when available): `codegraph_explore` answers most code questions in one call — the relevant symbols' verbatim source plus the call paths between them, including dynamic-dispatch hops grep can't follow. Name a file or symbol in the query to read its current line-numbered source. If it's listed but deferred, load it by name via tool search.
- **Shell** (always works): `codegraph explore "<symbol names or question>"` prints the same output.

If there is no `.codegraph/` directory, skip CodeGraph entirely — indexing is the user's decision.
<!-- CODEGRAPH_END -->
