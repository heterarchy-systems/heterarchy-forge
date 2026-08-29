# Heterarchy Forge Rust Project Profile

## Project shape

- kind: macOS desktop application + local runtime + stdio MCP service
- primary binaries: `forge-desktop`, `forge-mcp`, `xtask`
- primary libraries: domain, workspace/filesystem, persistence, control, execution, runtime, platform, UI
- normal rules: required
- async/concurrency rules: enabled
- production language: Rust only

Heterarchy Forge lets multiple Chat/Activity contexts work in explicitly selected local Workspaces while preserving typed authority, durable evidence, bounded effects, and owner-controlled stop/approval semantics.

## Current implementation status

Active in the current worktree:

- explicit Location/Workspace resolution and Workspace-local state;
- Activity lease ownership and Live/History projections;
- observational Activity refresh: expired leases remain explicit projections
  until a separate recovery owner performs a bounded transition;
- descriptor-confined filesystem read/create/replace/delete;
- Activity-attributed ChangeSet and redacted compressed Diff evidence;
- sandboxed structured/shell execution with process-group supervision;
- exact Plan 07 approval grants, conservative bounded Auto Approval, Workspace/global stop;
- schema-v16 Workspace SQLite authority, including exact checkpoint/restore provenance journals, optional Goal contracts, immutable DAG revisions, durable Agent attachments/principals, one-shot DAG authoring grants/replay ledger, recovery-maintenance fencing, and durable applied Harness state;
- app-global durable Harness Catalog with bounded local Bundle inspection, native Settings registration/refresh, Workspace Harness projection plumbing, source-integrity source/version/hash/verification projection, read-only CREATE/MERGE/UNCHANGED/CONFLICT installation Preview, and explicit conflict-free Apply through a descriptor-rooted managed-tree writer; Apply preserves user `AGENTS.md` text outside the bundle marker, writes `.agents/.heterarchy.toml` last with `deletion_authority = false`, converges after partial pre-marker materialization, and commits durable applied-Harness state only after filesystem success;
- adaptive Rust/Slint `Obsidian Assay Bench` workbench with exact
  minimum/standard/wide width classes, dead-zone-free resizable/collapsible
  rails, top-level Settings, real Goal/current-DAG projections, deterministic
  UI-only DAG columns/lanes and exact edge connectors, and truthful
  Harness/narrative empty states;
- exact 22-tool stdio MCP surface without command, shell, restore, node-lifecycle,
  execution, or implicit-continuation exposure; its only DAG mutation is a
  credential-bound exact-head one-shot immutable successor revision;
- opt-in loopback-only Streamable HTTP projection of the same exact 22 tools,
  with bounded Host/Origin/body validation and durable Workspace-scoped local
  bearer authorization; raw bearer values are one-time reveals, keyed digests
  live in a separate app-global SQLite catalog, and the pepper is macOS
  Keychain-owned;
- descriptor-capable macOS checkpoint capture into a Forge-owned bare Git store,
  provenance-safe direct restore through the confined mutation boundary, and
  bounded row/ref/object integrity observation without touching user Git refs;
- read-only exact-scope Workspace Doctor with bounded SQLite integrity/FK,
  stale lifecycle, Git local-state, Diff DB/artifact + invalid-node,
  checkpoint owned-store, and current DAG semantic/cycle/readiness evidence;
- bounded cross-Location Workspace identity Doctor for duplicate durable IDs and
  stored Location attribution mismatches;
- Selected-Workspace Doctor Workbench projection through the bounded control
  worker, with a 64-row UI cap, 16 KiB operator-safe text projection, and an
  explicit asynchronous export to product-owned Application Support diagnostics.

Plan 09 and Plan 10 add optional durable Goal and DAG contracts without adding
a scheduler or implicit continuation. DAG revisions
are immutable; head and node lifecycle changes use typed comparison-and-swap;
readiness is a deterministic ALL-of projection; completed nodes/evidence carry
across validated replans; and current-head lineage remains explicit. Trusted
local control and the bounded worker own mutations. Slint receives read-only
Goal/DAG projections plus explicit issue/revoke controls for a five-minute,
one-shot, exact-head Agent DAG authoring grant; the graph itself remains
selection-only. Checkpoint Git authority is the Forge-owned bare store
below `.heterarchy-forge/checkpoints/store.git`; the user repository's
HEAD/index/worktree/refs are never selected as checkpoint authority or mutated.

Explicitly incomplete: reviewed handling of database/filesystem observational
non-atomicity beyond the current before/after root/binding checks; automatic or
maintenance-fenced checkpoint restore policy beyond explicit direct restore;
production App Sandbox/bookmark persistence; remote/public TLS/OAuth MCP beyond
the loopback listener and configured public origin; verified command-submission adapters;
full ChatGPT → MCP → FORGE capture/restore/Doctor E2E; and
universal2/Developer ID signing/notarization E2E. A verified arm64 local Installer
package is available through `cargo xtask package`; its default ad-hoc app
signature and unsigned package are not distribution approval. Doctor remains observational; diagnostics file
creation is a separate explicit operator export effect outside Workspace state.

## Toolchain and compatibility

- edition: 2024
- workspace resolver: 3
- toolchain policy: repository-owned Rust 1.92.0 channel, minimal profile
- `rust-toolchain.toml`: `/rust-toolchain.toml`
- MSRV policy: explicit `rust-version = "1.92"` for workspace packages
- `Cargo.lock` policy: committed application lockfile; all canonical gates use `--locked`
- formatting/lint components: rustfmt + Clippy required
- supported targets: macOS aarch64 and x86_64; development evidence is currently aarch64 macOS unless a gate states otherwise

## Crate and authority map

| Crate / binary | Responsibility | Effects owned | Must not own |
| --- | --- | --- | --- |
| `forge-domain` | typed deterministic commands, states, decisions, IDs, revisions, policy, checkpoint CAS planning | none | filesystem, Git, SQLite, Tokio, Slint, clocks/randomness |
| `forge-workspace` | Workspace discovery/state layout, descriptor-confined filesystem, Diff/checkpoint/Git adapters | bounded local filesystem and reviewed Git process effects | Workspace semantic policy, UI, MCP transport |
| `forge-persistence` | Global Registry + Workspace SQLite repositories/migrations/recovery | SQLite and metadata transactions | live process/grant/task handles, raw large artifacts |
| `forge-control` | application policy/orchestration across repositories and effects | short-lived adapter composition through owned services | transport/Slint policy, hidden global Workspace |
| `forge-execution` | sandbox profile, process-group execution, bounded output, supervision | owned child processes and signals | approval policy, UI/MCP exposure |
| `forge-runtime` | Tokio lifecycle, projection transport, stop/drain coordination | Tokio tasks/timers/cancellation | durable semantic authority |
| `forge-mcp` | strict stdio rmcp DTO/transport and bounded admission | stdio transport + MCP Activity lease owner | implicit Workspace, arbitrary command/restore capability |
| `forge-platform` | narrow macOS AppKit/path/logging adapters | safe `objc2` AppKit integration and app-local paths | domain/persistence policy |
| `forge-ui` | Slint component/projection definitions | UI-thread projection only | SQLite, Git, filesystem/process policy |
| `forge-desktop` | desktop composition/controllers/tray | UI-owned handles and bounded worker requests | direct SQLite/Git/process effects in callbacks |
| `xtask` | Cargo-native structural and mechanical verification | developer tooling processes | product runtime authority |

Dependency direction:

```text
Slint / MCP / macOS adapters
            ↓
      application control
            ↓
      deterministic domain

persistence / workspace / execution implement application-owned effects
without importing UI or transport authority into the domain.
```

## Effects and external state

- persistence authority: Global Registry SQLite for Location metadata; app-global Harness Catalog SQLite for registered Bundle/Skill metadata/source roots; app-global MCP Token Catalog SQLite for keyed token digests/lifecycle/scopes; app-global MCP Connection Settings SQLite for public origin/local port; Workspace-local SQLite schema v16 for Workspace/Activity/ChangeSet/Diff/Execution/Approval/Checkpoint/Restore/Goal/DAG/Agent authoring/recovery/applied-Harness/verifier semantic state
- large payload authority: `.heterarchy-forge/diffs`, `checkpoints`, `artifacts`, and `recovery`; SQLite stores bounded metadata/ref/hash only
- network/transport authority: stdio-default `forge-mcp` plus explicit 127.0.0.1-only bearer-authenticated Streamable HTTP; remote/public OAuth/TLS is not implemented; network remains denied to executions unless exact effective permission grants it
- filesystem authority: descriptor-rooted `forge-workspace` adapters under a revalidated Workspace root
- process authority: `forge-execution` supervisor; Git plumbing belongs to a bounded `forge-workspace::git_safety` adapter
- clocks/randomness/IDs: observed/generated at application/worker boundaries and passed into deterministic commands
- configuration/environment ownership: Cargo/config and platform bootstrap; child processes receive an explicit allowlisted environment
- semantic durability: durable-first/write-through; no SQLite transaction is held across filesystem, Git, process, UI, or network waits

## Async / concurrency

- runtime/executor: Tokio multi-thread runtime in `forge-runtime`
- runtime model: owned service lifecycle with latest-value/coalesced UI projections
- task ownership/supervision: service-owned task/process handles with joined shutdown; no meaningful detached work
- cancellation propagation: runtime stop participant → approval revoke/drain → execution process-group drain → worker joins
- queue/channel capacities: all application/control/supervisor/UI handoffs are bounded; current notable bounds include Location UI queue 1, Activity/Approval UI queues 4, execution supervisor queue 32, completion backlog 64, raw approval payloads 128, cached Auto Approval scopes 32
- connection/in-flight limits: MCP/service and Activity groups use explicit repository bounds; no unbounded request admission
- blocking bridge: blocking filesystem/SQLite/Git/process work stays in bounded single-owner workers/adapters and never blocks the Slint event thread indefinitely
- CPU parallel executor: none; no separate Rayon pool is currently justified
- graceful shutdown budget: focused lifecycle tests require stop/restart/shutdown completion within one second where deterministic
- concurrency verification: bounded-channel saturation, same/different Workspace isolation, SQLite CAS/busy rollback, restart reconciliation, process descendant cleanup, and runtime coalescing tests; Loom/Shuttle are not yet configured

## Feature policy

The application uses a constrained reviewed feature set rather than treating arbitrary `--all-features` combinations as supported.

Supported matrix:

- workspace default feature selection under the checked-in lockfile
- two configured macOS targets for dependency policy
- rmcp `server + transport-io` only
- Slint accessibility + winit + femtovg + std + system-tray

Unsupported combinations are not silently promoted to supported by a blanket all-feature gate. Root xtask uses the project-owned matrix and locked workspace checks/tests.

## Unsafe / FFI / native boundary

- default unsafe policy: workspace `deny`; handwritten unsafe remains prohibited
- approved unsafe modules: none
- FFI/native ABI: no application FFI ABI; safe `objc2`/`objc2-app-kit` wrapper use only
- thread affinity: AppKit/Slint handles remain on the UI/main thread; background messages contain typed Send projections
- soundness verification: safe Rust compiler/Clippy gates and real macOS adapter tests; any future unsafe/native ABI requires a separately reviewed crate/module and profile update before code lands

## Dependency / supply-chain policy

- direct dependency review required: yes; no dependency without a concrete capability
- default features: disabled/minimized where the selected crate permits it
- `cargo-deny`: required, exact tool version enforced by project xtask
- `cargo-audit`: required for the project supply-chain/release gate
- allowed registries/git sources: crates.io registry only; no Git dependencies
- build-script/proc-macro/native-sys review: required as trusted product surface
- license/advisory/duplicate exceptions: repository-owned `deny.toml` with rationale and removal/review conditions

## Verification gates

### Mandatory CI

- `cargo xtask rules`
- `cargo xtask fmt`
- `cargo xtask check`
- `cargo xtask test`
- `cargo xtask ci`
- project-specific `cargo xtask doctor` before completion claims that depend on runnable binaries

### Extended / scheduled / high-risk

- `cargo xtask deps`
- `cargo xtask extended`
- project-specific `cargo xtask supply-chain` (`cargo deny` + `cargo audit`)
- project-specific `cargo xtask package` for an arm64 local `.app` and Installer payload gate
- real macOS sandbox/Git/filesystem/process integration tests for touched high-risk boundaries
- x86_64 macOS, universal packaging, Developer ID signing/notarization, VoiceOver, Miri/fuzz/Loom/Shuttle only when their release/high-risk gate is explicitly invoked or added

### Performance

- `cargo xtask perf` is measurement evidence and currently must fail as unconfigured until a reviewed benchmark target exists
- critical workloads: UI-thread latency, Activity projection fan-in, SQLite query bounds, Git/checkpoint size scaling, diff/output artifact volume, process cancel/stop latency, and build/check latency
- no performance PASS is claimed from intuition or one noisy measurement

## Operational lifecycle

- readiness/liveness authority: committed Workspace/Activity/Harness/Execution evidence plus live runtime overlay; model-written text is never sole authority
- shutdown sequence: stop admission → revoke approval authority → cancel/drain process groups → journal terminal evidence → stop runtime tasks → join control/location workers → report
- leak evidence: process-group absence, bounded queues, task/service joins, closed Activity leases, terminal/interrupted durable reconciliation
- UI callbacks enqueue bounded application intents; they never directly run SQLite, Git, filesystem, command, or policy effects

## Explicit exceptions and reviewed debt

### Slint generated-code unsafe lint compatibility

- rule affected: shared default `unsafe_code = "forbid"`
- reason: Slint 1.17.1 generated Rust expands macros that locally declare `allow(unsafe_code)`; rustc rejects that declaration under a command-line/workspace `forbid` before application code is checked
- scope: generated `forge-ui` build output only; no handwritten unsafe block or unsafe impl is approved
- compensating evidence: workspace `unsafe_code = "deny"`, `unsafe_op_in_unsafe_fn = "deny"`, `undocumented_unsafe_blocks = "deny"`, strict Clippy, and source review/grep for handwritten unsafe
- owner/review: Heterarchy Forge UI/runtime owner; retry `forbid` on each Slint upgrade or when generated bindings no longer require a local allowance

### Deprecated macOS sandbox prototype

- rule affected: supported production platform/security boundary
- reason: current local command slice uses deprecated `/usr/bin/sandbox-exec` for real fail-closed prototype enforcement
- scope: local execution tests/runtime only
- compensating evidence: real inside/outside/state-root/network deny tests, process-group cleanup, no claim of production App Sandbox readiness
- owner/review: Heterarchy Forge release engineering; remove when supported App Sandbox/security-scoped design lands

### Slint dependency graph debt

- rule affected: duplicate/unmaintained dependency minimization
- reason: pinned Slint 1.17.1 rendering/platform graph currently owns the duplicates and four allowed unmaintained transitive warnings
- scope: `bincode`, `paste`, `rustybuzz`, `ttf-parser` warnings and reviewed duplicate versions
- compensating evidence: locked graph, cargo-deny/cargo-audit gates, exact Slint license exceptions
- review: every Slint upgrade and release gate

### Native interactive evidence gap

- rule affected: real UI/platform E2E evidence
- reason: unbundled folder-picker/VoiceOver automation is not fully available in the current environment
- scope: modal picker and populated Goal/DAG/narrative accessibility paths
- compensating evidence: source contracts, safe AppKit adapter tests, native window capture, keyboard/focus tests
- review: packaging/acceptance phase; never report this E2E as passed before execution

## Harness source and replacement policy

The active reusable harness was materialized from Alexandria:

```text
Jobs/Harness/Engineering Harness/02 Rust/rust_dev_harness/
```

`HARNESS_MANIFEST.tsv` records materialized body SHA-256 values and relative paths for the shared harness bundle. `cargo xtask rules` recomputes the body hashes. Retired `profiles/native-compute` material is not active local authority. Repository-specific authority is this profile plus live Cargo/xtask/source/tests; the shared bundle is not an escape hatch or a substitute for live inspection.
