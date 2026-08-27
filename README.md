<p align="center">
  <img src="./docs/assets/hf-image.png" alt="Heterarchy Forge workspace" width="100%" />
</p>

# Heterarchy Forge

Heterarchy Forge is a Rust-only macOS desktop application and local runtime for preparing, operating, and observing AI-driven local workspaces.

The product is being built from the accepted V1 architecture in Alexandria. The
current verified foundation includes a typed runtime lifecycle, owned Tokio
background runtime, host-standard application directories, structured logging,
a Slint desktop control surface, explicit Location/Workspace flows, and the
canonical Rust `xtask` quality gate.

## Current implemented foundation

```text
Cargo workspace
├─ crates/forge-domain       # typed Location, Workspace, Activity, runtime domain
├─ crates/forge-workspace    # Location discovery, Workspace resolution, state layout
├─ crates/forge-persistence  # global Location registry + Workspace-local SQLite
├─ crates/forge-control      # bounded transport/UI-neutral application control plane
├─ crates/forge-mcp          # official rmcp stdio server + Activity lease supervisor
├─ crates/forge-platform     # paths, logging, safe objc2 folder picker
├─ crates/forge-runtime      # owned Tokio runtime and latest-value transport
├─ crates/forge-execution    # macOS sandbox prototype + owned process supervision
├─ crates/forge-ui           # Slint projection surface
├─ crates/forge-desktop      # startup bootstrap, controls, and doctor
└─ xtask                     # canonical bounded Rust verification harness
```

The implemented foundation is Rust-only and keeps authority explicit:

- The global SQLite registry owns Location discovery/approval metadata only.
  Each explicitly established Workspace owns its durable `WorkspaceId`, root
  binding, revisions, and Activity records in
  `<workspace>/.heterarchy-forge/state.sqlite3`. Live process/task capabilities
  remain in runtime memory.
- Location and Workspace selection are explicit; there is no process-global
  active Workspace fallback.
- Filesystem, Git, SQLite, process, and Slint effects stay behind Rust adapter
  boundaries with typed errors and bounded ingress/output.
- Runtime projections use owned Tokio tasks and a bounded/latest-value transport
  so a slow observer cannot create unbounded backlog.
- The headless desktop doctor opens and health-checks the registry, starts the
  runtime, and proves a `Running` projection before reporting PASS.
- The platform boundary contains a safe direct `objc2`/`NSOpenPanel` adapter
  for directory-only single-selection, with typed cancellation, main-thread,
  modal, URL, and path outcomes.
- The bounded application worker keeps filesystem/database work off the UI thread with
  bounded request handling. Add Location, durable Location list projection,
  Workspace discovery, and durable Workspace establishment are implemented.
  Candidate indices remain UI correlation only; the UI publishes a selection
  after candidate revalidation and the Workspace-local SQLite commit.
- Location state uses schema-v2 revision CAS. Workspace/Activity records use
  independent typed revisions and fail-closed root fingerprints. A committed
  Workspace selection is still not a filesystem/process/network effect grant.
- Workspace-local state initialization serializes concurrent writers and writes
  exact nested-worktree rules to `.git/info/exclude` without modifying tracked
  `.gitignore` files.
- The official `rmcp 3.1.4` stdio server exposes exactly `workspace_list`,
  `workspace_resolve`, `activity_bootstrap`, `file_read`, `file_create`,
  `file_replace`, `file_delete`, `diff_list`, `diff_read`, `diff_doctor`,
  `diff_retention_plan`, and `diff_artifact_doctor`. The last two are read-only
  storage planning and owned/orphan/conflicting inventory surfaces; they do not
  grant MCP deletion authority.
  Every request carries an exact Location revision and Workspace
  locator/identity. File effects additionally require a tracked live Activity;
  bounded history reads do not silently promote process ownership.
- Activity schema v2 separates durable Open/Closed/Interrupted state from a
  process-owned runtime lease. Heartbeats and graceful close are grouped into
  one bounded transaction per Workspace; expired leases reconcile to
  Interrupted and cannot be silently reattached.
- WorkspaceStore schema v10 retains metadata-only, Activity-attributed ChangeSet,
  Diff Evidence, execution intent/terminal records, approval authority, and
  checkpoint/restore journals. Redacted Diff bodies remain bounded
  Workspace-local `.diff.zst` artifacts with exact compressed/uncompressed
  BLAKE3 hashes and sizes rather than SQLite BLOBs. A Starting/Intent pair is
  recovery evidence and is never replayed automatically; migrated v3 Applied
  records remain explicit legacy-without-Diff history.
- Plan 10 schema-v10 foundation adds immutable DAG revision/head/node/edge
  storage with exact SQL validation and a no-synthetic-state v9 migration.
  The pure domain already rejects cycles, self/duplicate/unknown edges and
  derives ALL-of readiness deterministically. Persistence now provides immutable
  revision insertion/readback, head CAS, current-head-only node lifecycle CAS,
  completed-node/evidence carry-forward, atomic source+Goal+node evidence
  admission, typed split/replace/merge lineage, and a Goal completion gate.
  Trusted-local control and bounded worker dispatch are active with explicit
  revision/head/node requests and shutdown rejection. The Rust/Slint desktop
  now projects the selected Goal's current immutable DAG revision as a bounded,
  bidirectionally scrollable read-only causal canvas. Validated exact edges are
  laid out into deterministic longest-depth columns and stable per-column
  lanes; blocked incoming dependencies and exact edges into the active node are
  visible without inventing a critical path. Nodes retain derived readiness,
  waiting state, evidence counts, and selection-aware Inspector details. The UI
  exposes no DAG authoring or lifecycle mutation callback.
- Plan 09 durable Goal contracts are active in trusted local control and the
  Rust/Slint desktop. Goals are optional, immutable after creation, revision-CAS
  guarded, restart durable, and explicitly lifecycle controlled. Hard completion
  recomputes bounded linked Approval/Execution/ChangeSet/Checkpoint evidence in
  the write transaction and verifies `FilePresent` requirements through the
  descriptor-confined Workspace boundary before that transaction. Effect
  admission associates Goal evidence atomically; Goal-linked Diff artifacts are
  excluded from retention and tombstone races. A Goal creates no background
  task, scheduler, implicit continuation, or execution authority. DAG remains a
  separate optional contract, and MCP remains the exact 12-tool surface.
- Plan 11A Doctor-01 adds a typed, exact-scope, read-only Workspace integrity
  report without a schema bump. It validates the current schema/application/
  Workspace binding, runs bounded `quick_check(1)` plus first-row foreign-key
  diagnosis, and reports up to 256 stale Starting/Running Executions and
  Starting checkpoint restores with an explicit truncation bit. Existing
  DB/WAL/SHM identity, size, and modification observations are rechecked; an
  active WAL is inspected through a temporary DB+WAL snapshot capped at
  512MiB, and the source is never migrated, checkpointed, or reconciled.
  Trusted-local control and
  its bounded worker revalidate the exact Location/Workspace root around the
  report; MCP remains unchanged.
- Plan 11A Doctor-02 composes that same read-only observation with the
  Workspace's local Git visibility contract and bounded Diff database/artifact
  evidence. Git inspection distinguishes a non-Git Workspace from verified
  local exclusion, missing exact `.git/info/exclude` coverage, tracked Forge
  state, state made visible by an ignore negation, and unavailable Git
  observation without repairing any of them. Diff inspection preloads at most
  256 canonical database references with explicit truncation, joins them to a
  bounded filesystem inventory, fully verifies owned zstd/UTF-8 payload hashes
  and sizes, and classifies available, missing, corrupt, orphan, conflicting,
  pending, not-applicable, and unverified evidence. The aggregate result is
  typed as Healthy, RecoveryRequired, Damaged, or Incomplete. The existing
  artifact inventory path now uses the same fixed-query preload instead of up
  to roughly 2,048 per-entry SQLite lookups. No schema, MCP tool, background
  task, repair, purge, or reconciliation authority was added.
- Desktop and MCP `--doctor` now inspect an existing Global Registry before any
  Application Support creation, logging initialization, or write-capable open.
  A missing Registry is a truthful `NOT_INITIALIZED` warning and an active
  Registry WAL fails closed without touching sidecars. MCP transport smoke uses
  only an owned temporary Registry. Repository `xtask doctor` injects an
  isolated HOME/nonexistent Registry path and verifies that Doctor creates no
  Registry, so canonical verification no longer reads or mutates operator
  state.
- File effects use a per-component descriptor-relative `rustix` walk with
  `NOFOLLOW`, reject protected paths, all symlinks, non-regular files and
  hardlinks, serialize Forge writers with a bounded cross-process lock, and use
  `blake3-256` expected-content CAS plus same-parent synced temporary files.
  Initialized parent/child Workspace overlap fails closed before effects.
  Overlap is linearized at effect admission; an already admitted effect is not
  dynamically revoked by a concurrently created scope.
- Text Diff Evidence captures at most 64KiB from the same PRE descriptor read,
  classifies binary/oversized sources as summary-only, redacts configured secret
  keys, bearer credentials, and PEM private-key blocks before rendering, and
  caps deterministic unified output and compressed artifacts at 128KiB. Pending
  artifacts are synced before the file effect; final artifacts are atomically
  published before `Applied + Ready` commits. Read/doctor paths reverify hashes,
  sizes, UTF-8, zstd decoding, directory identity, and missing/corrupt state.
- Explicit retention is opt-in: callers supply `keep_recent` and receive a
  read-only revision-bound plan. Trusted local control can then perform
  `Ready → PurgePending → Tombstoned` around verified artifact deletion under
  the same cross-process Workspace writer lock. No automatic age/count default
  exists. Bounded directory inventory classifies owned, orphan, and conflicting
  entries; orphan deletion requires the exact native name, BLAKE3 hash, and
  size and refuses any current or legacy DB ownership conflict.
- Command execution keeps structured argv distinct from the explicit shell
  escape path, clears the parent environment, applies a fixed safe baseline,
  and hashes the exact request with typed/length-delimited BLAKE3 fields without
  persisting raw argv or shell text. The macOS prototype uses the deprecated
  `/usr/bin/sandbox-exec` backend and fails closed when unavailable; tests prove
  Workspace-only read/write, protected `.heterarchy-forge` denial, outside-read
  and outside-write denial, and network default-off/explicit-on behavior.
  Every child owns a process group, bounded stdout/stderr drain, timeout,
  graceful TERM -> KILL escalation, descendant cleanup, manual/Workspace/global
  cancel, and joined supervisor path. Runtime Stop/Restart/Shutdown drains the
  execution owner before publishing successful completion.
- Execution evidence uses exact schema-v5 -> v6 migration, revision CAS, and
  `Starting -> Running -> terminal` records with bounded output totals and
  truncation metadata. Exact request-digest retries converge; conflicting reuse
  fails closed. Restart reconciliation marks bounded incomplete records
  `Interrupted` without replaying them or signalling stale persisted PIDs.
  Control-worker journaling stays responsive while long commands run on the
  separate execution owner.
- Plan 07 authorization is active in trusted local control: direct structured
  and shell execution remain ASK by default, one-shot grants bind the exact
  Workspace/Activity/Execution/request digest, bounded Auto Approval applies
  only to verified discovered commands, and Workspace/global stop reports
  success only after terminal evidence is journalled and owned process groups
  are drained. No command or shell mutation tool is exposed through MCP.
- Plan 08 checkpoint foundations are typed and schema-v10 durable. Checkpoints
  bind the exact ChangeSet mutation path/PRE/POST attribution, lifecycle
  rehydration fails closed, terminal retries are idempotent, list reads use
  bounded preload queries rather than per-row N+1 validation, and the Git
  adapter has bounded process-group cleanup plus deterministic `mktree`
  plumbing. Apple Git 2.50.1 cannot use an inherited directory FD as
  `GIT_DIR`; the adapter therefore rejects Git writes before effects on macOS
  instead of falling back to a rebindable named path. Production checkpoint
  capture/restore remains explicitly experimental and unintegrated.
- MCP/worker authority time is captured at execution rather than accepted from
  wire input. The lease tracker acknowledges registration, keeps recovery per
  Activity, migrates an entire Workspace group on scope rebind without revision
  downgrade, and deliberately caps one process at two Workspace heartbeat
  groups / 128 Activities so the single-owner heartbeat lane stays within its
  lease budget.
- The Desktop projects only fresh leased Open Activities as Live and shows
  Closed/Interrupted/recovery records in History. An expired Open lease is
  projected as explicit `Expired` history and is no longer rewritten to
  `Interrupted` merely because the UI refreshed; semantic reconciliation stays
  behind the separate trusted recovery operation. Activity UUIDs remain hidden
  behind temporary `Chat NN` labels. Selecting a Live/History row loads at most
  50 durable changes through the nonblocking control worker; selecting a change
  opens a verified read-only Diff inspector with explicit binary/oversized/
  missing/corrupt states. It provides no manual Chat-to-Workspace binding or
  Activity creation control.
- The Rust/Slint workbench now uses a real adaptive three-region topology:
  Goal/Workspace scope on the left, Goal + read-only DAG + Activity/Evidence in
  the center, and a full-height selection-aware Inspector with fixed Safety
  access on the right. Minimum (`1120`), standard (`1280`), and wide (`1600`)
  width classes change pane budgets and the lower-deck topology rather than
  stretching one fixed layout. Both rails resize from a drag-origin snapshot,
  collapse independently to 48px, and restore their session widths. Settings
  replaces the whole workbench body with a flat domain surface; unavailable
  Harness Library registration and selected-Workspace source/version/hash/
  source-integrity projection now use bounded workers rather than fabricated
  state. Plan 08A Preview reports CREATE / MERGE / UNCHANGED / CONFLICT without
  writing Workspace files. A conflict-free Preview can be explicitly Applied:
  descriptor-confined materialization creates the managed `.agents/` tree,
  preserves user-authored `AGENTS.md` outside the bundle-owned marker block,
  writes `.agents/.heterarchy.toml` last as the materialization/provenance marker,
  and commits durable applied-Harness state only after materialization succeeds.
  The v1 marker explicitly has no deletion authority, so a pre-existing
  byte-identical file is never silently converted into future Remove authority.
  Regular Apply cannot silently switch to a different durable Harness; Update /
  Switch / Remove and sandboxed declared-verifier execution remain separate
  follow-up flows. Still-unmodeled preferences remain explicitly labelled. A selected Goal's current DAG is loaded through the same bounded
  nonblocking worker boundary; a missing DAG remains a truthful empty state.
  The Goal rail now loads real bounded Workspace-local contracts through the
  nonblocking worker and supports inline create, fresh hard review,
  Pause/Resume/Cancel/Complete, revision-bound selection, and truthful Inspector
  projections without exposing private model reasoning.
- The final UI quality pass raises the operating type scale, replaces character
  chevrons with accessible Slint paths, uses semantic unavailable-state contrast,
  keeps one Inspector tab authority, removes splitter dead zones across width
  classes, constrains Settings reading width, and makes the first Workspace
  preparation action directly operable. Native 1120×720, 1480×920, 1680×920,
  Settings, Harness Settings, and both-rails-collapsed captures are checked in
  under `docs/screenshots/plan11-ui/`.
- MCP ingress frames, worker queues, catalog/activity lists, Git/doctor output,
  and heartbeat batches are explicitly bounded. SQLite/state roots are guarded
  against symlink, hardlink, parent replacement, and stale-handle races.

## Development

```bash
cargo xtask rules
cargo xtask fmt
cargo xtask check
cargo xtask test
cargo xtask ci
cargo xtask msrv
cargo xtask doctor
cargo xtask supply-chain
cargo xtask extended
cargo run -p forge-desktop
cargo run -p forge-mcp -- --doctor
cargo run -p forge-mcp
```

`cargo xtask doctor` performs both desktop runtime and MCP stdio lifecycle smoke
tests. The reviewed `deny.toml` policy requires current `cargo-deny` and
`cargo-audit`; the final local evidence used versions 0.20.2 and 0.22.2.
`cargo xtask perf` deliberately reports `unconfigured` until a reviewed
benchmark target and workload exist; that result is not a performance PASS.

The native folder picker adapter is implemented, but interactive modal E2E
(accessibility/screen capture) remains unverified. The following product slices
are not yet complete: packaged app/App Sandbox and security-scoped bookmark
persistence, path list/stat/search/patch/move, automatic Diff retention policy,
remote MCP Streamable HTTP/OAuth/authentication, production App Sandbox replacement,
approval/grant-backed command UI/MCP exposure, descriptor-capable macOS Git
checkpoint writes, production CAS restore authority, and full GUI/browser E2E
evidence. The local stdio MCP server, durable Activity lifecycle, and bounded
file read/create/replace/delete boundary are active. The low-level local command
engine and Plan 07 grant path are active, but no command/shell mutation tool is
MCP-exposed. Exact verification evidence is recorded in the dated development
log rather than copied here as a count that immediately becomes stale. The
canonical completion commands are `cargo xtask ci`, `cargo xtask msrv`,
`cargo xtask doctor`, and `cargo xtask extended`; supply-chain output retains
reviewed duplicate-version and four transitive unmaintained warnings.

## Non-negotiable boundaries

- Production application/runtime code is Rust.
- There is no process-global active workspace authority.
- Durable semantic state will not exist only in memory: Location metadata is
  global-registry authority, while Workspace/Activity semantics are
  Workspace-local SQLite authority.
- A Workspace candidate index is window-local UI state. Only a successfully
  revalidated and committed `WorkspaceId` is durable selection evidence, and
  even that identity cannot authorize filesystem, process, network, or other
  effects without a later explicit capability.
- Deterministic domain logic does not read hidden filesystem, network, clock, random, process, UI, or SQLite state.
- Slint remains a read/control projection; Tokio and effect adapters do not block the UI thread.
- Commit and push are explicit operator actions.
