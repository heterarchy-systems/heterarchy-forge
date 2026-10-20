<p align="center">
  <img src="./docs/assets/hf-image.png" alt="Heterarchy Forge workspace" width="100%" />
</p>

# Heterarchy Forge

[![CI](https://github.com/heterarchy-systems/heterarchy-forge/actions/workflows/ci.yml/badge.svg)](https://github.com/heterarchy-systems/heterarchy-forge/actions/workflows/ci.yml)
[![Releases](https://img.shields.io/github/v/release/heterarchy-systems/heterarchy-forge?include_prereleases)](https://github.com/heterarchy-systems/heterarchy-forge/releases)

Heterarchy Forge is a GUI-less, Rust-only execution and evidence backend: typed HTTP JSON commands and resumable SSE over loopback, with no GUI surface in the product.

The product is being built from the accepted V1 architecture in Alexandria. The
current verified foundation includes a typed runtime lifecycle, owned Tokio
background runtime, structured logging, an addressable backend host, explicit
Location/Workspace flows, and the canonical Rust `xtask` quality gate.

## Accepted migration target (2026-09-09)

The accepted target moves all GUI and external MCP
entry points, Agent/session operations, approvals, scheduling, and team
coordination into Orchestration. GroupCoordinator will be a separate module
inside Orchestration. Forge retains Workspace storage, confined source/worktree
execution, Goal/DAG, leases, Diff/checkpoint and verification evidence, exposed
through an addressable HTTP JSON backend with resumable SSE. Broker retains
generic membership, claims and fencing; its membership facade is distinct from
team elections.

The GUI retirement is now the product shape, not a migration stage: the
Slint `forge-ui` projection crate and the `forge-desktop` application crate
are removed, and the default build/run/package path is the headless backend
host. The [HTTP backend host](crates/forge-backend/README.md)
provides typed commands, resumable SSE, and remote Orchestration session
resolution. Explicit host Rust CI configuration prepares the existing isolated
toolchain and validates the selected cleanup root before admission. Verification
executes a checked copy of its retained snapshot outside live Cargo ancestry.
The current worktree exposes 111 backend operations; the Forge MCP crate and
desktop MCP server host are removed, and full API/consumer parity and
deployment recovery remain incomplete.
The capability descriptions below retain some
historical MCP terminology; they do not describe an available Forge MCP server.
Goal/DAG deletion and durable cleanup recovery preserve
shared checkpoints and pending-request readback.
Architecture and feature plans are saved in Alexandria under Agent Platform,
Architecture and Plans / Heterarchy Control Plane Cutover / 2026-09-09.

## Current implemented foundation

```text
Cargo workspace
├─ crates/forge-domain       # typed Location, Workspace, Activity, runtime domain
├─ crates/forge-workspace    # Location discovery, Workspace resolution, state layout
├─ crates/forge-persistence  # global Location registry + Workspace-local SQLite
├─ crates/forge-control      # bounded transport/UI-neutral application control plane
├─ crates/forge-backend      # standalone typed HTTP commands + durable SSE
├─ crates/forge-execution    # macOS sandbox prototype + owned process supervision
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
- Filesystem, Git, SQLite, and process effects stay behind Rust adapter
  boundaries with typed errors and bounded ingress/output.
- Runtime projections use owned Tokio tasks and a bounded/latest-value transport
  so a slow observer cannot create unbounded backlog.
- The backend doctor boots the real headless product path: init-registry,
  serve on loopback with file-backed bearer secrets, a real `/healthz` and
  `/readyz` probe, and bounded graceful SIGTERM shutdown inside a throwaway
  sandbox.
- The platform boundary retains the macOS `objc2` adapters from the desktop era
  (folder picker, clipboard, Keychain-backed MCP token stores); they have no
  backend consumer and their retirement is a tracked decision pending review.
- Bounded request handling keeps filesystem/database work off any interactive
  thread. Add Location, durable Location list projection,
  Workspace discovery, and durable Workspace establishment are implemented.
  Selection happens through explicit registration flows; there is no window-local
  candidate state in the product.
- Location state uses schema-v2 revision CAS. Workspace/Activity records use
  independent typed revisions and fail-closed root fingerprints. A committed
  Workspace selection is still not a filesystem/process/network effect grant.
- Workspace-local state initialization serializes concurrent writers and writes
  exact nested-worktree rules to `.git/info/exclude` without modifying tracked
  `.gitignore` files.
- The official `rmcp 3.1.4` server exposes exactly 61 tools. The surface covers
  durable Workspace list/discovery/resolve, Activity bootstrap, bounded source
  list/search/slice/patch, Diff evidence, Agent list/focus/work/context,
  logical session issuance, assignment lifecycle and inbox reads,
  Coordinator reads/claims, Goal create/revise/list/
  get, current DAG planning, Location list, and the exact command/execution
  lifecycle `command_list`, `command_run`, `execution_get`, `execution_cancel`,
  `execution_read`, and bounded long-poll `execution_wait`. Planning belongs to the durable Activity-local
  Coordinator, not to a declared role or a transport token. Initial plans and
  immutable successor DAG revisions are fenced by exact Coordinator, Goal, and
  DAG-head revisions. Node start/complete also require a current bound session.
  The analyzed `shell_run` surface uses server-owned execution profiles; callers
  cannot override executable, argv, environment, permission, or network policy.
  Workspace operations carry an exact Location revision and Workspace
  locator/identity. File effects additionally require a tracked live Activity,
  bound session, current node focus, and Writer Lease;
  bounded history reads do not silently promote process ownership.
- Open one logical session with `agent_session_open { request_id }`, retain the
  returned non-secret `session_id`, and reuse it across reconnects and Activity
  work bindings. Retrying the same issuance request preserves identity.
  Transport sessions and OAuth grants do not identify a Chat. Operational
  membership belongs to Orchestration; Forge activation requires the exact
  delegated membership receipt and keeps historical bindings readable.
  The retired `agent_attach`, `agent_detach`, `agent_handoff`,
  `agent_session_touch`, and `agent_inbox_ack` tools are absent. New work still
  requires current node focus and a Writer Lease. Inbox reads never acknowledge.
- `command_list` returns sealed command classes, a catalog fingerprint and
  current runtime availability. Catalog inspection remains available when the
  Rust runtime is unavailable; execution still fails closed.
  `command_run` requires `expected_catalog_fingerprint`; actual execution admission
  checks it again after approval. `make:package` is a distinct generated command
  requiring approval and writes only to its execution-specific product cache.
  A successful execution exposes a persisted package hash/size manifest through
  `execution_get`; user source and `.heterarchy-forge` are read-only to the child.
- Stdio remains the default trusted-local process transport. An explicit
  loopback-only Streamable HTTP listener uses the same 61-tool surface and
  validates Host/Origin/body bounds. Loopback callers use a durable app-global
  bearer token; a configured fixed HTTPS domain enables OAuth 2.1 discovery,
  dynamic client registration, authorization-code PKCE S256, short-lived
  access tokens, and refresh-token rotation/reuse revocation. Public-host MCP
  requests accept OAuth access tokens only. Raw bearer/code/refresh values are
  one-time reveals; SQLite stores keyed digests and typed metadata while
  separate peppers remain in macOS Keychain. A fixed domain relies on the
  operator-installed Cloudflare Named Tunnel; only blank-domain development
  mode starts the bundled ephemeral Quick Tunnel.
- Activity schema v2 separates durable Open/Closed/Interrupted state from a
  process-owned runtime lease. Heartbeats and graceful close are grouped into
  one bounded transaction per Workspace; expired leases reconcile to
  Interrupted and cannot be silently reattached.
- WorkspaceStore schema v34 retains metadata-only, Activity-attributed ChangeSet,
  Diff Evidence, execution intent/terminal/output records, approval authority
  with exact Agent binding, checkpoint/restore journals, Harness state, stable
  authenticated Agent attachment, and Activity-local Coordinator planning
  authority. Redacted Diff bodies remain bounded Workspace-local
  `.diff.zst` artifacts with exact compressed/uncompressed BLAKE3 hashes and
  sizes rather than SQLite BLOBs. A Starting/Intent pair is recovery evidence
  and is never replayed automatically. Older Workspace schemas are rejected
  without rewriting them; FORGE only opens the current schema as authority.
- Goal DAG persistence uses immutable revision/head/node/edge storage with exact
  SQL validation and no synthetic reconstruction of missing authority.
  The pure domain already rejects cycles, self/duplicate/unknown edges and
  derives ALL-of readiness deterministically. Persistence now provides immutable
  revision insertion/readback, head CAS, current-head-only node lifecycle CAS,
  completed-node/evidence carry-forward, atomic source+Goal+node evidence
  admission, typed split/replace/merge lineage, and a Goal completion gate.
  Trusted-local control and bounded worker dispatch are active with explicit
  revision/head/node requests and shutdown rejection. Planning submits flow
  through the authenticated current Coordinator while the durable projection
  remains read-only to every consumer.
- Durable Goal contracts are active in trusted local control. Goals are
  Activity-scoped, contract-revision-CAS guarded, restart
  durable, and explicitly lifecycle controlled. Hard completion
  recomputes bounded linked Approval/Execution/ChangeSet/Checkpoint evidence in
  the write transaction and verifies `FilePresent` requirements through the
  descriptor-confined Workspace boundary before that transaction. Effect
  admission associates Goal evidence atomically; Goal-linked Diff artifacts are
  excluded from retention and tombstone races. A Goal creates no background
  task, scheduler, implicit continuation, or execution authority. Substantive
  Agent execution requires an exact Goal/current-DAG/active-node focus, and MCP
  uses the current 61-tool surface described above.
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
- `--doctor` variants inspect an existing Global Registry before any
  Application Support creation, logging initialization, or write-capable open.
  A missing Registry is a truthful `NOT_INITIALIZED` warning and an active
  Registry WAL fails closed without touching sidecars. Repository `xtask doctor`
  boots the headless backend inside an isolated HOME/sandbox registry and
  proves health, readiness, and graceful shutdown, so canonical verification
  never reads or mutates operator state.
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
  size and refuses any conflicting DB ownership.
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
- Execution evidence uses the current exact schema, revision CAS, and
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
  are drained. MCP command and analyzed shell execution use the current bounded
  admission and approval paths described above.
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
- Activity projection is explicit about liveness: only fresh leased Open
  Activities are Live; Closed/Interrupted/recovery records surface as History.
  An expired Open lease is projected as explicit `Expired` history and is not
  rewritten to `Interrupted` merely because an observer refreshed; semantic
  reconciliation stays behind the separate trusted recovery operation. Change
  reads stay bounded (at most 50 durable changes per selection equivalent) and
  every Diff read is a verified read-only evidence query with explicit
  binary/oversized/missing/corrupt states.
- The Slint workbench projection (adaptive three-region topology, Inspector,
  Harness read-only observation surface, UI quality passes, and the checked-in
  screenshot corpus) was retired with the `forge-ui`/`forge-desktop` crates.
  Every capability it only projected remains available through the backend
  operations listed above; nothing was retired from the control plane itself.
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
cargo xtask package
cargo run --locked -p forge-backend -- init-registry /absolute/path/registry.sqlite3
cargo run --locked -p forge-backend -- serve /absolute/path/backend.json
```

For a verification run with an explicit existing temporary directory, set
`FORGE_VERIFY_TMPDIR`. The xtask forwards it as Cargo command-line configuration
to every child Cargo, including when an inherited `[env]` entry forces another
`TMPDIR`. The outer Cargo also needs that override when launching xtask:

```bash
FORGE_VERIFY_TMPDIR=/absolute/task/tmp \
cargo --config 'env.TMPDIR.value="/absolute/task/tmp"' --config env.TMPDIR.force=true xtask ci
```

This opt-in setting requires a real absolute directory and changes only the
verification process temporary path. It does not edit Cargo configuration,
select Cargo/Rustup homes, alter product startup storage policy or skip gates.

The [backend host instructions](crates/forge-backend/README.md) specify exact
Registry, Workspace, backend/destination identity and separate service credentials.
External MCP ingress and logical-session issuance belong to Orchestration.

`cargo xtask doctor` boots the headless backend product path inside a
throwaway sandbox: build, init-registry, real loopback serve, `/healthz` and
`/readyz` probes, and bounded graceful SIGTERM shutdown.
The reviewed `deny.toml` policy requires current `cargo-deny` and
`cargo-audit`; the final local evidence used versions 0.20.2 and 0.22.2.
`cargo xtask perf` deliberately reports `unconfigured` until a reviewed
benchmark target and workload exist; that result is not a performance PASS.

### Local backend package

`cargo xtask package` builds the locked release `forge-backend` binary and
assembles a bounded tarball with the binary and the operations guide:

```text
dist/forge-backend-v<version>-<os>-<arch>.tar.gz
dist/forge-backend-v<version>-<os>-<arch>.tar.gz.sha256
```

There is no installer and no GUI bundle; unpack the tarball and follow
`OPERATIONS.md` inside it.

### GitHub Releases

Public macOS arm64 backend builds are published from Git tags by
`.github/workflows/release.yml`. Download the versioned backend tarball and
`SHA256SUMS.txt` from:

https://github.com/heterarchy-systems/heterarchy-forge/releases

The release workflow is fail-closed: a tag must exactly match the workspace
Cargo version (`v<version>`), `make ci` must pass, and only then is the
versioned backend tarball attached to the GitHub Release. To publish a version,
update the workspace version, land it on `main`, then create and push the
matching tag, for example `v0.2.0`.

The backend product slices not yet complete: production Linux
execution/deployment evidence, production CAS restore authority, two-endpoint
source move with ChangeSet/Diff/checkpoint recovery, automatic Diff retention
policy, and the remaining Orchestration consumer cutover. The retired Forge MCP
server, Slint workbench, and desktop Connection/token lifecycle are
unavailable. Durable Agent work bindings, explicit Goal/current-DAG reads,
Activity-local Coordinator-authorized DAG planning/replanning, durable Activity
lifecycle, and descriptor-confined file listing, literal text search, ranged
source reads, and Add/Update/Delete source patch boundary are active. The
low-level local command engine, Plan 07 grant path, sealed command catalog,
and analyzed shell execution remain available through backend operations.
Callers cannot override server-owned execution profiles. Exact verification
evidence is recorded in the dated development log rather than copied here as a
count that immediately becomes stale. The canonical completion commands are
`cargo xtask ci`, `cargo xtask msrv`, `cargo xtask doctor`, and
`cargo xtask extended`; supply-chain output retains reviewed duplicate-version
and four transitive unmaintained warnings.

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
- The backend is the only product surface: HTTP JSON/SSE over loopback, with no
  GUI projection layer in the workspace.
- Commit and push are explicit operator actions.
