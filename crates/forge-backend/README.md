# Forge HTTP backend

This crate provides typed HTTP JSON commands and resumable SSE over the existing
Forge control worker. The standalone host uses Orchestration's logical-session
authority. HTTP API parity and deployment cutover are still in progress; the
capability endpoint lists the operations implemented by the current binary.

## Start the two services

Use an existing Forge Registry and an existing Orchestration session catalog.
These service entrypoints reject missing catalogs; they do not bootstrap a new
workspace or issue a logical session. Keep both service credentials in private
files and use a different credential for each direction.

From the Orchestration checkout:

```sh
cargo run --locked -p heterarchy-orchestration-mcp -- \
  session-authority serve 9101 \
  --catalog /absolute/path/orchestration-sessions.sqlite3 \
  --secret-file /absolute/path/session-service.secret
```

The session authority binds to loopback and prints
`session_authority_endpoint=http://127.0.0.1:9101`. Port `0` selects an available
port. Use that actual numeric address in the Forge configuration:

```json
{
  "listen": "127.0.0.1:9102",
  "registry_path": "/absolute/path/registry.sqlite3",
  "product_cache_root": "/absolute/product/cache/rust-ci",
  "backend_id": "00000000-0000-0000-0000-000000000001",
  "issuer_id": "00000000-0000-0000-0000-000000000002",
  "destination_id": "00000000-0000-0000-0000-000000000003",
  "api_bearer_file": "/absolute/path/forge-api.secret",
  "session_authority": "127.0.0.1:9101",
  "session_bearer_file": "/absolute/path/session-service.secret"
}
```

Use the backend and issuer identities selected for the deployment. The values
above illustrate the JSON shape; they do not establish approval authority.
From the Forge checkout:

```sh
cargo run --locked -p forge-backend -- serve /absolute/path/backend.json
```

Forge prints its bound numeric address. Both endpoints are loopback-only. The
host accepts at most 64 KiB of configuration and 4 KiB per credential file, with
an optional single trailing LF or CRLF. Registry and credential paths must be
absolute; unknown configuration fields and nil identities are rejected. The required
`product_cache_root` is the same host-owned isolated Rust CI cache used by execution
(normally `AppPaths::rust_ci_cache_root()` in native composition). It is passed
explicitly by embedded hosts and is never accepted in an HTTP command payload.

Standalone Rust CI is disabled unless the strict optional `rust_ci` object is
configured with absolute `host_home` and `local_cache_root` paths. For example:

```json
"rust_ci": {
  "host_home": "/Users/example",
  "local_cache_root": "/Users/example/Library/Caches/forge/rust-ci"
}
```

The existing storage policy attempts the SSD view four times before selecting
the local `rust-ci-1.98.0-local` sibling. `product_cache_root` must exactly match
the selected canonical view; unavailable inputs or a mismatch stop startup.
Preparation runs under the serve fence before admission. The capability response
reports `execution.rust_ci_available`; enabling it does not issue approvals or
grant execution authority. Commands still require the current session and grant.

Verification retains its durable Workspace snapshot and runs a validated copy
under the isolated execution cache, outside the live Workspace's Cargo ancestry.
The sandbox denies source writes and live Workspace reads. The copy is checked
against the retained manifest before and after execution, then removed through
the existing runtime cleanup path after confirmed process-group termination.
Replica directory modes match the sealed snapshot; cleanup changes those
permissions only through the owned runtime descriptors after termination.
The retained native Desktop carries an absent cleanup-root authority when its
toolchain is unavailable. Package cleanup then remains pending with
`product_cache_unavailable`, preserving the artifact until a known root is
available; SQL-only and Workspace-local cleanup continue normally.

## Authority and lifecycle

Optional host-owned Activity lease renewal and same-Activity restart recovery
are described in [Activity lease supervision](activity-lease-supervision.md).

The capability endpoint reports the current command surface:

| Operations | Behavior |
| --- | --- |
| `location.list`, `location.register`, `location.state` | Observe and manage explicit revision-fenced Location registrations. |
| `location.removal_probe`, `location.remove` | Observe or remove a registered Location-root listing/state through the existing confined owner; direct-child Workspace deletion and process stop are separate. |
| `workspace.list`, `workspace.discover`, `workspace.doctor` | Observe registered Workspaces, discover candidates and read bounded diagnostics. |
| `workspace.registration_probe`, `workspace.register` | Read current identity without mutation, or explicitly establish/open a physically fenced root through the shared application owner. |
| `workspace.inventory` | Read all registered root/direct-child Workspaces plus per-candidate diagnostics. Startup recovery uses this inventory. |
| `workspace.resolve` | Resolve the explicit Location/Workspace revision. |
| `goal.list`, `goal.read`, `dag.read_current` | Read full Goal contracts and DAG nodes, readiness, dependencies, lineage and evidence counts. |
| `goal.create`, `goal.revise`, `goal.transition`, `goal.complete` | Apply Coordinator-fenced Goal changes with immutable request receipts. |
| `goal.delete`, `goal.delete_pending` | Apply generation-fenced native Goal/DAG cleanup and observe bounded pending journals. |
| `goal.review`, `goal.mutation_readback` | Inspect completion checks or the exact historical Goal mutation receipt. |
| `dag.plan_commit`, `dag.plan_readback` | Commit a full bounded DAG draft or observe the existing planning ledger. |
| `node.assignment_read` | Read exact Goal/DAG/node metadata, its active assignment and current DAG head in one SQLite snapshot. |
| `agent.assignment_offer_seal`, `agent.assignment_offer_seal_get` | Seal future admission for one exact Activity/Assignment key and read back the seal plus the current global Assignment row. |
| `node.start`, `node.complete` | Apply the existing authority-checked node transitions. |
| `command.list` | Read the sealed command catalog and fingerprint. |
| `command.submit`, `shell.submit` | Submit exact session-bound command/shell requests through the host-owned approval coordinator. Submission is separate from an execution success receipt. |
| `approval.get`, `approval.pending` | Read an exact approval audit or bounded pending projection; pending observation reconciles only elapsed authority through the existing owner. |
| `execution.begin`, `execution.read`, `execution.output`, `execution.cancel` | Start preapproved execution through the approval application owner and execution admission owner, read bounded binary-safe output, and cancel with current session and provenance checks. |
| `execution.stop_workspace`, `execution.stop_workspace_get` | Capture one exact Pending execution/approval/grant/auto-scope stop through the existing administrative owner, request native cancellation, and observe the original paired receipt without repeating cancellation. |
| `execution.get`, `execution.wait` | Read native execution metadata with generated evidence in one authorized snapshot, or wait asynchronously for bounded output/progress. |
| `diff.read` | Read full durable Diff evidence and verified text content, or explicit missing/corrupt/summary health. |
| `diff.inventory` | Read100 compact Activity-scoped GUI rows with exact scope, revision and aggregate metadata; selected full evidence remains in diff.read. |
| `diff.list`, `diff.doctor`, `diff.retention_plan`, `diff.artifact_doctor` | Read bounded Diff inventory, metadata/artifact diagnostics and retention plans. |
| `verification.projection` | Read bounded verification evidence and actual run disposition. |
| `execution.inventory`, `execution.observe` | Issuer/operator read-only Activity/Goal-scoped execution metadata and actual Verification evidence; selected bounded output comes from the same SQLite snapshot. |
| `activity.bootstrap`, `activity.successor_create`, `activity.successor_get`, `activity.coordinator_get`, `activity.coordinator_claim` | Bootstrap and observe work Activities and manage session-fenced successor/Coordinator work facts. |
| `activity.list` | Read server-timed, bounded Activity lifecycle/liveness projections for one exact Workspace locator, UUID and revision. |
| `activity.get`, `activity.close` | Read one exact Activity or administratively close the current runtime-owned lease with exact owner/revision CAS and typed uncertain-outcome readback. |
| `activity.lease.renew`, `activity.lease.release`, `activity.lease.renew_batch`, `activity.lease.release_batch` | Renew or release exact caller-owned lease revisions through the dedicated bounded lane, preserving native atomic batch order and rollback. |
| `recovery.lease.get`, `recovery.lease.claim`, `recovery.lease.renew`, `recovery.lease.release` | Observe or manage the native Workspace maintenance fence through owner/epoch/revision checks; these lease-only operations do not run classification. |
| `recovery.maintenance.run`, `recovery.maintenance.get` | Atomically classify expired authority and record exact immutable request/cohort/lease evidence, or read the original historical receipt without classification. |
| `queue.status`, `workspace.queue.status`, `workspace.queue.settings` | Read actual runtime queue counters and separate saved/effective Workspace preference under exact pre/post scope validation. |
| `workspace.queue.settings.replace` | Persist an exact Workspace preference CAS and retain the committed record alongside a separate, fenced runtime observation. |
| `agent.list`, `agent.get_context`, `agent.coordination_get`, `agent.inbox_list`, `agent.set_focus`, `agent.publish_work` | Observe work bindings and update session-fenced focus/work evidence; logical session issuance remains external. |
| `agent.assignment.mutate`, `agent.assignment.get`, `agent.assignment.list` | Apply tagged assignment mutations and observe current assignment records through existing control authority. |
| `agent.operations.delegate`, `agent.operations.delegation_get` | Seal the trusted destination manifest against an exact existing source freeze, or observe the durable delegation. |
| `agent.operations.freeze`, `agent.operations.freeze_get`, `agent.operations.export`, `agent.operations.freeze_release` | Create or replay the source freeze, read its exact durable row, read bounded frozen-source pages, or release the pre-delegation fence with exact revision/timestamp CAS. |
| `agent.binding.reserve`, `agent.binding.reservation_get` | Reserve an immutable future binding or observe its receipt under current session authority. Reservation creates no active Agent or work rights. |
| `agent.binding.activate`, `agent.binding.activation_get` | Activate the reserved binding through the existing delegated owner or observe its immutable receipt. |
| `agent.session.reconcile`, `agent.session.reconciliation_get` | Reconcile an existing Agent session with native revision fences or observe its immutable receipt. |
| `agent.departure.reconcile`, `agent.departure.reconciliation_get` | Apply tagged detach/handoff through native session and Coordinator fences or observe its immutable receipt. |
| `effect_fact.outbox` | Read the immutable destination-fenced work/effect fact outbox. |
| `file.list`, `text.search`, `file.read_slice` | Perform bounded confined source reads through Forge control. |
| `writer_lease.acquire`, `writer_lease.renew`, `writer_lease.release`, `writer_lease.get`, `writer_lease.list` | Manage revision-fenced Writer Leases and read bounded scope pages. |
| `writer_lease.recovery_release` | Perform the control-owned expired/orphaned lease recovery with exact revision checks. |
| `work_cut.inventory`, `work_cut.prepare`, `work_cut.get`, `work_cut.drain` | Observe attested work inventory, capture bounded leadership custody, read its immutable receipt, or observe captured effects settling. Drain grants no custody release. |
| `file.apply_patch` | Apply one bounded Add, Update or Delete through the existing source authority. |
| `source_tree.apply`, `source_tree.readback` | Apply a bounded journaled tree mutation group and observe its historical result. |
| `file.mutation_readback` | Observe the recorded outcome and Diff identity of one historical file mutation. |

All ten delegated Agent lifecycle payloads carry `scope`, `issuer_id` and
`destination_id`. The authenticated service issuer and configured destination
must match before a control call. These IDs are selectors and fences; they do
not authenticate the caller. The service credential must belong to the trusted
Orchestration composition that verifies manifest and membership attestations.
Forge does not issue logical sessions or membership through these endpoints.

Freeze references contain `migration_id` and `expected_freeze_revision`;
delegation references also contain the exact 32-byte hex `manifest_digest`.
Forge resolves its existing durable freeze/delegation and checks the Workspace,
destination, revision and digest. The API cannot create a freeze or construct
opaque authority from a caller-supplied status. Reserve, activate and reconcile,
including their receipt reads, require current session/principal authority.
Receipt reads return `found` with immutable fields when present. An absent
receipt does not authorize retrying an uncertain mutation. Lost admitted replies
carry operation-specific readback keys; callers retain their original principal
and use those keys to inspect durable state before deciding what to do next.
Departure closes or hands off the native binding; it does not implicitly cancel
an execution or change logical membership.

The four source-migration operations are the bootstrap exception to the
existing-freeze-only delegation boundary. They remain service-bearer and
destination-fenced, re-resolve the current Workspace scope through
`forge-control`, and return the source Workspace/migration/destination/revision
identity on every success. Export is a bounded observation over the five typed
source record families and never computes a digest or advances a cursor. A lost
admitted freeze or release reply is `UNKNOWN_OUTCOME` with the migration
readback identity; callers read `agent.operations.freeze_get` before retrying.

`workspace.registration_probe` takes a lossless encoded `locator` from the
existing WorkspaceLocator codec (`hf1:<location UUID>:<revision>:<URL-safe
unpadded Base64 native relative path>`). It reads current root fingerprint and
optional Workspace metadata without creating state, changing Git excludes or
migrating SQLite. Absence is current observation, never a historical non-commit
receipt. Native root paths in replies use `root_path_base64`.

`workspace.register` takes the same `locator`, `expected_root_fingerprint`
(32 hex characters), non-nil `proposed_workspace_id`, and `observed_at_ms`.
The proposed UUID applies only to a fresh store; an existing registered root
retains its actual UUID/revision/timestamps. The application checks Location,
candidate eligibility and physical fingerprint before initialization, then
revalidates read-only after commit. A post-commit replacement never initializes
the replacement directory. `status: "committed_but_unconfirmed"` and
`confirmed: false` preserve the actual committed record while withholding a
confirmed selection. They do not grant source or execution authority.
Lost replies and potentially partial initialization/upgrade errors carry
`UNKNOWN_OUTCOME` with original locator/proposal/fingerprint readback guidance;
read current state and authority before retrying.

`workspace.inventory` takes `location_id` and `expected_revision`. It returns
registered root/direct-child entries in root-first/native-path order plus
explicit unavailable diagnostics for corrupt/foreign/duplicate identities.
Uninitialized candidates are omitted without mutation. This wider inventory
feeds standalone startup recovery, so registered child Workspaces are no
longer skipped. `workspace.list` retains its existing exact-Location-root
contract for current consumers; inventory is the all-registered query.

`activity.list` takes an encoded `locator`, non-nil `workspace_id`, positive
`workspace_revision`, and `limit` in `1..=256`. It validates the Location and
Workspace through the existing control owner and echoes the resolved scope.
Observation time is server supplied; the operation does not bootstrap,
heartbeat, close or recover Activities. Rows retain their durable lifecycle,
revision, timestamps and lease fields, with distinct Available/Live/Expired
Open projections. GUI Live rows require both Open state and Live liveness.

`node.assignment_read` takes `scope`, `goal_id`, positive `dag_revision`, and
`node_id`. A missing Goal, revision or node returns `found: false`. A found
node includes its Activity, Goal creation timestamp (`goal_created_at_ms`),
Goal and node revisions, current DAG/head revisions,
and the exact Offered, Running or Submitted assignment when present, including
its target Agent/session and cancellation flag. Historical nodes remain readable;
consumers must compare the requested revision with `current_dag_revision` before
sending new work. This observation grants no assignment or work authority.

`agent.assignment_offer_seal` and `agent.assignment_offer_seal_get` take the
exact Coordinator `authority`, `assignment_id`, and `observed_at_ms`. Both are
session-bound; Forge revalidates the Coordinator session and current Activity
Coordinator. The seal is a future-admission fence and creates no work authority.
Get returns `found: false` only when no seal row exists; that result proves
nothing about assignment history or current presence. A found reply with
`state: "absent_now_sealed"` and a null `present_registered_assignment` means
the global Assignment row is currently absent while fresh offers for that
Activity/ID are permanently blocked. It does not mean the assignment was never
offered or completed. When a row is present, `present_registered_assignment`
reports its actual `activity_id` and `activity_relation` (`same_activity` or
`foreign_activity`). Readback also preserves the first sealer authority kind
and Coordinator agent/session/revision; it returns no report or credential data.

Commands use `POST /api/v1/commands/{op}` with the envelope
`{"forge_api":1,"request_id":"<uuid>","op":"<op>","payload":{...}}`.
The URL and envelope operation must match.

Source-read payloads share `scope` and `activity`. Scope contains
`workspace_id`, `workspace_revision`, and a `locator` object with `location_id`,
`expected_revision`, and `relative_root`. Activity contains `activity_id`,
`runtime_instance_id`, and `observed_at_ms`. Source results return the same
scope shape. The existing control boundary revalidates the supplied scope and
Open Activity; the transport does not access the filesystem directly.

- `file.list`: optional `directory_base64`, `max_results`, `max_output_bytes`.
- `text.search`: literal `query`, optional `root_base64`, `max_results`,
  `max_output_bytes`.
- `file.read_slice`: `path_base64`, one-based inclusive `start_line` and
  `end_line`.

Path tokens use canonical URL-safe base64 without padding over native relative
path bytes. Absolute, parent, empty, and noncanonical paths are rejected.
Omitted read bounds use the existing domain defaults. Slice replies retain exact
UTF-8 content, separate whole-file/range/line hashes, and EOL values
`lf`, `crlf`, `cr`, `mixed`, or `none`. No lossy content conversion is used.

Writer Lease mutations take `scope`, `activity_id`, `actor` (session/principal/
agent IDs), and `writer_lease_id`. Acquire additionally takes `duration_ms` and
`scopes` entries with `kind` (`exact_path` or `directory_subtree`) and
`path_base64`. Renew takes `expected_revision` and `duration_ms`; release takes
`expected_revision`. The valid duration is 1,000–300,000 ms. Caller timestamps
and absolute expiry are not accepted. The control worker refreshes observation
time after queue admission, preserving duration.

Get accepts `scope`, `writer_lease_id`, optional `expected_revision` and
`scope_offset`. List accepts `scope`, optional `cursor` and a `limit` of 1–4.
Each returned lease contains at most four scope entries and a
`next_scope_offset` for subsequent get calls. Lease state is durable: an
`active` lease can already be expired according to `lease_until_ms` and remains
a conflict fence until release/recovery. Observation does not grant write authority.

`file.apply_patch` takes `scope`, `activity`, an `actor` with session/principal/
workspace/Agent ID and expected Agent revision, exact Goal/DAG/node IDs and
revisions, Writer Lease ID/revision, ChangeSet ID, mutation ID, and a tagged
`operation`. Activity observation time is refreshed by the control worker after
admission. The operation is one of:

- `add`: `path_base64` and UTF-8 `content`.
- `update`: `path_base64`, `expected_whole_file_hash`, and `hunks` containing
  one-based inclusive `start_line`/`end_line`, `expected_range_hash`, and exact
  UTF-8 `replacement` text.
- `delete`: `path_base64` and `expected_whole_file_hash`.

Hashes use the canonical domain format returned by `file.read_slice`. NUL text,
noncanonical/conflicting paths and invalid/overlapping hunks are rejected.
Compact JSON payloads are limited to 16 KiB before typed decoding; the outer
HTTP envelope retains the configured 1 MiB transport ceiling. The domain also
bounds source size to 1 MiB and hunks to 128. Hash and source-request conflicts
return `SOURCE_CONFLICT` (HTTP 409) with source-read recovery guidance.
Source-size/output limits return non-retryable `CAPACITY_EXCEEDED` (HTTP 503);
reduce the requested work instead of retrying the same mutation.

A successful command response preserves mutation status (`applied`,
`already_applied`, `recovery_required`, or `terminal_failed`) and PRE/POST
metadata. `ok` means the command returned a result; callers must inspect
`status` to know whether the file effect applied. A committed-but-unconfirmed
result becomes `UNKNOWN_OUTCOME`, carrying the exact mutation readback identity.
No response grants automatic retry authority. In particular, replaying an
Update is rejected because its original hunks/request digest are not persisted.

`file.mutation_readback` takes current `scope` plus original `activity_id`,
`change_set_id`, and `mutation_id`. It reads the journal and optional Diff
metadata from one database snapshot without requiring the original lease to
remain active. `retry_authorized` and `request_equivalence_proven` are false:
the stored fields do not prove an identical resubmitted Update patch. A missing
record does not establish that an admitted operation can never commit later.

Unknown-outcome replies carry a tagged `readback` identity (`execution`,
`writer_lease`, `file_mutation`, or `tree_change_set`) from the admitted request. A lease operation never receives a
fabricated execution ID. Read the exact identity before deciding the next
action; mutation requests are not automatically retried. The `file_mutation`
hint contains Workspace, Activity, ChangeSet and mutation IDs; retain the
original exact scope to call `file.mutation_readback`.

`source_tree.apply` uses the same flat source-authority fields as
`file.apply_patch`, with `change_set_id` and `mutations` instead of a single
`mutation_id`/`operation`. The strict mutation kinds are `create_directory`,
`create_file`, `update_file`, `patch_file`, `delete_file`, `move_file`,
`move_directory`, and `delete_directory`. Each has a unique non-nil
`mutation_id` and `path_base64`, or `source_base64`/`destination_base64` for
moves. Hash and patch fields match the single-file operation. Whole-file
create/update content is at most 8 KiB. There are at most 256 mutations, within
the 1 MiB HTTP envelope/payload ceiling and existing domain aggregate bounds.

The caller cannot supply a request digest. MCP and HTTP derive the same
canonical digest from the ordered typed mutations through Forge control.
Responses and `tree_change_set` unknown-outcome hints retain that digest with
the Workspace/Activity/ChangeSet identity. Exact native replay still requires
fresh current source authority; it is not an automatic retry policy.

Tree effects are journaled individually; the operation does not promise an
all-or-nothing filesystem rollback. `applied_mutations` contains journal-
acknowledged progress. If a filesystem effect or its journal acknowledgement
is uncertain, `uncertain_mutation` identifies that mutation and status remains
`recovery_required`. A later durable observation can resolve that uncertainty.

`source_tree.readback` takes current exact `scope`, original `activity_id` and
`change_set_id`, plus optional `expected_request_digest` as 64 lowercase hex
characters. ID-only observation supports a caller that lost the entire write
response. A supplied digest must match. The read uses one SQLite snapshot for
the persisted request/header, bounded mutation flags and optional Diff, then
revalidates scope/root. It needs no live source lease or session and grants no
retry authority. It reports journal-confirmed IDs, not inferred filesystem
completion for unmarked rows. `found:false` means no supported source-tree
request journal was observed; it does not prove a prior effect cannot commit or
that an older generic tree ChangeSet never existed.

Planning writes use nested `authority`: `scope`, `activity_id`, and `actor`
with `session_id`, `principal`, `agent_id`, and `expected_coordinator_revision`.
The existing control/SQLite owners validate current session and Coordinator
identity; these fields are not grants by themselves.

Goal writes take caller-visible `mutation_request_id`, `goal_id`, and
`observed_at_ms`. Create adds a bounded `contract`; revise adds the expected
Goal revision and replacement contract; transition takes the expected Goal
revision and a tagged pause/resume/block/fail/cancel action. Complete takes the
expected revision and `review_id`, and obtains its own actual evidence review.
Callers cannot provide a passing review or a request digest. `goal.review`
returns current hard checks, blockers and manual-assessment information.

Schema49 adds immutable request receipts in the same transaction as Goal state
and semantic events. The canonical digest covers the full semantic command,
including actor, revisions, ordered contract fields and observation time.
Exact replay needs the original unchanged command and current write authority;
changed intent with the same request ID conflicts. Fresh request IDs do not
claim creation of an already-existing Goal. Mutation replies separate the
original `receipt` from `current_goal`, which can be newer, recreated, or absent
within the original Activity scope. Never treat it as the original snapshot.

`goal.mutation_readback` takes current `scope`, original `activity_id`,
`goal_id`, `mutation_request_id` and optional `expected_request_digest`.
Historical readback requires no current session/Coordinator and grants no retry
authority. Receipts survive Goal deletion; a new generation of the same Goal
UUID uses a new mutation request ID and can start at revision1. Unknown replies
carry the exact Goal request identity and digest before admission.

`dag.plan_commit` takes the same planning authority plus `plan_request_id`,
Goal ID/revision, optional expected parent/head, history ID/sequence,
observation time and full bounded `draft` (revision ID/number, nodes with
acceptance/lifecycle, edges and lineage). Its digest is derived from the native
draft. `dag.plan_readback` takes scope/Activity/Goal/plan request IDs and optional
`expected_draft_digest`, and returns the existing immutable ledger metadata
without inventing a replay flag. The existing cleanup policy removes DAG
planning ledger rows on Goal/DAG deletion; a missing record is not proof the
request never committed. The new Goal mutation receipts do not change that
separate retention policy.

Planning conflicts use `PLANNING_CONFLICT`. A result lost after commit retains
`UNKNOWN_OUTCOME` and a command-owned `goal_mutation` or `dag_plan` readback
hint. Do not automatically retry mutations after unknown outcomes; inspect the
original receipt and current authority first.

`/healthz` reports liveness; `/readyz` performs a bounded control-worker probe;
`/api/v1/capability` reports the API version and
supported commands. Other endpoints require the configured Forge API service
bearer. That bearer identifies the service issuer, while each session-bound
command carries its separate agent/session/principal and work authority.

Forge resolves logical sessions afresh through
`POST /internal/v1/sessions/resolve`. Closed sessions, unavailable authority,
and mismatched identities cannot fall back to Forge's local session catalog.
The remote request has a maximum five-second deadline and bounded headers/body.
Forge's existing Workspace, Activity, Agent, Goal/DAG, approval, and lease
checks remain authoritative for effects.

Ctrl-C and SIGTERM stop HTTP admission, close streams and drain admitted work,
then join the approval coordinator before stopping its execution dependency.
Pending approval cleanup and execution cancellation retain the control worker.
The control worker stops last. HTTP cleanup is observed again if work remained
pending. A failed or incomplete cleanup produces a failing process exit.
The five-second shutdown budget bounds each observation, not total process
exit. A noncancellable blocking authority worker remains owned and is joined
before its dependency stops; a budget overrun emits a pending diagnostic.
The host does not detach or forcibly abort a worker that may be committing an
effect. An operator-forced process termination still requires durable recovery.

Readiness permits remain attached to the actual blocking probe until it exits,
including after a timeout or disconnected caller. Shutdown accounts for these
probes through the same owned task tracker used for event reads; a pending probe
prevents a successful drain report. Health remains independent of readiness.

HTTP/1 ingress is owned by a bounded listener over the same Axum Router and
native SSE response types. The default is 128 admitted connection tasks, including
idle connections and SSE streams. Excess connections are immediately closed
before HTTP/application admission; there is no additional waiting queue. The
accept loop can hold one transient socket while rejecting it, in addition to
the listener and admitted connections; it allocates no request task for it. The
capability response advertises these bounds, and embedded hosts can inspect
`AppState::http_connection_stats()` for active/admitted/rejected/failed sockets.

Headers have a 32 KiB buffer, 64-header limit and absolute five-second read
deadline. Each body retains the existing 1 MiB limit with its own absolute
five-second acquisition deadline. Trickle traffic does not renew either input
deadline. Body deadline/size failures return 408/413 before application work
and close the connection; shutdown also stops incomplete body acquisition.
Admitted effects retain their existing unknown-outcome and readback semantics.
The total connection cap is shared: a request's control route cannot be known
before its headers arrive. The existing cancellation application lane remains
independent of the command bridge; privileged acceptance during total socket
saturation is not claimed.

Output writes that make no progress for five seconds close their connection.
A responsive SSE stream has no total-lifetime timeout. Shutdown stops the
accept loop, gracefully closes each owned Hyper connection and joins all
connection tasks. A pending root drain report keeps its server handle; it does
not abort admitted work to manufacture a successful shutdown.

This host does not provide public TLS ingress or proof of a complete
Orchestration/GUI consumer cutover. The Forge MCP crate has been removed from
the current worktree. The Forge desktop now has an explicit HTTP consumer mode
for Location, Workspace, Activity, Goal/review, DAG and verified Diff observations. Its default
mode still composes local control/execution/approval workers. Mutation, full verification evidence
and resumable streaming parity remain incomplete; those local owners cannot
yet be retired on the strength of the observation path alone.

Run the existing Slint surface with
`forge-desktop --backend /absolute/path/client-config.json`. The strict client
configuration is `{ "authority": "127.0.0.1:9102", "bearer_file": "/absolute/path/api.secret" }`.
The authority must be loopback and the file contains the service credential.
`--doctor` uses the same HTTP worker without opening a local Registry. A
connection or configuration failure does not switch to local authority.
Workspace selection rechecks its captured UUID, revision, root and fingerprint
before requesting server-timed Activity projections. Refresh/selection replies
are generation checked. Closing this mode joins its observation worker and
does not issue server cancellation. Read-only observation I/O checks shutdown
or a newer admitted generation at 100 ms polling intervals (connect remains
bounded to three seconds). One 32-second deadline covers the complete refresh,
including all Location inventories. Observation cancellation is unavailable
for mutations; their existing unknown-outcome semantics remain intact.
The native GUI smoke gate exercises the
real window and checks that the server's opened Activity remains unchanged;
it does not establish running-process, reconnect or mutation parity.

Interactive backend mode owns one read-only Workspace SSE worker alongside the
command observer. `GET /api/v1/snapshot` returns explicit validated `scope`,
`watermark_seq`, `retained_low` and bounded Goal/DAG summary. Snapshot and SSE
responses use nil correlation identity; command responses retain their non-nil
request identity rule. The capability's `sse.last_event_id_header` advertises
the exact `Last-Event-ID` request header. The client opens
`/api/v1/events/stream` after that watermark, with the matching header, so
commits during hydration replay.
It validates complete chunked HTTP/SSE frames and the canonical semantic digest
against the selected Workspace. Keepalive, shutdown and resync are cursor-neutral.

Scope and notice queues are capacity1; pending notices coalesce query-family
invalidations. Current state still comes from the existing typed queries, with
round-robin refresh and250ms minimum cadence. Stale-generation replies cannot
restore a closed view. Transient query failures retain last-observed identities
and output, mark them stale and retry with a1s delay. Snapshot scope rejection
clears the selected Workspace/stream epoch and reloads inventory. EOF or an
in-stream resync reads a fresh snapshot with bounded250ms–8s backoff and small
jitter; authentication or malformed protocol failure is explicitly unavailable.
The streaming parser is separate from strict one-shot command parsing. Its
headers32KiB, chunks64KiB and SSE frames16KiB are bounded, with100ms I/O polling,
10s partial-SSE-frame timeout and45s idle policy against15s keepalive.

The ignored native `backend_gui_realtime_requeries_the_updated_goal_from_durable_sse`
test mutates an actual Coordinator-owned Goal, consumes its durable SSE event,
and checks the actual revised Goal/DAG and advanced cursor in Slint without a
local Registry/source/runtime owner. Real scripted-listener gates exercise the
snapshot handoff, EOF/fresh-snapshot reconnect, idle cancellation and malformed
digest/scope rejection. Whole backend-process restart, proxy/provider delivery,
full UI command/session parity and measured performance require separate evidence.

Activity selection now loads `goal.list`; Goal selection loads the full Goal,
completion review and current DAG, followed by a full Goal readback to reject
changed contracts/lifecycle/revisions. The existing Goal rows and DAG readiness,
dependency layout and evidence-count reducer are reused. Rows retain typed
revisions, timestamps, verification requirements and lineage. `status.blocker_kind`
preserves the durable Goal blocker category; it is null for other Goal states.
No category is invented when reading a blocked Goal.

Selection changes cancel obsolete observation I/O, clear descendant detail state
and withhold stale replies. A failed Workspace refresh leaves no old selectable
frame. Goal/DAG deletion, registration and runtime-owner controls stay unavailable
in this mode until their actual command/session consumers are connected. Native
planning smoke uses a real activated Coordinator fixture and checks displayed
node readiness/waiting, exact edge endpoints and dependency columns. It does
not prove an atomic Goal+DAG snapshot or SSE replan/reconnect convergence.
Shared planning ScopeDto still requires a UTF-8 relative root; native locators
that cannot be represented losslessly return an explicit error, never a lossy
scope or local fallback. Full native-path transport parity remains outstanding.
Client response bounds retain 2 MiB for ordinary operations, with 8 MiB for a
full `goal.list` page and 16 MiB for `dag.read_current`. These accommodate the
existing domain maxima without reducing the100-Goal/128-node limits. Header,
framing, cancellation and aggregate deadline checks still apply; no unbounded
response or mutation retry is enabled.

`diff.inventory` consumes the existing100-record Activity query and returns a
compact UI projection with exact Workspace scope, Activity and Diff/ChangeSet
identity, revision, first entry, entry count, uniform/mixed kind and aggregate
line counts. It retains100 rows without serializing every path of every Diff.
`diff.read` returns full entries, attribution, payload state, actual Base64
artifact references, both hashes/sizes, renderer/redaction versions and verified
text content when available. It preserves explicit missing/corrupt/summary or
archived health instead of inventing content. The client validates scope, selected
revision/metadata, content byte count and BLAKE3 digest before showing the dialog.
Its full Diff reply limit is4MiB; inventory uses the ordinary2MiB bound.

Workspace/Activity changes clear evidence state. Closing an in-flight Diff view
supersedes only its observation and cannot cancel server work. Diff query errors
do not clear healthy Goal/DAG observations. `verification.projection` is still
workspace-wide latest-per-command; this Diff consumer does not present it as
selected-Goal verification or claim a successful verification run.

## Execution observations and Goal cleanup

The service/operator observation API is distinct from Agent execution control.
`execution.inventory` accepts `scope`, `activity_id`, optional `goal` with
`goal_id`/`expected_revision`, and `limit` (1–256). It validates the Activity and
current Goal revision in one read transaction, filters actual Goal execution
refs before the limit, and returns compact metadata with `has_more`. It never
loads stdout/stderr BLOBs into an inventory. The GUI response bound is8MiB for
256 headers, native cwd metadata and up to32 exact requirement links each.

`execution.observe` takes that same selection plus `execution_id`,
`after_sequence`, `max_bytes` and `max_events`. It binds the selected execution
and output cursor, returning immutable request/provenance, terminal counters,
VerificationInput/Run/revision/output-integrity/fingerprint, requirement links
and bounded binary-safe ledger events from one snapshot. A missing Verification
is explicit. Historical/shared Goal evidence retains its original attribution;
an accepted run describes its frozen input, not current Goal completion.

These operations use the host's existing issuer credential for observation.
They do not create an Agent/session, grant, acknowledgement, source mutation or
server cancellation. Agent execution/get/read/control keep the full authority
tuple described below. Observation does not transfer execution ownership;
server work remains owned by the backend when an observer disconnects.

The ignored native `standalone_native_rust_ci_project_command_reaches_verified_terminal`
gate checks standalone admission, terminal execution, verification, observation,
and source/cache retention with a real host toolchain and external Orchestration
session-authority binary. `generated_package_execution_survives_location_disable`
retains the backend lifecycle proof for a running generated-package execution.
Neither gate requires the retired Forge Desktop or WindowServer. Their external
prerequisites must be supplied before either can be reported as executed.

Workspace-wide `verification.projection` remains unchanged for the Harness and
must not be relabeled selected-Goal evidence. Goal review/completion semantics
continue to use their existing linked evidence and request-digest checks.

`execution.get` takes only the shared `authority` object. It returns execution,
Workspace and Activity IDs, lowercase state/failure codes, revision/timestamps,
terminal status and optional generated-package metadata. Current logical session,
Agent and execution provenance are checked; record and manifest share one SQLite
snapshot. The metadata response does not include artifact file bytes.

`execution.wait` takes the same authority, `after_sequence`, `max_bytes`, and
`max_events` as `execution.read`, plus required `timeout_ms` in `0..=30000`.
The result includes bounded binary-safe events/cursor, state/revision, terminal,
`changed` and `timed_out`. Native timeout performs a final durable read. Waits
have their own HTTP admission bound (at most16, also limited by configured
command capacity) and retain the existing native16-waiter bound. The request
owns a cancellable native Future; no general command bridge worker is held
while waiting. Dropping the request or server shutdown cancels this observation,
not the underlying execution. A delivery watchdog allows the requested native
wait budget plus the configured command response budget; expiry reports an
unconfirmed observation with the original execution ID and no automatic retry.

`goal.list` takes `scope`, `activity_id` and `limit` (`1..=100`).
`goal.delete_pending` takes `scope` and `limit` (`1..=32`), returning bounded
original deletion fences, cleanup progress and `has_more`.
`goal.delete` takes the shared planning `authority`, target `goal` or `dag`,
`goal_id`, `goal_created_at_ms`, `expected_goal_revision`, optional
`expected_dag_head_revision`, and `observed_at_ms`. The native owner requires the
head fence whenever the target currently has a DAG. Only Coordinator authority
is exposed; no local-operator bypass is available over HTTP.

Deletion returns native `complete`, `pending` or `blocked` progress. Pending
recovery preserves the original generation and revision fences and requires a
fresh authorized actor for another mutation. SQL-only completion may have no
cleanup ID; absence from pending inventory or Goal lookup is not proof that a
particular lost request committed. Unknown-outcome hints retain the original
Goal generation and head fence. Neither absence nor a historical read grants an
automatic retry. Existing Goal mutation receipts survive Goal deletion, while
DAG planning records retain their existing cleanup policy.

## Goal identity reuse

Schema 52 retains a per-Workspace/Goal creation watermark after Goal deletion.
A newly created Goal using a previously observed UUID must have a strictly later
creation timestamp; an unchanged existing Goal remains replayable. The server
rejects a nonadvancing timestamp with `GOAL_CONFLICT` and does not silently replace
the caller's time. Goal creation, watermark advancement and the GoalCreated event
commit together.

Migration preserves creation timestamps known from current Goals, pending cleanup
records and retained GoalCreated events. Deleted pre-event lifetimes cannot be
reconstructed. Consumers must not attach unversioned legacy node messages or Team
bindings to a newly observed Goal generation. Node assignment reads reject an
active assignment whose stored Goal creation time differs from the current Goal.

## Registered Location-root removal

`location.removal_probe` takes only non-nil `location_id`, including disabled
Locations. It returns current Location metadata/revision, `root_fingerprint` and
`expected_state` (`absent`, `uninitialized`, or `workspace` with UUID/revision).
Observation does not initialize/migrate state or establish a deletion receipt.

`location.remove` takes `location_id`, `expected_revision` and a nested `mode`:

```json
{
  "location_id": "00000000-0000-0000-0000-000000000001",
  "expected_revision": 1,
  "mode": {
    "kind": "delete_state",
    "expected_root_fingerprint": "0123456789abcdef0123456789abcdef",
    "expected_state": {
      "kind": "workspace",
      "workspace_id": "00000000-0000-0000-0000-000000000002",
      "workspace_revision": 1
    }
  }
}
```

`mode: {"kind":"list_only"}` disables the listing and preserves every file.
DeleteState additionally confirms the exact physical root and state under the
exclusive gate before disable. It deletes only the registered Location root's
owned `.heterarchy-forge`; source, Git and direct-child state remain. It does
not cancel processes or change logical membership. Disabling a parent hides
future child discovery; cohort stop/terminalization remains a separate contract.
IDs/fingerprint are confirmation selectors, not authentication. Caller paths,
timestamps, unknown fields and nil identities are rejected.

Successful replies carry the actual disabled `location` and `cleanup`:
`listing_only`, `state_removed` or `state_already_absent`, with retry/equivalence
flags false. DeleteState rejects active durable work/maintenance or a busy root
gate before cleanup. Incomplete or unconfirmed cleanup becomes `UNKNOWN_OUTCOME` with exact
original Location/revision/mode/fingerprint/state keys; internal error detail is
not exposed. COMMIT uncertainty stops further filesystem work. Never re-enable
automatically or retry using the original revision. After a confirmed deletion,
an old workspace expectation is stale; probe current state to form any new
intent. Current absence/disabled state cannot prove request causality.

Existing `location.state` unknown outcomes also retain Location ID, expected
revision and desired state. The general native worker supplies transition time
after admission; direct deterministic control retains explicit clock inputs.

## Recovery maintenance lease

`recovery.maintenance.run` accepts exact `scope`, non-nil `request_id`, the original
configured service echo (`backend_id`, `issuer`, `destination_id`,
`runtime_instance_id`), `duration_ms`, `activity_limit` (1–1000) and
`execution_limit` (1–256). The authenticated internal service supplies the actual
backend owner; Control stamps wall time. Caller owner, clock and permission fields
are rejected. An old boot echo is accepted only for an exact stored request replay.

Request lookup, lease claim, Activity then Execution classification, immutable
receipt and exact lease release share one SQLite transaction. Same-request replay
returns the original receipt and counts; it cannot classify rows created later.
Changed business metadata conflicts. `Busy`/`ClaimConflict` classify nothing.
The receipt preserves before/after revisions, original lease fields, ordered
targets and semantic/effect linkage. It describes a classification into
`Interrupted`, which does not prove native process closure or release stop/source
or Writer Lease authority.

`recovery.maintenance.get` takes `scope`, `request_id` and the original 64-character
lowercase `request_digest`. It is read-only. `absent_now` does not prove an already
queued owner job cannot commit. Deadline/disconnect uncertainty carries this exact
readback identity; use the same request identity for reconciliation. Schema61 adds
empty history when migrating60 and does not infer receipts from legacy rows.

`recovery.lease.get` takes exact `scope`. Claim adds non-nil `owner_id` and
`duration_ms` (1,000..=300,000). Renew also requires `expected_epoch` (>=0)
and `expected_revision` (>=1); release takes those fences without duration.
`work_cut.inventory` and `work_cut.prepare` take exact `scope`, configured
`service` (`issuer`, `backend_id`, `destination_id`) and a checked `request`.
The request includes cut/election IDs, Workspace and leadership revisions,
nonzero roster digest, distinct `parties.incumbent`/`parties.elected`, side-tagged
sessions/bindings and `scope.kind` (`workspace` or bounded `team` nodes).
Prepare also takes `grant` with issuer, canonical request digest and issued/expiry
window. Service UUIDs are configuration fences; existing bearer authentication
authenticates the issuer. The server resolves each bound session/principal before
capture. Inventory uses the same live session check; neither operation has a
local fallback when the provider is unavailable.

`work_cut.get` takes exact scope/service, `cut_id` and nonzero `request_digest`.
It reads immutable history without resolving sessions. `work_cut.drain` adds a
positive `expected_revision` and reports captured effects' current settlement;
`custody_released` remains false. Held cuts reject fresh source effects and
captured actors' new Writer Leases while preserving original recovery/readback
and normal exact owner release. Team cuts preserve unselected actors' work.
Unknown Prepare replies include the original cut/scope/digest readback hint;
read that identity before retrying. Get absence alone does not cancel queued work.
Limits remain sessions128, bindings256, team nodes256 and captured effects1024.
These operations do not transfer membership or release custody.

These are authenticated service/operator operations. The owner UUID selects
native runtime ownership; it is not authentication or logical membership.
The bounded native control worker supplies time after admission and preserves
the requested duration. Caller timestamps and expiry fields are rejected.
Renewal must move expiry forward; the worker does not clamp or advance time.

Replies contain `scope`, `status` and `lease` with `workspace_id`, `owner_id`,
`lease_until_ms`, `epoch`, `revision` and `updated_at_ms`. Get is `observed`;
claim is `acquired`, `already_owned`, `busy` or `claim_conflict`; other mutations
are `renewed` or `released`. Claim replay is not an HTTP idempotency guarantee:
server time may produce `claim_conflict` with the unchanged live lease.
Retry authorization and request-equivalence flags remain false.

Unknown mutation outcomes retain the `recovery_lease` readback key, including
owner/operation, expected epoch/revision and duration/null. Read the original
scope with get; a current row does not establish causal commit or authorize
retry. A released row has no owner/expiry; native CAS validates the prior owner.
Lease operations do not classify Activities/Executions, cancel processes or
issue a maintenance run receipt. Composite maintenance remains a separate owner.

Get observes current schema without migration or initialization. Missing
WAL/SHM uses immutable read-only access with source observation fences. Existing
paired live WAL uses a read-only transaction and physical identity fences so
concurrent committed writes remain visible; SQLite may update its existing
shared-memory read marks. Doctor retains its stricter private snapshot path.

## Activity lifecycle and queue observations

Activity bootstrap, get, close and all four lease commands use a dedicated
transport worker with a maximum of four admitted commands, backed by the narrow
native `ActivityLeaseClient`. They never fall back to the general command bridge.
General work can wait on another Workspace without consuming this admission
budget. Both bridges close admission and retain unfinished joins on bounded
shutdown; the lease bridge drains first. The host retains the native lease worker
and Registry serve fence through startup failure and shutdown.

`activity.lease.renew` takes `scope`, `activity_id`, `runtime_instance_id`,
`expected_lease_revision` and positive `duration_ms`. Release takes the same
fields without duration. Batch routes take `scope` and `commands` containing
one to256 corresponding entries. All entries must have unique Activity IDs and
the same runtime owner; renewal durations may differ. Native preflight and CAS
are atomic and preserve requested order. The worker supplies observation time
after admission; caller absolute timestamps and unknown fields are rejected.

These are authenticated service/operator operations. Runtime IDs are selectors
and revision fences, not authentication. Renew keeps the Activity open; release
keeps it open and unleased. Neither implicitly cancels an admitted process or
changes logical membership. Confirmed single replies contain `activity`; batch
replies always contain `activities`, including a batch ofone. Bootstrap now
returns the same full native Activity metadata as get, including timestamps.

An uncertain single mutation uses the existing `activity_lifecycle` readback key.
An uncertain batch uses `activity_lease_batch`, retaining operation and every
ordered Activity/runtime/revision key. Bootstrap uncertainty retains Workspace,
Activity and runtime IDs in `activity_bootstrap`. Read original IDs with
`activity.get`; observation neither establishes causal commit nor permits retry.
Missing, reordered or inconsistent post-commit rows cannot become confirmed
success. Known stale/foreign/batch conflicts have no unknown-outcome hint.

In embedded composition, `assemble(config, BackendClients { ... })` requires
the narrow client alongside control, execution and approval clients. Retain the
native lease worker until HTTP owners drain and it is explicitly shut down.
`AppState::new` remains a test port seam and does not establish host readiness.

`workspace.queue.settings.replace` takes `scope`, `capacity` (32, 64, 128 or
256) and required `expected_revision`. Explicit `null` inserts the first row;
a positive existing revision updates that exact CAS. Omission, invalid capacity,
unknown fields and caller timestamps are rejected. The native worker supplies
the save time after admission. This service/operator command does not require
or issue logical session, approval or execution authority.

A confirmed save returns `save_status: "committed"` and actual `saved_preference`.
`effective_runtime` is a separate optional observation. `runtime_application`
reports `matched` only when initialized capacity, persisted revision and both
persisted observations equal that saved record; otherwise it reports
`different_or_pending`, `unavailable` or `scope_changed`, with typed redacted
observation errors. An observation failure never erases a confirmed save.
`observation: "separate_non_atomic_reads"` retains concurrent-update semantics;
queue draining, active work and counters remain owned by the native mailbox.

Admitted reply loss or native commit uncertainty returns HTTP202 with a
`workspace_queue_settings` readback key: Workspace UUID, original expected
preference revision/null and requested capacity. Read `workspace.queue.settings`
with the original scope before deciding what to do next. That read is current
state, not a historical receipt or proof that this exact request committed.
Neither observation nor a matching capacity authorizes blind retry. Both query
and save replies explicitly withhold retry and request-equivalence proof.

`activity.get` takes `{scope, activity_id}`. It reads one actual durable row and
returns an exact scope echo, lifecycle/revision/timestamps and lease owner,
revision and expiry. `found:false` is explicit; this observation authorizes no
retry and proves no request equivalence.

`activity.close` takes `{scope, activity_id, runtime_instance_id,
expected_lease_revision}`. The configured issuer/operator credential authorizes
runtime-lease administration; the supplied runtime ID is a selector and CAS
fence, not caller authentication. The existing control owner closes the Activity
and releases its lease atomically with server-assigned observation time.
Execution cancellation remains its separate session/Agent/provenance operation.
A lost reply or committed-but-unconfirmed result is HTTP202 `UNKNOWN_OUTCOME`
with the exact `activity_lifecycle` readback tuple. Renew/close/release conversion
preserves uncertainty even when a post-commit scope fence yields no Activity
projection. A matching current row never proves which concurrent request won.

`queue.status` takes an empty object. `workspace.queue.status` and
`workspace.queue.settings` take `{scope}` and fence the registered scope before
and after reading the existing runtime counters. Status contains actual active,
pending/per-lane, capacity/source, generation/draining, age/rejection/high-water
and global counters. A read itself may enter the queue; empty user work does not
imply zero active work. Settings returns explicit optional `saved_preference`
and `effective_runtime`, labeled `separate_non_atomic_reads`. Reads do not save
preferences, change admission policy or mint approval/grant authority.

`approval.pending` takes `{scope}` and returns `{pending, limit: 256, bounded: true}`.
Each item carries Approval/Workspace/Activity/Execution IDs, action class, expiry
and `local_payload_available`, which describes cached execution payload presence
and does not grant approval authority. The owner reconciles one bounded page of
elapsed approvals, unused grants and AutoScopes before reading pending rows.
Server time and immutable before/after plans govern expiry; active nonexpired
authority remains unchanged. The projection does not claim a full inventory or
full reconciliation. Listing never attaches administrative cleanup ownership.
Disable or revision drift blocks new expiry effects; uncertain results retain
the original plan for exact owner readback before any identical retry. This is
a live-owner protocol, not a durable causal stop or restart receipt.

Approval/scheduling policy and grant issuance remain Orchestration-owned target
contracts. Existing `command.submit`/`shell.submit` still traverse the transitional
Forge-local approval coordinator; they do not establish completed ownership
cutover. Approval decision/auto-policy mutation routes are not added as a parity
shortcut. Native Agent binding/delegation/departure, recovery maintenance,
Workspace removal and complete downstream HTTP caller parity remain open.

### Workspace stop and exact readback

`execution.stop_workspace` is an administrative cancellation request to the
existing ApprovalCoordinator owner. The Workspace must already be attached by an
actual owned operation, such as preapproved `execution.begin`. Listing, an Agent
UUID, a session identity, or a caller-provided digest cannot create that permit.
The original Scope and physical binding remain usable after Location disable.

Both stop and `execution.stop_workspace_get` require the configured service bearer
and a currently Open logical session resolved by the canonical provider. Service
authentication and propagated session/principal are separate. The payload is:

```text
scope: existing ScopeDto
stop_id: non-nil UUID
durable_request_id: non-nil UUID retained across retries
service: {backend_id, issuer, destination_id, runtime_instance_id}
actor: {session_id, principal: existing PrincipalDto}
```

The four service fields must echo the configured backend/issuer/destination and
the backend process boot identity. Activity runtime identity is not that boot.
No observation time or arbitrary digest is accepted. Control computes the
canonical digest from these identities, the exact Scope/revisions/locator bytes
and the logical actor. Keep the original payload for readback; the transport
envelope request ID may change on an exact retry.

These commands use a dedicated four-slot HTTP owner lane. After owner admission,
deadline or disconnect leaves the original task, receiver and slot owned until
the actual reply settles; shutdown tracks them. A fifth concurrent retained call
is rejected before admission. Ordinary command-bridge saturation does not route
stop through a native fallback.

The reply's `execution` and `authority` fields describe the atomic captured pair.
Execution targets are bounded256; approval/grant/auto-scope targets are bounded256
per family,768 total. `durable_status` remains `pending`. Native operation results
are separate: positive count is `requested`; zero is `no_owned_execution` with
`cancellation_requested: false`; errors remain `unknown` with exact readback keys.
Counts are not terminal or release receipts. `owner_quiescence` separately reports
`observed`, `not_observed` or `unknown` for the current live execution owner.
An observation requires drained Start/terminal/output ownership and no uncertain
cleanup; it is a snapshot, not durable stop completion or admission permission.
Get returns `native: null` and `owner_quiescence: null` and does
not cancel, recapture, clean up or release anything. `absent_now` describes a
durable read snapshot, not non-admission or permission to choose another request.

Known validation/capacity/identity refusal has no admitted-effect hint. Unknown
admitted outcomes carry a `workspace_stop` hint with Workspace, stop/durable request
IDs, canonical digest and original boot ID. Read back the same intent before any
identical retry. Historical readback after restart requires its remaining original
owner/binding recovery path; this API does not recreate native rights from stored
IDs. Schema59 stores actual native closure/reap/output/manifest facts atomically
with terminal evidence. Stop target settlement and admission release remain
unimplemented follow-through. Source and Writer Lease quiescence are outside
this execution-stop intent.
