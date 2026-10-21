# Activity lease supervision

The standalone host can keep an explicitly registered Activity live while its
existing Goal is active. This is disabled unless `activity_lease_supervision` is
present in the host configuration. It does not create a Workspace, Goal, Agent,
Session, assignment, or approval.

The object contains an absolute private `journal_root`, optional
`lease_duration_ms` (default 60000), optional `renew_interval_ms` (default 20000),
and one to sixteen `registrations`. Duration must be 30000–300000 ms; interval
must be 1000–60000 ms and no greater than one third of the duration.

Each registration requires:

- `supervision_id`: a distinct non-nil UUID.
- `scope`: exact `location_id`, `location_revision`, `workspace_id`, and
  `workspace_revision`. Source inventory resolves the root, including a
  Location-root Workspace; configuration never supplies a Workspace path.
- `activity_id`, `goal_id`, and `goal_created_at_ms`: the existing work generation.
- `initiating_session_id`: the existing open sponsoring Session.
- `principal`: `kind` and `id`. Direct-token and OAuth-grant principals require
  their actual non-nil identity; trusted-stdio uses a null ID. These are identity
  selectors, never bearer secrets.
- `coordinator`: the existing `agent_id`, `session_id`, and Coordinator `revision`.
  Its Session must equal the initiating Session.

The host acquires its Registry serve fence before opening the journal. The
journal also holds its own exclusive fence for its entire lifetime, preventing
two different Registries from writing the same journal. Keep that directory
private and durable. A pending operation cannot be removed by replacing its
registration, and the sixteen-record bound is checked before a write.

For a live lease owned by the current boot, Source authenticates the Session at
admission and checks the active Goal, Coordinator, and attached Agent in the
same Workspace transaction as the lease CAS. A remote Session closure after
admission does not retroactively cancel an admitted transaction. A foreign live
lease is left alone until expiry. An expired lease uses the existing Started
resume proof or the separate Quiescent proof; ineligible work stops progressing.

Quiescent recovery exposes `activity.quiescent_lease_resume_probe`,
`activity.quiescent_lease_resume_run`, and `activity.quiescent_lease_resume_get`.
It requires the current expired Activity and Coordinator, complete history and
effect censuses, zero assignment rows, and no physical effects. Schema 69 adds
an immutable receipt ledger. Read-only inventory can still inspect schema 68;
normal mutable open performs the forward migration. Started and Quiescent Run
sample the trusted Source clock after acquiring the transaction and checking
for an exact receipt replay.

Before Run, the host persists an exact Get selector. Uncertain results and
restart begin with readback; receipt absence does not authorize a repeat Run.
Renewal uncertainty records the owner, expected revision and duration. An exact
next revision with the same live owner proves current state, not a historical
receipt for the lost request. Divergent state pauses automatic writes.

Shutdown joins the supervisor before its workers. It does not close the Activity
or release its lease. A new boot waits for any old live lease and uses canonical
recovery to retain the same Activity, Goal, DAG and work history. Terminal Goals
stop further renewal. Do not erase a pending journal or downgrade a migrated
Workspace to an older binary as a recovery shortcut.
