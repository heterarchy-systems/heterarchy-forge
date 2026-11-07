//! Canonical, bounded binary representation of a captured Home-transfer source.
//!
//! This format is deliberately local to the persistence-owned capsule. It is
//! versioned and closed: adding a field or enum alternative requires a format
//! revision rather than silently dropping information.

use super::inventory::{
    HomeTransferSourceInventory, HomeTransferSourceInventoryError as Error, MAX_HOME_SOURCE_AGENTS,
    MAX_HOME_SOURCE_ENTRIES, MAX_HOME_SOURCE_INVENTORY_BYTES, SourceAgent, SourceApproval,
    SourceApprovalAttribution, SourceApprovalGrant, SourceApprovalState, SourceAssignment,
    SourceAssignmentOrigin, SourceAssignmentState, SourceAttachment, SourceAuthorizationSource,
    SourceBindingReservation, SourceChangeSet, SourceChangeSetState, SourceClosureLaunch,
    SourceClosureProcess, SourceClosureRuntime, SourceExecution, SourceExecutionActionClass,
    SourceExecutionGrantState, SourceExecutionPermissions, SourceExecutionState,
    SourceFileMutation, SourceFileMutationKind, SourceFilePathState, SourceFilePrecondition,
    SourceFocus, SourceNativeClosure, SourcePrincipal, SourceProjectCommand,
    SourceProjectCommandClass, SourceRejectionReason, SourceReservationOutcome, SourceTransport,
    SourceTreeMutation, SourceTreeMutationKind, SourceWorkCreditBudget, SourceWriterLease,
    SourceWriterLeaseEntry, SourceWriterLeaseScopeKind, SourceWriterLeaseState,
};
use forge_domain::{
    HomeTransferSourceRequest, MAX_AGENT_DISPLAY_NAME_BYTES, MAX_AGENT_ROLE_BYTES,
    MAX_EXECUTION_COMMAND_ID_BYTES, MAX_HOME_TRANSFER_SOURCE_SESSIONS,
    MAX_TREE_CHANGESET_MUTATIONS, MAX_WORKSPACE_RELATIVE_PATH_BYTES,
    MAX_WRITER_LEASE_SCOPE_ENTRIES,
};
use uuid::Uuid;

const MAGIC: &[u8; 4] = b"FHTI";
const CODEC_VERSION: u8 = 1;

/// Encode a validated source inventory into its one canonical byte sequence.
pub(super) fn encode(inventory: &HomeTransferSourceInventory) -> Result<Vec<u8>, Error> {
    inventory.validate_shape()?;
    let mut writer = ByteWriter::default();
    writer.raw(MAGIC)?;
    writer.u8(CODEC_VERSION)?;
    writer.u8(inventory.version)?;
    writer.raw(&inventory.request_digest)?;
    writer.uuid(inventory.workspace_id)?;
    writer.i64(inventory.workspace_revision)?;

    writer.count(
        inventory.session_ids.len(),
        MAX_HOME_TRANSFER_SOURCE_SESSIONS,
        "sessions",
    )?;
    for id in &inventory.session_ids {
        writer.uuid(*id)?;
    }

    writer.count(inventory.agents.len(), MAX_HOME_SOURCE_AGENTS, "Agents")?;
    for value in &inventory.agents {
        write_agent(&mut writer, value)?;
    }

    writer.count(
        inventory.reservations.len(),
        MAX_HOME_SOURCE_ENTRIES,
        "reservations",
    )?;
    for value in &inventory.reservations {
        write_reservation(&mut writer, value, inventory.version)?;
    }

    writer.count(
        inventory.assignments.len(),
        MAX_HOME_SOURCE_ENTRIES,
        "assignments",
    )?;
    for value in &inventory.assignments {
        write_assignment(&mut writer, value, inventory.version)?;
    }

    writer.count(
        inventory.writer_leases.len(),
        MAX_HOME_SOURCE_ENTRIES,
        "Writer Leases",
    )?;
    for value in &inventory.writer_leases {
        write_writer_lease(&mut writer, value)?;
    }

    writer.count(
        inventory.executions.len(),
        MAX_HOME_SOURCE_ENTRIES,
        "executions",
    )?;
    for value in &inventory.executions {
        write_execution(&mut writer, value)?;
    }
    writer.u64(inventory.closed_execution_count)?;
    writer.raw(&inventory.closed_execution_digest)?;
    writer.i64(inventory.closed_execution_high_water_ms)?;

    writer.count(
        inventory.approvals.len(),
        MAX_HOME_SOURCE_ENTRIES,
        "approvals",
    )?;
    for value in &inventory.approvals {
        write_approval(&mut writer, value)?;
    }

    writer.count(
        inventory.change_sets.len(),
        MAX_HOME_SOURCE_ENTRIES,
        "ChangeSets",
    )?;
    for value in &inventory.change_sets {
        write_change_set(&mut writer, value)?;
    }

    writer.count(
        inventory.affected_activity_ids.len(),
        MAX_HOME_SOURCE_ENTRIES,
        "affected Activities",
    )?;
    for id in &inventory.affected_activity_ids {
        writer.uuid(*id)?;
    }
    writer.count(
        inventory.affected_agent_ids.len(),
        MAX_HOME_SOURCE_AGENTS,
        "affected Agents",
    )?;
    for id in &inventory.affected_agent_ids {
        writer.uuid(*id)?;
    }
    writer.i64(inventory.source_high_water_ms)?;
    Ok(writer.finish())
}
/// Decode only a canonical capsule bound to the exact Operations request.
pub(super) fn decode(
    bytes: &[u8],
    request: &HomeTransferSourceRequest,
) -> Result<HomeTransferSourceInventory, Error> {
    if bytes.len() > MAX_HOME_SOURCE_INVENTORY_BYTES {
        return Err(Error::PayloadTooLarge {
            actual: bytes.len(),
            maximum: MAX_HOME_SOURCE_INVENTORY_BYTES,
        });
    }
    // Scan the complete grammar without allocating before materializing any
    // collection. Count, tag, UTF-8, truncation, version, and tail failures are
    // therefore rejected before attacker-controlled lengths can allocate.
    let mut scan = ByteReader::preflight(bytes);
    let scanned = read_inventory(&mut scan)?;
    if scanned.request_digest != *request.request_digest().as_bytes()
        || scanned.workspace_id != request.scope().workspace_id().into_uuid()
        || scanned.workspace_revision != request.scope().workspace_revision().get()
    {
        return Err(Error::RequestMismatch);
    }

    let mut reader = ByteReader::new(bytes);
    let inventory = read_inventory(&mut reader)?;
    inventory.validate_for_request(request)?;
    if encode(&inventory)?.as_slice() != bytes {
        return Err(Error::Corrupt("noncanonical encoding"));
    }
    Ok(inventory)
}

#[allow(
    clippy::too_many_lines,
    reason = "preflight and materialization share one ordered decoder for the closed capsule"
)]
fn read_inventory(reader: &mut ByteReader<'_>) -> Result<HomeTransferSourceInventory, Error> {
    if reader.raw(MAGIC.len(), "magic")? != MAGIC {
        return Err(Error::Corrupt("codec magic"));
    }
    if reader.u8("codec version")? != CODEC_VERSION {
        return Err(Error::Corrupt("codec version"));
    }
    let version = reader.u8("inventory version")?;
    if !super::inventory::supported_inventory_version(version) {
        return Err(Error::Corrupt("inventory version"));
    }
    let request_digest = reader.array::<32>("request digest")?;
    let workspace_id = reader.uuid("Workspace identity")?;
    let workspace_revision = reader.i64("Workspace revision")?;

    let mut budget = RecordBudget::default();
    let session_count = reader.count(MAX_HOME_TRANSFER_SOURCE_SESSIONS, 16, "sessions")?;
    let mut session_ids = vector_with_capacity(reader, session_count);
    for _ in 0..session_count {
        let id = reader.uuid("Session identity")?;
        push_if_materializing(reader, &mut session_ids, id);
    }

    let agent_count = reader.count(MAX_HOME_SOURCE_AGENTS, 16, "Agents")?;
    budget.add(agent_count)?;
    let mut agents = vector_with_capacity(reader, agent_count);
    for _ in 0..agent_count {
        let value = read_agent(reader)?;
        push_if_materializing(reader, &mut agents, value);
    }

    let reservation_count = reader.count(MAX_HOME_SOURCE_ENTRIES, 16, "reservations")?;
    budget.add(reservation_count)?;
    let mut reservations = vector_with_capacity(reader, reservation_count);
    for _ in 0..reservation_count {
        let value = read_reservation(reader, version)?;
        push_if_materializing(reader, &mut reservations, value);
    }

    let assignment_count = reader.count(MAX_HOME_SOURCE_ENTRIES, 16, "assignments")?;
    budget.add(assignment_count)?;
    let mut assignments = vector_with_capacity(reader, assignment_count);
    for _ in 0..assignment_count {
        let value = read_assignment(reader, version)?;
        push_if_materializing(reader, &mut assignments, value);
    }

    let lease_count = reader.count(MAX_HOME_SOURCE_ENTRIES, 16, "Writer Leases")?;
    budget.add(lease_count)?;
    let mut writer_leases = vector_with_capacity(reader, lease_count);
    for _ in 0..lease_count {
        let value = read_writer_lease(reader)?;
        push_if_materializing(reader, &mut writer_leases, value);
    }

    let execution_count = reader.count(MAX_HOME_SOURCE_ENTRIES, 16, "executions")?;
    budget.add(execution_count)?;
    let mut executions = vector_with_capacity(reader, execution_count);
    for _ in 0..execution_count {
        let value = read_execution(reader)?;
        push_if_materializing(reader, &mut executions, value);
    }
    let closed_execution_count = reader.u64("closed execution count")?;
    let closed_execution_digest = reader.array::<32>("closed execution digest")?;
    let closed_execution_high_water_ms = reader.i64("closed execution high-water")?;

    let approval_count = reader.count(MAX_HOME_SOURCE_ENTRIES, 16, "approvals")?;
    budget.add(approval_count)?;
    let mut approvals = vector_with_capacity(reader, approval_count);
    for _ in 0..approval_count {
        let approval = read_approval(reader, &mut budget)?;
        push_if_materializing(reader, &mut approvals, approval);
    }

    let change_set_count = reader.count(MAX_HOME_SOURCE_ENTRIES, 16, "ChangeSets")?;
    budget.add(change_set_count)?;
    let mut change_sets = vector_with_capacity(reader, change_set_count);
    for _ in 0..change_set_count {
        let change_set = read_change_set(reader, &mut budget)?;
        push_if_materializing(reader, &mut change_sets, change_set);
    }

    let affected_activity_count =
        reader.count(MAX_HOME_SOURCE_ENTRIES, 16, "affected Activities")?;
    let mut affected_activity_ids = vector_with_capacity(reader, affected_activity_count);
    for _ in 0..affected_activity_count {
        let id = reader.uuid("affected Activity identity")?;
        push_if_materializing(reader, &mut affected_activity_ids, id);
    }
    let affected_agent_count = reader.count(MAX_HOME_SOURCE_AGENTS, 16, "affected Agents")?;
    let mut affected_agent_ids = vector_with_capacity(reader, affected_agent_count);
    for _ in 0..affected_agent_count {
        let id = reader.uuid("affected Agent identity")?;
        push_if_materializing(reader, &mut affected_agent_ids, id);
    }
    let source_high_water_ms = reader.i64("source high-water")?;
    reader.finish()?;

    Ok(HomeTransferSourceInventory {
        version,
        request_digest,
        workspace_id,
        workspace_revision,
        session_ids,
        agents,
        reservations,
        assignments,
        writer_leases,
        executions,
        closed_execution_count,
        closed_execution_digest,
        closed_execution_high_water_ms,
        approvals,
        change_sets,
        affected_activity_ids,
        affected_agent_ids,
        source_high_water_ms,
    })
}

#[derive(Default)]
struct ByteWriter {
    bytes: Vec<u8>,
}

impl ByteWriter {
    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn raw(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let actual = self.bytes.len().saturating_add(bytes.len());
        if actual > MAX_HOME_SOURCE_INVENTORY_BYTES {
            return Err(Error::PayloadTooLarge {
                actual,
                maximum: MAX_HOME_SOURCE_INVENTORY_BYTES,
            });
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), Error> {
        self.raw(&[value])
    }
    fn u32(&mut self, value: u32) -> Result<(), Error> {
        self.raw(&value.to_be_bytes())
    }
    fn u64(&mut self, value: u64) -> Result<(), Error> {
        self.raw(&value.to_be_bytes())
    }
    fn i64(&mut self, value: i64) -> Result<(), Error> {
        self.raw(&value.to_be_bytes())
    }
    fn uuid(&mut self, value: Uuid) -> Result<(), Error> {
        self.raw(value.as_bytes())
    }

    fn count(&mut self, count: usize, maximum: usize, field: &'static str) -> Result<(), Error> {
        if count > maximum {
            return Err(Error::Bounds(field));
        }
        let count = u32::try_from(count).map_err(|_| Error::Bounds(field))?;
        self.u32(count)
    }

    fn bytes(&mut self, bytes: &[u8], maximum: usize, field: &'static str) -> Result<(), Error> {
        if bytes.len() > maximum {
            return Err(Error::Bounds(field));
        }
        self.count(bytes.len(), maximum, field)?;
        self.raw(bytes)
    }

    fn string(&mut self, value: &str, maximum: usize, field: &'static str) -> Result<(), Error> {
        self.bytes(value.as_bytes(), maximum, field)
    }

    fn option<T>(
        &mut self,
        value: Option<T>,
        write: impl FnOnce(&mut Self, T) -> Result<(), Error>,
    ) -> Result<(), Error> {
        match value {
            None => self.u8(0),
            Some(value) => {
                self.u8(1)?;
                write(self, value)
            }
        }
    }
}

struct ByteReader<'a> {
    bytes: &'a [u8],
    offset: usize,
    materialize: bool,
}

fn vector_with_capacity<T>(reader: &ByteReader<'_>, count: usize) -> Vec<T> {
    if reader.materialize {
        Vec::with_capacity(count)
    } else {
        Vec::new()
    }
}

fn push_if_materializing<T>(reader: &ByteReader<'_>, values: &mut Vec<T>, value: T) {
    if reader.materialize {
        values.push(value);
    }
}

impl<'a> ByteReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            materialize: true,
        }
    }
    fn preflight(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            materialize: false,
        }
    }
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn raw(&mut self, length: usize, field: &'static str) -> Result<&'a [u8], Error> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(Error::Corrupt(field))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(Error::Corrupt(field))?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self, field: &'static str) -> Result<[u8; N], Error> {
        self.raw(N, field)?
            .try_into()
            .map_err(|_| Error::Corrupt(field))
    }
    fn u8(&mut self, field: &'static str) -> Result<u8, Error> {
        Ok(self.raw(1, field)?[0])
    }
    fn u32(&mut self, field: &'static str) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.array(field)?))
    }
    fn u64(&mut self, field: &'static str) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array(field)?))
    }
    fn i64(&mut self, field: &'static str) -> Result<i64, Error> {
        Ok(i64::from_be_bytes(self.array(field)?))
    }
    fn uuid(&mut self, field: &'static str) -> Result<Uuid, Error> {
        Ok(Uuid::from_bytes(self.array(field)?))
    }

    fn count(
        &mut self,
        maximum: usize,
        minimum_bytes_per_item: usize,
        field: &'static str,
    ) -> Result<usize, Error> {
        let count = usize::try_from(self.u32(field)?).map_err(|_| Error::Bounds(field))?;
        if count > maximum {
            return Err(Error::Bounds(field));
        }
        let minimum = count
            .checked_mul(minimum_bytes_per_item)
            .ok_or(Error::Bounds(field))?;
        if minimum > self.remaining() {
            return Err(Error::Corrupt(field));
        }
        Ok(count)
    }

    fn bytes(&mut self, maximum: usize, field: &'static str) -> Result<Vec<u8>, Error> {
        let length = self.count(maximum, 0, field)?;
        let bytes = self.raw(length, field)?;
        Ok(if self.materialize {
            bytes.to_vec()
        } else {
            Vec::new()
        })
    }

    fn string(&mut self, maximum: usize, field: &'static str) -> Result<String, Error> {
        let length = self.count(maximum, 0, field)?;
        let bytes = self.raw(length, field)?;
        let value = std::str::from_utf8(bytes).map_err(|_| Error::Corrupt(field))?;
        Ok(if self.materialize {
            value.to_owned()
        } else {
            String::new()
        })
    }

    fn option<T>(
        &mut self,
        field: &'static str,
        read: impl FnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<Option<T>, Error> {
        match self.u8(field)? {
            0 => Ok(None),
            1 => read(self).map(Some),
            _ => Err(Error::Corrupt(field)),
        }
    }

    fn finish(&self) -> Result<(), Error> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::Corrupt("trailing bytes"))
        }
    }
}

#[derive(Default)]
struct RecordBudget {
    used: usize,
}

impl RecordBudget {
    fn add(&mut self, count: usize) -> Result<(), Error> {
        self.used = self
            .used
            .checked_add(count)
            .ok_or(Error::Bounds("source entries"))?;
        if self.used > MAX_HOME_SOURCE_ENTRIES {
            return Err(Error::Bounds("source entries"));
        }
        Ok(())
    }
}

fn write_principal(w: &mut ByteWriter, value: SourcePrincipal) -> Result<(), Error> {
    match value {
        SourcePrincipal::TrustedStdio => w.u8(0),
        SourcePrincipal::DirectToken(id) => {
            w.u8(1)?;
            w.uuid(id)
        }
        SourcePrincipal::OAuthGrant(id) => {
            w.u8(2)?;
            w.uuid(id)
        }
    }
}

fn read_principal(r: &mut ByteReader<'_>) -> Result<SourcePrincipal, Error> {
    match r.u8("principal tag")? {
        0 => Ok(SourcePrincipal::TrustedStdio),
        1 => Ok(SourcePrincipal::DirectToken(r.uuid("principal token")?)),
        2 => Ok(SourcePrincipal::OAuthGrant(r.uuid("principal grant")?)),
        _ => Err(Error::Corrupt("principal tag")),
    }
}

fn write_transport(w: &mut ByteWriter, value: SourceTransport) -> Result<(), Error> {
    w.u8(match value {
        SourceTransport::Retired => 0,
        SourceTransport::Stdio => 1,
        SourceTransport::StreamableHttp => 2,
        SourceTransport::Other => 3,
    })
}

fn read_transport(r: &mut ByteReader<'_>) -> Result<SourceTransport, Error> {
    match r.u8("transport tag")? {
        0 => Ok(SourceTransport::Retired),
        1 => Ok(SourceTransport::Stdio),
        2 => Ok(SourceTransport::StreamableHttp),
        3 => Ok(SourceTransport::Other),
        _ => Err(Error::Corrupt("transport tag")),
    }
}

fn write_project_command(w: &mut ByteWriter, value: SourceProjectCommand) -> Result<(), Error> {
    w.u8(match value.class {
        SourceProjectCommandClass::Verify => 0,
        SourceProjectCommandClass::GeneratedPackage => 1,
    })?;
    w.raw(&value.catalog_fingerprint)
}

fn read_project_command(r: &mut ByteReader<'_>) -> Result<SourceProjectCommand, Error> {
    let class = match r.u8("project command class")? {
        0 => SourceProjectCommandClass::Verify,
        1 => SourceProjectCommandClass::GeneratedPackage,
        _ => return Err(Error::Corrupt("project command class")),
    };
    Ok(SourceProjectCommand {
        class,
        catalog_fingerprint: r.array("project command fingerprint")?,
    })
}

fn write_agent(w: &mut ByteWriter, value: &SourceAgent) -> Result<(), Error> {
    w.uuid(value.agent_id)?;
    w.uuid(value.workspace_id)?;
    w.uuid(value.activity_id)?;
    w.option(value.session_id, ByteWriter::uuid)?;
    write_principal(w, value.principal)?;
    w.string(
        &value.display_name,
        MAX_AGENT_DISPLAY_NAME_BYTES,
        "Agent display name",
    )?;
    w.string(&value.declared_role, MAX_AGENT_ROLE_BYTES, "Agent role")?;
    write_transport(w, value.transport)?;
    w.u8(match value.attachment {
        SourceAttachment::Attached => 0,
        SourceAttachment::Detached => 1,
    })?;
    w.i64(value.revision)?;
    w.i64(value.created_at_ms)?;
    w.i64(value.updated_at_ms)?;
    write_focus(w, value.focus)
}

fn read_agent(r: &mut ByteReader<'_>) -> Result<SourceAgent, Error> {
    let agent_id = r.uuid("Agent identity")?;
    let workspace_id = r.uuid("Agent Workspace")?;
    let activity_id = r.uuid("Agent Activity")?;
    let session_id = r.option("Agent Session", |r| r.uuid("Agent Session"))?;
    let principal = read_principal(r)?;
    let display_name = r.string(MAX_AGENT_DISPLAY_NAME_BYTES, "Agent display name")?;
    let declared_role = r.string(MAX_AGENT_ROLE_BYTES, "Agent role")?;
    let transport = read_transport(r)?;
    let attachment = match r.u8("Agent attachment")? {
        0 => SourceAttachment::Attached,
        1 => SourceAttachment::Detached,
        _ => return Err(Error::Corrupt("Agent attachment")),
    };
    Ok(SourceAgent {
        agent_id,
        workspace_id,
        activity_id,
        session_id,
        principal,
        display_name,
        declared_role,
        transport,
        attachment,
        revision: r.i64("Agent revision")?,
        created_at_ms: r.i64("Agent created time")?,
        updated_at_ms: r.i64("Agent updated time")?,
        focus: read_focus(r)?,
    })
}

fn write_focus(w: &mut ByteWriter, value: SourceFocus) -> Result<(), Error> {
    w.option(value.goal_id, ByteWriter::uuid)?;
    w.option(value.goal_revision, ByteWriter::i64)?;
    w.option(value.dag_revision, ByteWriter::i64)?;
    w.option(value.node_id, ByteWriter::uuid)?;
    w.option(value.node_revision, ByteWriter::i64)
}

fn read_focus(r: &mut ByteReader<'_>) -> Result<SourceFocus, Error> {
    Ok(SourceFocus {
        goal_id: r.option("focus Goal", |r| r.uuid("focus Goal"))?,
        goal_revision: r.option("focus Goal revision", |r| r.i64("focus Goal revision"))?,
        dag_revision: r.option("focus DAG revision", |r| r.i64("focus DAG revision"))?,
        node_id: r.option("focus node", |r| r.uuid("focus node"))?,
        node_revision: r.option("focus node revision", |r| r.i64("focus node revision"))?,
    })
}

fn write_reservation(
    w: &mut ByteWriter,
    value: &SourceBindingReservation,
    inventory_version: u8,
) -> Result<(), Error> {
    w.uuid(value.request_id)?;
    w.uuid(value.workspace_id)?;
    w.uuid(value.activity_id)?;
    w.uuid(value.migration_id)?;
    w.uuid(value.destination_id)?;
    w.i64(value.freeze_revision)?;
    w.uuid(value.agent_id)?;
    w.uuid(value.session_id)?;
    write_principal(w, value.principal)?;
    w.i64(value.requested_at_ms)?;
    w.i64(value.reserved_at_ms)?;
    match &value.outcome {
        SourceReservationOutcome::Pending => w.u8(0),
        SourceReservationOutcome::Activated {
            membership_digest,
            display_name,
            declared_role,
            transport,
            activated_at_ms,
        } => {
            w.u8(1)?;
            w.raw(membership_digest)?;
            w.string(
                display_name,
                MAX_AGENT_DISPLAY_NAME_BYTES,
                "activation display name",
            )?;
            w.string(declared_role, MAX_AGENT_ROLE_BYTES, "activation role")?;
            write_transport(w, *transport)?;
            w.i64(*activated_at_ms)
        }
        SourceReservationOutcome::Rejected {
            request_digest,
            receipt_digest,
            rejected_at_ms,
            reason,
        } => {
            w.u8(2)?;
            w.raw(request_digest)?;
            w.raw(receipt_digest)?;
            w.i64(*rejected_at_ms)?;
            w.u8(match reason {
                SourceRejectionReason::PrincipalTransportMismatch => 0,
            })
        }
        SourceReservationOutcome::Retired {
            preparation_id,
            request_digest,
            receipt_digest,
            observed_at_ms,
        } => {
            if inventory_version < 2 {
                return Err(Error::Corrupt("retirement requires inventory version 2"));
            }
            w.u8(3)?;
            w.uuid(*preparation_id)?;
            w.raw(request_digest)?;
            w.raw(receipt_digest)?;
            w.i64(*observed_at_ms)
        }
    }
}

fn read_reservation(
    r: &mut ByteReader<'_>,
    inventory_version: u8,
) -> Result<SourceBindingReservation, Error> {
    let request_id = r.uuid("reservation request")?;
    let workspace_id = r.uuid("reservation Workspace")?;
    let activity_id = r.uuid("reservation Activity")?;
    let migration_id = r.uuid("reservation migration")?;
    let destination_id = r.uuid("reservation destination")?;
    let freeze_revision = r.i64("reservation freeze revision")?;
    let agent_id = r.uuid("reservation Agent")?;
    let session_id = r.uuid("reservation Session")?;
    let principal = read_principal(r)?;
    let requested_at_ms = r.i64("reservation request time")?;
    let reserved_at_ms = r.i64("reservation time")?;
    let outcome = match r.u8("reservation outcome")? {
        0 => SourceReservationOutcome::Pending,
        1 => SourceReservationOutcome::Activated {
            membership_digest: r.array("activation membership digest")?,
            display_name: r.string(MAX_AGENT_DISPLAY_NAME_BYTES, "activation display name")?,
            declared_role: r.string(MAX_AGENT_ROLE_BYTES, "activation role")?,
            transport: read_transport(r)?,
            activated_at_ms: r.i64("activation time")?,
        },
        2 => {
            let request_digest = r.array("rejection request digest")?;
            let receipt_digest = r.array("rejection receipt digest")?;
            let rejected_at_ms = r.i64("rejection time")?;
            let reason = match r.u8("rejection reason")? {
                0 => SourceRejectionReason::PrincipalTransportMismatch,
                _ => return Err(Error::Corrupt("rejection reason")),
            };
            SourceReservationOutcome::Rejected {
                request_digest,
                receipt_digest,
                rejected_at_ms,
                reason,
            }
        }
        3 if inventory_version >= 2 => SourceReservationOutcome::Retired {
            preparation_id: r.uuid("retirement preparation")?,
            request_digest: r.array("retirement request digest")?,
            receipt_digest: r.array("retirement receipt digest")?,
            observed_at_ms: r.i64("retirement observation time")?,
        },
        3 => return Err(Error::Corrupt("retirement requires inventory version 2")),
        _ => return Err(Error::Corrupt("reservation outcome")),
    };
    Ok(SourceBindingReservation {
        request_id,
        workspace_id,
        activity_id,
        migration_id,
        destination_id,
        freeze_revision,
        agent_id,
        session_id,
        principal,
        requested_at_ms,
        reserved_at_ms,
        outcome,
    })
}

fn write_assignment(
    w: &mut ByteWriter,
    value: &SourceAssignment,
    inventory_version: u8,
) -> Result<(), Error> {
    w.uuid(value.assignment_id)?;
    match value.origin {
        SourceAssignmentOrigin::CoordinatorOffer => w.u8(0)?,
        SourceAssignmentOrigin::CutContinuation {
            cut_id,
            transfer_id,
            predecessor_id,
        } => {
            w.u8(1)?;
            w.uuid(cut_id)?;
            w.uuid(transfer_id)?;
            w.uuid(predecessor_id)?;
        }
        SourceAssignmentOrigin::HomeHandoff {
            preparation_id,
            handoff_id,
            predecessor_id,
            root_assignment_id,
        } => {
            if inventory_version != super::inventory::INVENTORY_VERSION {
                return Err(Error::Corrupt(
                    "Home handoff origin requires inventory version 3",
                ));
            }
            w.u8(2)?;
            w.uuid(preparation_id)?;
            w.uuid(handoff_id)?;
            w.uuid(predecessor_id)?;
            w.uuid(root_assignment_id)?;
        }
    }
    w.uuid(value.workspace_id)?;
    w.uuid(value.activity_id)?;
    w.uuid(value.target_agent_id)?;
    w.uuid(value.target_session_id)?;
    write_principal(w, value.target_principal)?;
    w.i64(value.target_agent_revision)?;
    w.uuid(value.coordinator_agent_id)?;
    w.uuid(value.coordinator_session_id)?;
    write_principal(w, value.coordinator_principal)?;
    w.i64(value.coordinator_revision)?;
    w.u8(assignment_state_tag(value.state))?;
    w.u8(u8::from(value.cancellation_requested))?;
    w.i64(value.revision)?;
    w.i64(value.created_at_ms)?;
    w.i64(value.updated_at_ms)?;
    w.option(value.credit_budget, |w, budget| {
        w.u8(match budget {
            SourceWorkCreditBudget::One => 0,
            SourceWorkCreditBudget::Three => 1,
            SourceWorkCreditBudget::Five => 2,
        })
    })?;
    w.option(value.result_digest, |w, digest| w.raw(&digest))?;
    w.uuid(value.goal_id)?;
    w.i64(value.goal_created_at_ms)?;
    w.i64(value.goal_revision)?;
    w.i64(value.dag_revision)?;
    w.i64(value.dag_head_revision)?;
    w.uuid(value.node_id)?;
    w.i64(value.node_revision)
}

fn assignment_state_tag(value: SourceAssignmentState) -> u8 {
    match value {
        SourceAssignmentState::Offered => 0,
        SourceAssignmentState::Running => 1,
        SourceAssignmentState::Submitted => 2,
        SourceAssignmentState::Accepted => 3,
        SourceAssignmentState::Rejected => 4,
        SourceAssignmentState::Cancelled => 5,
        SourceAssignmentState::Interrupted => 6,
    }
}

fn read_assignment(
    r: &mut ByteReader<'_>,
    inventory_version: u8,
) -> Result<SourceAssignment, Error> {
    let assignment_id = r.uuid("assignment identity")?;
    let origin = match r.u8("assignment origin")? {
        0 => SourceAssignmentOrigin::CoordinatorOffer,
        1 => SourceAssignmentOrigin::CutContinuation {
            cut_id: r.uuid("assignment cut")?,
            transfer_id: r.uuid("assignment transfer")?,
            predecessor_id: r.uuid("assignment predecessor")?,
        },
        2 if inventory_version == super::inventory::INVENTORY_VERSION => {
            SourceAssignmentOrigin::HomeHandoff {
                preparation_id: r.uuid("Home handoff preparation")?,
                handoff_id: r.uuid("Home handoff identity")?,
                predecessor_id: r.uuid("Home handoff predecessor")?,
                root_assignment_id: r.uuid("Home handoff root assignment")?,
            }
        }
        2 => {
            return Err(Error::Corrupt(
                "Home handoff origin requires inventory version 3",
            ));
        }
        _ => return Err(Error::Corrupt("assignment origin")),
    };
    let workspace_id = r.uuid("assignment Workspace")?;
    let activity_id = r.uuid("assignment Activity")?;
    let target_agent_id = r.uuid("assignment target Agent")?;
    let target_session_id = r.uuid("assignment target Session")?;
    let target_principal = read_principal(r)?;
    let target_agent_revision = r.i64("assignment target revision")?;
    let coordinator_agent_id = r.uuid("assignment coordinator Agent")?;
    let coordinator_session_id = r.uuid("assignment coordinator Session")?;
    let coordinator_principal = read_principal(r)?;
    let coordinator_revision = r.i64("assignment coordinator revision")?;
    let state = match r.u8("assignment state")? {
        0 => SourceAssignmentState::Offered,
        1 => SourceAssignmentState::Running,
        2 => SourceAssignmentState::Submitted,
        3 => SourceAssignmentState::Accepted,
        4 => SourceAssignmentState::Rejected,
        5 => SourceAssignmentState::Cancelled,
        6 => SourceAssignmentState::Interrupted,
        _ => return Err(Error::Corrupt("assignment state")),
    };
    let cancellation_requested = read_bool(r, "assignment cancellation flag")?;
    let revision = r.i64("assignment revision")?;
    let created_at_ms = r.i64("assignment created time")?;
    let updated_at_ms = r.i64("assignment updated time")?;
    let credit_budget = r.option("assignment credit budget", |r| {
        match r.u8("credit budget")? {
            0 => Ok(SourceWorkCreditBudget::One),
            1 => Ok(SourceWorkCreditBudget::Three),
            2 => Ok(SourceWorkCreditBudget::Five),
            _ => Err(Error::Corrupt("credit budget")),
        }
    })?;
    let result_digest = r.option("assignment result digest", |r| {
        r.array("assignment result digest")
    })?;
    Ok(SourceAssignment {
        assignment_id,
        origin,
        workspace_id,
        activity_id,
        target_agent_id,
        target_session_id,
        target_principal,
        target_agent_revision,
        coordinator_agent_id,
        coordinator_session_id,
        coordinator_principal,
        coordinator_revision,
        state,
        cancellation_requested,
        revision,
        created_at_ms,
        updated_at_ms,
        credit_budget,
        result_digest,
        goal_id: r.uuid("assignment Goal")?,
        goal_created_at_ms: r.i64("assignment Goal created time")?,
        goal_revision: r.i64("assignment Goal revision")?,
        dag_revision: r.i64("assignment DAG revision")?,
        dag_head_revision: r.i64("assignment DAG head revision")?,
        node_id: r.uuid("assignment node")?,
        node_revision: r.i64("assignment node revision")?,
    })
}

fn write_writer_lease(w: &mut ByteWriter, value: &SourceWriterLease) -> Result<(), Error> {
    w.uuid(value.lease_id)?;
    w.uuid(value.workspace_id)?;
    w.uuid(value.activity_id)?;
    w.uuid(value.agent_id)?;
    w.u8(match value.state {
        SourceWriterLeaseState::Active => 0,
        SourceWriterLeaseState::Released => 1,
    })?;
    w.i64(value.revision)?;
    w.i64(value.acquired_at_ms)?;
    w.i64(value.updated_at_ms)?;
    w.i64(value.lease_until_ms)?;
    w.count(
        value.entries.len(),
        MAX_WRITER_LEASE_SCOPE_ENTRIES,
        "Writer Lease entries",
    )?;
    for entry in &value.entries {
        w.u8(match entry.kind {
            SourceWriterLeaseScopeKind::ExactPath => 0,
            SourceWriterLeaseScopeKind::DirectorySubtree => 1,
        })?;
        w.bytes(
            &entry.path,
            MAX_WORKSPACE_RELATIVE_PATH_BYTES,
            "Writer Lease path",
        )?;
    }
    Ok(())
}

fn read_writer_lease(r: &mut ByteReader<'_>) -> Result<SourceWriterLease, Error> {
    let lease_id = r.uuid("Writer Lease identity")?;
    let workspace_id = r.uuid("Writer Lease Workspace")?;
    let activity_id = r.uuid("Writer Lease Activity")?;
    let agent_id = r.uuid("Writer Lease Agent")?;
    let state = match r.u8("Writer Lease state")? {
        0 => SourceWriterLeaseState::Active,
        1 => SourceWriterLeaseState::Released,
        _ => return Err(Error::Corrupt("Writer Lease state")),
    };
    let revision = r.i64("Writer Lease revision")?;
    let acquired_at_ms = r.i64("Writer Lease acquired time")?;
    let updated_at_ms = r.i64("Writer Lease updated time")?;
    let lease_until_ms = r.i64("Writer Lease expiry")?;
    let entry_count = r.count(MAX_WRITER_LEASE_SCOPE_ENTRIES, 5, "Writer Lease entries")?;
    let mut entries = vector_with_capacity(r, entry_count);
    for _ in 0..entry_count {
        let kind = match r.u8("Writer Lease scope kind")? {
            0 => SourceWriterLeaseScopeKind::ExactPath,
            1 => SourceWriterLeaseScopeKind::DirectorySubtree,
            _ => return Err(Error::Corrupt("Writer Lease scope kind")),
        };
        let entry = SourceWriterLeaseEntry {
            kind,
            path: r.bytes(MAX_WORKSPACE_RELATIVE_PATH_BYTES, "Writer Lease path")?,
        };
        push_if_materializing(r, &mut entries, entry);
    }
    Ok(SourceWriterLease {
        lease_id,
        workspace_id,
        activity_id,
        agent_id,
        state,
        revision,
        acquired_at_ms,
        updated_at_ms,
        lease_until_ms,
        entries,
    })
}

fn read_bool(r: &mut ByteReader<'_>, field: &'static str) -> Result<bool, Error> {
    match r.u8(field)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::Corrupt(field)),
    }
}

fn write_execution(w: &mut ByteWriter, value: &SourceExecution) -> Result<(), Error> {
    w.uuid(value.execution_id)?;
    w.uuid(value.workspace_id)?;
    w.uuid(value.activity_id)?;
    w.u8(execution_state_tag(value.state))?;
    w.i64(value.revision)?;
    w.raw(&value.request_digest)?;
    w.i64(value.created_at_ms)?;
    w.i64(value.updated_at_ms)?;
    w.option(value.agent_id, ByteWriter::uuid)?;
    w.option(value.session_id, ByteWriter::uuid)?;
    w.option(value.agent_revision, ByteWriter::i64)?;
    w.option(value.principal, write_principal)?;
    w.option(value.goal_id, ByteWriter::uuid)?;
    w.option(value.goal_revision, ByteWriter::i64)?;
    w.option(value.dag_revision, ByteWriter::i64)?;
    w.option(value.node_id, ByteWriter::uuid)?;
    w.option(value.node_revision, ByteWriter::i64)?;
    w.option(value.command_id.as_deref(), |w, command| {
        w.string(
            command,
            MAX_EXECUTION_COMMAND_ID_BYTES,
            "execution command ID",
        )
    })?;
    w.option(value.project_command, write_project_command)?;
    write_closure(w, &value.closure)
}

fn execution_state_tag(value: SourceExecutionState) -> u8 {
    match value {
        SourceExecutionState::Starting => 0,
        SourceExecutionState::Running => 1,
        SourceExecutionState::Completed => 2,
        SourceExecutionState::Failed => 3,
        SourceExecutionState::TimedOut => 4,
        SourceExecutionState::Cancelled => 5,
        SourceExecutionState::Interrupted => 6,
    }
}

fn read_execution(r: &mut ByteReader<'_>) -> Result<SourceExecution, Error> {
    let execution_id = r.uuid("execution identity")?;
    let workspace_id = r.uuid("execution Workspace")?;
    let activity_id = r.uuid("execution Activity")?;
    let state = match r.u8("execution state")? {
        0 => SourceExecutionState::Starting,
        1 => SourceExecutionState::Running,
        2 => SourceExecutionState::Completed,
        3 => SourceExecutionState::Failed,
        4 => SourceExecutionState::TimedOut,
        5 => SourceExecutionState::Cancelled,
        6 => SourceExecutionState::Interrupted,
        _ => return Err(Error::Corrupt("execution state")),
    };
    let revision = r.i64("execution revision")?;
    let request_digest = r.array("execution request digest")?;
    let created_at_ms = r.i64("execution created time")?;
    let updated_at_ms = r.i64("execution updated time")?;
    let agent_id = r.option("execution Agent", |r| r.uuid("execution Agent"))?;
    let session_id = r.option("execution Session", |r| r.uuid("execution Session"))?;
    let agent_revision = r.option("execution Agent revision", |r| {
        r.i64("execution Agent revision")
    })?;
    let principal = r.option("execution principal", read_principal)?;
    let goal_id = r.option("execution Goal", |r| r.uuid("execution Goal"))?;
    let goal_revision = r.option("execution Goal revision", |r| {
        r.i64("execution Goal revision")
    })?;
    let dag_revision = r.option("execution DAG revision", |r| {
        r.i64("execution DAG revision")
    })?;
    let node_id = r.option("execution node", |r| r.uuid("execution node"))?;
    let node_revision = r.option("execution node revision", |r| {
        r.i64("execution node revision")
    })?;
    let command_id = r.option("execution command ID", |r| {
        r.string(MAX_EXECUTION_COMMAND_ID_BYTES, "execution command ID")
    })?;
    let project_command = r.option("execution project command", read_project_command)?;
    let closure = read_closure(r)?;
    Ok(SourceExecution {
        execution_id,
        workspace_id,
        activity_id,
        state,
        revision,
        request_digest,
        created_at_ms,
        updated_at_ms,
        agent_id,
        session_id,
        agent_revision,
        principal,
        goal_id,
        goal_revision,
        dag_revision,
        node_id,
        node_revision,
        command_id,
        project_command,
        closure,
    })
}

fn write_closure(w: &mut ByteWriter, value: &SourceNativeClosure) -> Result<(), Error> {
    match value {
        SourceNativeClosure::Unknown => w.u8(0),
        SourceNativeClosure::Present {
            before_revision,
            after_revision,
            observed_at_ms,
            final_output_sequence,
            launch,
            runtime,
            process,
        } => {
            w.u8(1)?;
            w.i64(*before_revision)?;
            w.i64(*after_revision)?;
            w.i64(*observed_at_ms)?;
            w.u64(*final_output_sequence)?;
            w.u8(match launch {
                SourceClosureLaunch::Baseline => 0,
                SourceClosureLaunch::RustCi => 1,
                SourceClosureLaunch::GeneratedPackage => 2,
            })?;
            w.u8(match runtime {
                SourceClosureRuntime::NotApplicable => 0,
                SourceClosureRuntime::Cleaned => 1,
            })?;
            w.u8(match process {
                SourceClosureProcess::NoChildSpawned => 0,
                SourceClosureProcess::ProcessGroupReaped => 1,
            })
        }
        SourceNativeClosure::Absent => w.u8(2),
    }
}

fn read_closure(r: &mut ByteReader<'_>) -> Result<SourceNativeClosure, Error> {
    match r.u8("native closure")? {
        0 => Ok(SourceNativeClosure::Unknown),
        1 => {
            let before_revision = r.i64("closure before revision")?;
            let after_revision = r.i64("closure after revision")?;
            let observed_at_ms = r.i64("closure observed time")?;
            let final_output_sequence = r.u64("closure final output sequence")?;
            let launch = match r.u8("closure launch")? {
                0 => SourceClosureLaunch::Baseline,
                1 => SourceClosureLaunch::RustCi,
                2 => SourceClosureLaunch::GeneratedPackage,
                _ => return Err(Error::Corrupt("closure launch")),
            };
            let runtime = match r.u8("closure runtime")? {
                0 => SourceClosureRuntime::NotApplicable,
                1 => SourceClosureRuntime::Cleaned,
                _ => return Err(Error::Corrupt("closure runtime")),
            };
            let process = match r.u8("closure process")? {
                0 => SourceClosureProcess::NoChildSpawned,
                1 => SourceClosureProcess::ProcessGroupReaped,
                _ => return Err(Error::Corrupt("closure process")),
            };
            Ok(SourceNativeClosure::Present {
                before_revision,
                after_revision,
                observed_at_ms,
                final_output_sequence,
                launch,
                runtime,
                process,
            })
        }
        2 => Ok(SourceNativeClosure::Absent),
        _ => Err(Error::Corrupt("native closure")),
    }
}

fn write_action(w: &mut ByteWriter, value: SourceExecutionActionClass) -> Result<(), Error> {
    w.u8(match value {
        SourceExecutionActionClass::DirectStructured => 0,
        SourceExecutionActionClass::DiscoveredProjectCommand => 1,
        SourceExecutionActionClass::ShellEscape => 2,
        SourceExecutionActionClass::AnalyzedShell => 3,
        SourceExecutionActionClass::GeneratedProjectCommand => 4,
    })
}

fn read_action(r: &mut ByteReader<'_>) -> Result<SourceExecutionActionClass, Error> {
    match r.u8("execution action")? {
        0 => Ok(SourceExecutionActionClass::DirectStructured),
        1 => Ok(SourceExecutionActionClass::DiscoveredProjectCommand),
        2 => Ok(SourceExecutionActionClass::ShellEscape),
        3 => Ok(SourceExecutionActionClass::AnalyzedShell),
        4 => Ok(SourceExecutionActionClass::GeneratedProjectCommand),
        _ => Err(Error::Corrupt("execution action")),
    }
}

fn write_permissions(w: &mut ByteWriter, value: SourceExecutionPermissions) -> Result<(), Error> {
    w.u8(u8::from(value.workspace_read))?;
    w.u8(u8::from(value.workspace_write))?;
    w.u8(u8::from(value.network))
}

fn read_permissions(r: &mut ByteReader<'_>) -> Result<SourceExecutionPermissions, Error> {
    Ok(SourceExecutionPermissions {
        workspace_read: read_bool(r, "workspace read permission")?,
        workspace_write: read_bool(r, "workspace write permission")?,
        network: read_bool(r, "network permission")?,
    })
}

fn write_approval_state(w: &mut ByteWriter, value: SourceApprovalState) -> Result<(), Error> {
    w.u8(match value {
        SourceApprovalState::Pending => 0,
        SourceApprovalState::Approved => 1,
        SourceApprovalState::AutoApproved => 2,
        SourceApprovalState::Rejected => 3,
        SourceApprovalState::Denied => 4,
        SourceApprovalState::Cancelled => 5,
        SourceApprovalState::Expired => 6,
        SourceApprovalState::Superseded => 7,
    })
}

fn read_approval_state(r: &mut ByteReader<'_>) -> Result<SourceApprovalState, Error> {
    match r.u8("approval state")? {
        0 => Ok(SourceApprovalState::Pending),
        1 => Ok(SourceApprovalState::Approved),
        2 => Ok(SourceApprovalState::AutoApproved),
        3 => Ok(SourceApprovalState::Rejected),
        4 => Ok(SourceApprovalState::Denied),
        5 => Ok(SourceApprovalState::Cancelled),
        6 => Ok(SourceApprovalState::Expired),
        7 => Ok(SourceApprovalState::Superseded),
        _ => Err(Error::Corrupt("approval state")),
    }
}

fn write_approval(w: &mut ByteWriter, value: &SourceApproval) -> Result<(), Error> {
    w.uuid(value.approval_id)?;
    w.uuid(value.workspace_id)?;
    w.uuid(value.activity_id)?;
    w.uuid(value.execution_id)?;
    w.raw(&value.request_digest)?;
    write_action(w, value.action)?;
    write_permissions(w, value.requested_permissions)?;
    w.i64(value.policy_revision)?;
    write_approval_state(w, value.state)?;
    w.i64(value.revision)?;
    w.i64(value.created_at_ms)?;
    w.i64(value.updated_at_ms)?;
    w.i64(value.expires_at_ms)?;
    w.option(value.agent_binding_digest.as_deref(), |w, digest| {
        w.bytes(digest, 32, "approval binding digest")
    })?;
    write_attribution(w, &value.attribution)?;
    write_grant(w, &value.grant)
}

fn read_approval(
    r: &mut ByteReader<'_>,
    budget: &mut RecordBudget,
) -> Result<SourceApproval, Error> {
    let approval_id = r.uuid("approval identity")?;
    let workspace_id = r.uuid("approval Workspace")?;
    let activity_id = r.uuid("approval Activity")?;
    let execution_id = r.uuid("approval execution")?;
    let request_digest = r.array("approval request digest")?;
    let action = read_action(r)?;
    let requested_permissions = read_permissions(r)?;
    let policy_revision = r.i64("approval policy revision")?;
    let state = read_approval_state(r)?;
    let revision = r.i64("approval revision")?;
    let created_at_ms = r.i64("approval created time")?;
    let updated_at_ms = r.i64("approval updated time")?;
    let expires_at_ms = r.i64("approval expiry")?;
    let agent_binding_digest = r.option("approval binding digest", |r| {
        r.bytes(32, "approval binding digest")
    })?;
    let attribution = read_attribution(r)?;
    let grant_tag = r.u8("approval grant")?;
    if grant_tag == 2 {
        budget.add(1)?;
    }
    let grant = read_grant(r, grant_tag)?;
    Ok(SourceApproval {
        approval_id,
        workspace_id,
        activity_id,
        execution_id,
        request_digest,
        action,
        requested_permissions,
        policy_revision,
        state,
        revision,
        created_at_ms,
        updated_at_ms,
        expires_at_ms,
        agent_binding_digest,
        attribution,
        grant,
    })
}

fn write_attribution(w: &mut ByteWriter, value: &SourceApprovalAttribution) -> Result<(), Error> {
    match value {
        SourceApprovalAttribution::LegacyUnknown => w.u8(0),
        SourceApprovalAttribution::Known {
            agent_id,
            session_id,
            agent_revision,
            principal,
            goal_id,
            goal_revision,
            dag_revision,
            node_id,
            node_revision,
            command_id,
            project_command,
        } => {
            w.u8(1)?;
            w.uuid(*agent_id)?;
            w.option(*session_id, ByteWriter::uuid)?;
            w.i64(*agent_revision)?;
            write_principal(w, *principal)?;
            w.uuid(*goal_id)?;
            w.i64(*goal_revision)?;
            w.i64(*dag_revision)?;
            w.uuid(*node_id)?;
            w.i64(*node_revision)?;
            w.string(
                command_id,
                MAX_EXECUTION_COMMAND_ID_BYTES,
                "approval command ID",
            )?;
            w.option(*project_command, write_project_command)
        }
    }
}

fn read_attribution(r: &mut ByteReader<'_>) -> Result<SourceApprovalAttribution, Error> {
    match r.u8("approval attribution")? {
        0 => Ok(SourceApprovalAttribution::LegacyUnknown),
        1 => Ok(SourceApprovalAttribution::Known {
            agent_id: r.uuid("approval Agent")?,
            session_id: r.option("approval Session", |r| r.uuid("approval Session"))?,
            agent_revision: r.i64("approval Agent revision")?,
            principal: read_principal(r)?,
            goal_id: r.uuid("approval Goal")?,
            goal_revision: r.i64("approval Goal revision")?,
            dag_revision: r.i64("approval DAG revision")?,
            node_id: r.uuid("approval node")?,
            node_revision: r.i64("approval node revision")?,
            command_id: r.string(MAX_EXECUTION_COMMAND_ID_BYTES, "approval command ID")?,
            project_command: r.option("approval project command", read_project_command)?,
        }),
        _ => Err(Error::Corrupt("approval attribution")),
    }
}

fn write_grant(w: &mut ByteWriter, value: &SourceApprovalGrant) -> Result<(), Error> {
    match value {
        SourceApprovalGrant::Unknown => w.u8(0),
        SourceApprovalGrant::Absent => w.u8(1),
        SourceApprovalGrant::Present {
            grant_id,
            state,
            revision,
            expires_at_ms,
            consumed_at_ms,
            request_digest,
            action,
            effective_permissions,
            policy_revision,
            source,
        } => {
            w.u8(2)?;
            w.uuid(*grant_id)?;
            w.u8(match state {
                SourceExecutionGrantState::Active => 0,
                SourceExecutionGrantState::Consumed => 1,
                SourceExecutionGrantState::Expired => 2,
                SourceExecutionGrantState::Revoked => 3,
            })?;
            w.i64(*revision)?;
            w.i64(*expires_at_ms)?;
            w.option(*consumed_at_ms, ByteWriter::i64)?;
            w.raw(request_digest)?;
            write_action(w, *action)?;
            write_permissions(w, *effective_permissions)?;
            w.i64(*policy_revision)?;
            w.u8(match source {
                SourceAuthorizationSource::ExplicitGrant => 0,
                SourceAuthorizationSource::AutoApprovalScope => 1,
                SourceAuthorizationSource::LegacyPlan06 => 2,
            })
        }
    }
}

fn read_grant(r: &mut ByteReader<'_>, tag: u8) -> Result<SourceApprovalGrant, Error> {
    match tag {
        0 => Ok(SourceApprovalGrant::Unknown),
        1 => Ok(SourceApprovalGrant::Absent),
        2 => {
            let grant_id = r.uuid("grant identity")?;
            let state = match r.u8("grant state")? {
                0 => SourceExecutionGrantState::Active,
                1 => SourceExecutionGrantState::Consumed,
                2 => SourceExecutionGrantState::Expired,
                3 => SourceExecutionGrantState::Revoked,
                _ => return Err(Error::Corrupt("grant state")),
            };
            Ok(SourceApprovalGrant::Present {
                grant_id,
                state,
                revision: r.i64("grant revision")?,
                expires_at_ms: r.i64("grant expiry")?,
                consumed_at_ms: r
                    .option("grant consumed time", |r| r.i64("grant consumed time"))?,
                request_digest: r.array("grant request digest")?,
                action: read_action(r)?,
                effective_permissions: read_permissions(r)?,
                policy_revision: r.i64("grant policy revision")?,
                source: match r.u8("grant source")? {
                    0 => SourceAuthorizationSource::ExplicitGrant,
                    1 => SourceAuthorizationSource::AutoApprovalScope,
                    2 => SourceAuthorizationSource::LegacyPlan06,
                    _ => return Err(Error::Corrupt("grant source")),
                },
            })
        }
        _ => Err(Error::Corrupt("approval grant")),
    }
}

fn write_change_set(w: &mut ByteWriter, value: &SourceChangeSet) -> Result<(), Error> {
    w.uuid(value.change_set_id)?;
    w.uuid(value.workspace_id)?;
    w.uuid(value.activity_id)?;
    w.uuid(value.runtime_instance_id)?;
    w.i64(value.workspace_revision)?;
    w.i64(value.activity_lease_revision)?;
    w.u8(match value.state {
        SourceChangeSetState::Starting => 0,
        SourceChangeSetState::Applied => 1,
        SourceChangeSetState::Failed => 2,
    })?;
    w.option(value.source_tree_request_digest, |w, digest| w.raw(&digest))?;
    w.i64(value.revision)?;
    w.i64(value.created_at_ms)?;
    w.i64(value.updated_at_ms)?;
    w.option(value.file_mutation.as_ref(), write_file_mutation)?;
    w.count(
        value.tree_mutations.len(),
        MAX_TREE_CHANGESET_MUTATIONS,
        "tree mutations",
    )?;
    for mutation in &value.tree_mutations {
        write_tree_mutation(w, mutation)?;
    }
    Ok(())
}

fn read_change_set(
    r: &mut ByteReader<'_>,
    budget: &mut RecordBudget,
) -> Result<SourceChangeSet, Error> {
    let change_set_id = r.uuid("ChangeSet identity")?;
    let workspace_id = r.uuid("ChangeSet Workspace")?;
    let activity_id = r.uuid("ChangeSet Activity")?;
    let runtime_instance_id = r.uuid("ChangeSet runtime")?;
    let workspace_revision = r.i64("ChangeSet Workspace revision")?;
    let activity_lease_revision = r.i64("ChangeSet Activity Lease revision")?;
    let state = match r.u8("ChangeSet state")? {
        0 => SourceChangeSetState::Starting,
        1 => SourceChangeSetState::Applied,
        2 => SourceChangeSetState::Failed,
        _ => return Err(Error::Corrupt("ChangeSet state")),
    };
    let source_tree_request_digest =
        r.option("tree request digest", |r| r.array("tree request digest"))?;
    let revision = r.i64("ChangeSet revision")?;
    let created_at_ms = r.i64("ChangeSet created time")?;
    let updated_at_ms = r.i64("ChangeSet updated time")?;
    let file_tag = r.u8("file mutation option")?;
    let file_mutation = match file_tag {
        0 => None,
        1 => {
            budget.add(1)?;
            Some(read_file_mutation(r)?)
        }
        _ => return Err(Error::Corrupt("file mutation option")),
    };
    let tree_count = r.count(MAX_TREE_CHANGESET_MUTATIONS, 16, "tree mutations")?;
    budget.add(tree_count)?;
    let mut tree_mutations = vector_with_capacity(r, tree_count);
    for _ in 0..tree_count {
        let mutation = read_tree_mutation(r)?;
        push_if_materializing(r, &mut tree_mutations, mutation);
    }
    Ok(SourceChangeSet {
        change_set_id,
        workspace_id,
        activity_id,
        runtime_instance_id,
        workspace_revision,
        activity_lease_revision,
        state,
        source_tree_request_digest,
        revision,
        created_at_ms,
        updated_at_ms,
        file_mutation,
        tree_mutations,
    })
}

fn write_file_mutation(w: &mut ByteWriter, value: &SourceFileMutation) -> Result<(), Error> {
    w.uuid(value.mutation_id)?;
    w.bytes(
        &value.path,
        MAX_WORKSPACE_RELATIVE_PATH_BYTES,
        "file mutation path",
    )?;
    w.u8(match value.kind {
        SourceFileMutationKind::Create => 0,
        SourceFileMutationKind::Replace => 1,
        SourceFileMutationKind::Delete => 2,
    })?;
    match value.precondition {
        SourceFilePrecondition::Absent => w.u8(0)?,
        SourceFilePrecondition::Matches { expected_hash } => {
            w.u8(1)?;
            w.raw(&expected_hash)?;
        }
    }
    w.option(value.intended_hash, |w, digest| w.raw(&digest))?;
    write_path_state(w, value.pre_state)?;
    w.option(value.post_state, write_path_state)?;
    w.i64(value.revision)
}

fn read_file_mutation(r: &mut ByteReader<'_>) -> Result<SourceFileMutation, Error> {
    let mutation_id = r.uuid("file mutation identity")?;
    let path = r.bytes(MAX_WORKSPACE_RELATIVE_PATH_BYTES, "file mutation path")?;
    let kind = match r.u8("file mutation kind")? {
        0 => SourceFileMutationKind::Create,
        1 => SourceFileMutationKind::Replace,
        2 => SourceFileMutationKind::Delete,
        _ => return Err(Error::Corrupt("file mutation kind")),
    };
    let precondition = match r.u8("file precondition")? {
        0 => SourceFilePrecondition::Absent,
        1 => SourceFilePrecondition::Matches {
            expected_hash: r.array("file expected hash")?,
        },
        _ => return Err(Error::Corrupt("file precondition")),
    };
    Ok(SourceFileMutation {
        mutation_id,
        path,
        kind,
        precondition,
        intended_hash: r.option("file intended hash", |r| r.array("file intended hash"))?,
        pre_state: read_path_state(r)?,
        post_state: r.option("file post-state", read_path_state)?,
        revision: r.i64("file mutation revision")?,
    })
}

fn write_path_state(w: &mut ByteWriter, value: SourceFilePathState) -> Result<(), Error> {
    match value {
        SourceFilePathState::Absent => w.u8(0),
        SourceFilePathState::Regular { hash, size } => {
            w.u8(1)?;
            w.raw(&hash)?;
            w.u64(size)
        }
    }
}

fn read_path_state(r: &mut ByteReader<'_>) -> Result<SourceFilePathState, Error> {
    match r.u8("file path state")? {
        0 => Ok(SourceFilePathState::Absent),
        1 => Ok(SourceFilePathState::Regular {
            hash: r.array("file state hash")?,
            size: r.u64("file state size")?,
        }),
        _ => Err(Error::Corrupt("file path state")),
    }
}

fn write_tree_mutation(w: &mut ByteWriter, value: &SourceTreeMutation) -> Result<(), Error> {
    w.uuid(value.mutation_id)?;
    w.i64(value.ordinal)?;
    w.u8(match value.kind {
        SourceTreeMutationKind::CreateDirectory => 0,
        SourceTreeMutationKind::CreateFile => 1,
        SourceTreeMutationKind::UpdateFile => 2,
        SourceTreeMutationKind::DeleteFile => 3,
        SourceTreeMutationKind::MoveFile => 4,
        SourceTreeMutationKind::MoveDirectory => 5,
        SourceTreeMutationKind::DeleteDirectory => 6,
    })?;
    w.bytes(
        &value.primary_path,
        MAX_WORKSPACE_RELATIVE_PATH_BYTES,
        "tree primary path",
    )?;
    w.option(value.secondary_path.as_deref(), |w, path| {
        w.bytes(
            path,
            MAX_WORKSPACE_RELATIVE_PATH_BYTES,
            "tree secondary path",
        )
    })?;
    w.option(value.expected_hash, |w, digest| w.raw(&digest))?;
    w.option(value.intended_hash, |w, digest| w.raw(&digest))?;
    w.u8(u8::from(value.applied))?;
    w.i64(value.revision)
}

fn read_tree_mutation(r: &mut ByteReader<'_>) -> Result<SourceTreeMutation, Error> {
    let mutation_id = r.uuid("tree mutation identity")?;
    let ordinal = r.i64("tree mutation ordinal")?;
    let kind = match r.u8("tree mutation kind")? {
        0 => SourceTreeMutationKind::CreateDirectory,
        1 => SourceTreeMutationKind::CreateFile,
        2 => SourceTreeMutationKind::UpdateFile,
        3 => SourceTreeMutationKind::DeleteFile,
        4 => SourceTreeMutationKind::MoveFile,
        5 => SourceTreeMutationKind::MoveDirectory,
        6 => SourceTreeMutationKind::DeleteDirectory,
        _ => return Err(Error::Corrupt("tree mutation kind")),
    };
    Ok(SourceTreeMutation {
        mutation_id,
        ordinal,
        kind,
        primary_path: r.bytes(MAX_WORKSPACE_RELATIVE_PATH_BYTES, "tree primary path")?,
        secondary_path: r.option("tree secondary path", |r| {
            r.bytes(MAX_WORKSPACE_RELATIVE_PATH_BYTES, "tree secondary path")
        })?,
        expected_hash: r.option("tree expected hash", |r| r.array("tree expected hash"))?,
        intended_hash: r.option("tree intended hash", |r| r.array("tree intended hash"))?,
        applied: read_bool(r, "tree mutation applied flag")?,
        revision: r.i64("tree mutation revision")?,
    })
}

#[cfg(test)]
mod tests {
    use forge_domain::{
        ActivityId, AgentInstanceId, AgentSessionId, AuthenticatedPrincipal, ForgeBackendId,
        HomeTransferSourceBinding, HomeTransferSourceRequest, HomeTransferSourceScope,
        HomeTransferSourceSubject, HomeTransferSourceWitness, WorkspaceId, WorkspaceRevision,
    };
    use uuid::Uuid;

    use super::*;

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn request() -> Result<HomeTransferSourceRequest, Box<dyn std::error::Error>> {
        let workspace_id = id(1);
        let activity_id = id(3);
        let agent_id = id(4);
        let session_id = id(2);
        let scope = HomeTransferSourceScope::new(
            WorkspaceId::from_uuid(workspace_id),
            WorkspaceRevision::new(7)?,
            ForgeBackendId::from_uuid(id(5)),
            id(6),
        )?;
        let subject = HomeTransferSourceSubject::new(id(7), 1, id(8), id(9), id(10), id(11), 1, 1)?;
        let witness = HomeTransferSourceWitness::new(id(12), [0x51; 32], [0x52; 32])?;
        let binding = HomeTransferSourceBinding::new(
            ActivityId::from_uuid(activity_id),
            AgentInstanceId::from_uuid(agent_id),
            AgentSessionId::from_uuid(session_id),
            AuthenticatedPrincipal::TrustedStdio,
        )?;
        Ok(HomeTransferSourceRequest::new(
            witness,
            scope,
            subject,
            vec![AgentSessionId::from_uuid(session_id)],
            vec![binding],
        )?)
    }

    fn empty_inventory(
        request: &HomeTransferSourceRequest,
        version: u8,
    ) -> HomeTransferSourceInventory {
        HomeTransferSourceInventory {
            version,
            request_digest: *request.request_digest().as_bytes(),
            workspace_id: request.scope().workspace_id().into_uuid(),
            workspace_revision: request.scope().workspace_revision().get(),
            session_ids: request
                .sessions()
                .iter()
                .map(|session| session.into_uuid())
                .collect(),
            agents: Vec::new(),
            reservations: Vec::new(),
            assignments: Vec::new(),
            writer_leases: Vec::new(),
            executions: Vec::new(),
            closed_execution_count: 0,
            closed_execution_digest: [0; 32],
            closed_execution_high_water_ms: 0,
            approvals: Vec::new(),
            change_sets: Vec::new(),
            affected_activity_ids: Vec::new(),
            affected_agent_ids: Vec::new(),
            source_high_water_ms: 0,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one populated DTO fixture exercises the complete closed codec shape"
    )]
    fn populated_inventory(
        request: &HomeTransferSourceRequest,
    ) -> Result<HomeTransferSourceInventory, Box<dyn std::error::Error>> {
        let workspace_id = request.scope().workspace_id().into_uuid();
        let activity_id = id(3);
        let agent_id = id(4);
        let session_id = id(2);
        let goal_id = id(100);
        let node_id = id(101);
        let principal = SourcePrincipal::TrustedStdio;
        let action = SourceExecutionActionClass::DiscoveredProjectCommand;
        let permissions = SourceExecutionPermissions {
            workspace_read: true,
            workspace_write: false,
            network: false,
        };
        let execution_digest = [0x81; 32];
        let project_command = SourceProjectCommand {
            class: SourceProjectCommandClass::Verify,
            catalog_fingerprint: [0x82; 32],
        };
        let agent = SourceAgent {
            agent_id,
            workspace_id,
            activity_id,
            session_id: Some(session_id),
            principal,
            display_name: "Source Agent".to_owned(),
            declared_role: "Worker".to_owned(),
            transport: SourceTransport::Stdio,
            attachment: SourceAttachment::Attached,
            revision: 2,
            created_at_ms: 1,
            updated_at_ms: 35,
            focus: SourceFocus {
                goal_id: Some(goal_id),
                goal_revision: Some(2),
                dag_revision: Some(3),
                node_id: None,
                node_revision: None,
            },
        };
        let reservations = vec![
            SourceBindingReservation {
                request_id: id(60),
                workspace_id,
                activity_id,
                migration_id: id(61),
                destination_id: id(6),
                freeze_revision: 2,
                agent_id,
                session_id,
                principal,
                requested_at_ms: 10,
                reserved_at_ms: 11,
                outcome: SourceReservationOutcome::Pending,
            },
            SourceBindingReservation {
                request_id: id(62),
                workspace_id,
                activity_id,
                migration_id: id(63),
                destination_id: id(6),
                freeze_revision: 2,
                agent_id,
                session_id,
                principal,
                requested_at_ms: 11,
                reserved_at_ms: 12,
                outcome: SourceReservationOutcome::Activated {
                    membership_digest: [0x64; 32],
                    display_name: "Activated Agent".to_owned(),
                    declared_role: "Worker".to_owned(),
                    transport: SourceTransport::Stdio,
                    activated_at_ms: 13,
                },
            },
            SourceBindingReservation {
                request_id: id(65),
                workspace_id,
                activity_id,
                migration_id: id(66),
                destination_id: id(6),
                freeze_revision: 2,
                agent_id,
                session_id,
                principal,
                requested_at_ms: 12,
                reserved_at_ms: 13,
                outcome: SourceReservationOutcome::Rejected {
                    request_digest: [0x67; 32],
                    receipt_digest: [0x68; 32],
                    rejected_at_ms: 14,
                    reason: SourceRejectionReason::PrincipalTransportMismatch,
                },
            },
        ];
        let assignment = |assignment_id,
                          origin,
                          state,
                          cancellation_requested,
                          credit_budget,
                          result_digest,
                          created_at_ms| {
            SourceAssignment {
                assignment_id,
                origin,
                workspace_id,
                activity_id,
                target_agent_id: agent_id,
                target_session_id: session_id,
                target_principal: principal,
                target_agent_revision: 2,
                coordinator_agent_id: id(42),
                coordinator_session_id: id(43),
                coordinator_principal: SourcePrincipal::DirectToken(id(44)),
                coordinator_revision: 3,
                state,
                cancellation_requested,
                revision: if state == SourceAssignmentState::Submitted {
                    2
                } else {
                    1
                },
                created_at_ms,
                updated_at_ms: created_at_ms + 1,
                credit_budget,
                result_digest,
                goal_id,
                goal_created_at_ms: 9,
                goal_revision: 2,
                dag_revision: 3,
                dag_head_revision: 4,
                node_id,
                node_revision: 5,
            }
        };
        let assignments = vec![
            assignment(
                id(70),
                SourceAssignmentOrigin::CoordinatorOffer,
                SourceAssignmentState::Offered,
                false,
                None,
                None,
                15,
            ),
            assignment(
                id(71),
                SourceAssignmentOrigin::CutContinuation {
                    cut_id: id(72),
                    transfer_id: id(73),
                    predecessor_id: id(74),
                },
                SourceAssignmentState::Submitted,
                true,
                Some(SourceWorkCreditBudget::Five),
                Some([0x75; 32]),
                17,
            ),
        ];
        let writer_leases = vec![SourceWriterLease {
            lease_id: id(76),
            workspace_id,
            activity_id,
            agent_id,
            state: SourceWriterLeaseState::Active,
            revision: 1,
            acquired_at_ms: 20,
            updated_at_ms: 21,
            lease_until_ms: 40,
            entries: vec![SourceWriterLeaseEntry {
                kind: SourceWriterLeaseScopeKind::DirectorySubtree,
                path: b"src".to_vec(),
            }],
        }];
        let executions = vec![
            SourceExecution {
                execution_id: id(80),
                workspace_id,
                activity_id,
                state: SourceExecutionState::Running,
                revision: 2,
                request_digest: execution_digest,
                created_at_ms: 20,
                updated_at_ms: 24,
                agent_id: Some(agent_id),
                session_id: Some(session_id),
                agent_revision: Some(2),
                principal: Some(principal),
                goal_id: Some(goal_id),
                goal_revision: Some(2),
                dag_revision: Some(3),
                node_id: Some(node_id),
                node_revision: Some(5),
                command_id: Some("verify".to_owned()),
                project_command: Some(project_command),
                closure: SourceNativeClosure::Absent,
            },
            SourceExecution {
                execution_id: id(81),
                workspace_id,
                activity_id,
                state: SourceExecutionState::Completed,
                revision: 1,
                request_digest: [0x83; 32],
                created_at_ms: 25,
                updated_at_ms: 26,
                agent_id: None,
                session_id: None,
                agent_revision: None,
                principal: None,
                goal_id: None,
                goal_revision: None,
                dag_revision: None,
                node_id: None,
                node_revision: None,
                command_id: None,
                project_command: None,
                closure: SourceNativeClosure::Absent,
            },
        ];
        let mut approvals = vec![
            SourceApproval {
                approval_id: id(90),
                workspace_id,
                activity_id,
                execution_id: id(80),
                request_digest: execution_digest,
                action,
                requested_permissions: permissions,
                policy_revision: 1,
                state: SourceApprovalState::Approved,
                revision: 2,
                created_at_ms: 28,
                updated_at_ms: 29,
                expires_at_ms: 50,
                agent_binding_digest: Some(vec![0x91; 32]),
                attribution: SourceApprovalAttribution::Known {
                    agent_id,
                    session_id: None,
                    agent_revision: 2,
                    principal,
                    goal_id,
                    goal_revision: 2,
                    dag_revision: 3,
                    node_id,
                    node_revision: 5,
                    command_id: "verify".to_owned(),
                    project_command: Some(project_command),
                },
                grant: SourceApprovalGrant::Present {
                    grant_id: id(92),
                    state: SourceExecutionGrantState::Active,
                    revision: 1,
                    expires_at_ms: 50,
                    consumed_at_ms: None,
                    request_digest: execution_digest,
                    action,
                    effective_permissions: permissions,
                    policy_revision: 1,
                    source: SourceAuthorizationSource::ExplicitGrant,
                },
            },
            SourceApproval {
                approval_id: id(93),
                workspace_id,
                activity_id,
                execution_id: id(81),
                request_digest: [0x94; 32],
                action: SourceExecutionActionClass::ShellEscape,
                requested_permissions: SourceExecutionPermissions {
                    workspace_read: true,
                    workspace_write: true,
                    network: false,
                },
                policy_revision: 2,
                state: SourceApprovalState::Pending,
                revision: 1,
                created_at_ms: 30,
                updated_at_ms: 31,
                expires_at_ms: 60,
                agent_binding_digest: None,
                attribution: SourceApprovalAttribution::LegacyUnknown,
                grant: SourceApprovalGrant::Unknown,
            },
        ];
        // Bind the rich fixture to the same canonical provenance as production.
        {
            use forge_domain::{
                AgentInstanceRevision, ApprovalAgentBindingDigest, DagNodeId, DagNodeRevision,
                DagRevisionNumber, ExecutionAgentProvenance, ExecutionCommandId, ExecutionId,
                FileContentHash, GoalId, GoalNodeAttribution, GoalRevision,
                ProjectCommandCatalogFingerprint, ProjectCommandClass, ProjectCommandEvidence,
            };
            let provenance = ExecutionAgentProvenance::from_parts(
                ExecutionId::from_uuid(id(80)),
                AgentInstanceId::from_uuid(agent_id),
                AgentInstanceRevision::new(2)?,
                AuthenticatedPrincipal::TrustedStdio,
                GoalNodeAttribution::new(
                    GoalId::from_uuid(goal_id),
                    GoalRevision::new(2)?,
                    DagRevisionNumber::new(3)?,
                    DagNodeId::from_uuid(node_id),
                    DagNodeRevision::new(5)?,
                ),
                ExecutionCommandId::new("verify".to_owned())?,
                None,
            )
            .with_project_command(ProjectCommandEvidence::new(
                ProjectCommandClass::Verify,
                ProjectCommandCatalogFingerprint::from_hash(FileContentHash::from_bytes(
                    [0x82; 32],
                )),
            ));
            approvals[0].agent_binding_digest = Some(
                ApprovalAgentBindingDigest::from_provenance(&provenance)
                    .as_bytes()
                    .to_vec(),
            );
        }
        let change_sets = vec![
            SourceChangeSet {
                change_set_id: id(95),
                workspace_id,
                activity_id,
                runtime_instance_id: id(96),
                workspace_revision: 7,
                activity_lease_revision: 2,
                state: SourceChangeSetState::Failed,
                source_tree_request_digest: None,
                revision: 1,
                created_at_ms: 38,
                updated_at_ms: 40,
                file_mutation: Some(SourceFileMutation {
                    mutation_id: id(97),
                    path: b"notes.txt".to_vec(),
                    kind: SourceFileMutationKind::Create,
                    precondition: SourceFilePrecondition::Absent,
                    intended_hash: Some([0x98; 32]),
                    pre_state: SourceFilePathState::Absent,
                    post_state: None,
                    revision: 1,
                }),
                tree_mutations: Vec::new(),
            },
            SourceChangeSet {
                change_set_id: id(99),
                workspace_id,
                activity_id,
                runtime_instance_id: id(100),
                workspace_revision: 7,
                activity_lease_revision: 2,
                state: SourceChangeSetState::Failed,
                source_tree_request_digest: Some([0x9a; 32]),
                revision: 1,
                created_at_ms: 40,
                updated_at_ms: 42,
                file_mutation: None,
                tree_mutations: vec![SourceTreeMutation {
                    mutation_id: id(101),
                    ordinal: 0,
                    kind: SourceTreeMutationKind::CreateFile,
                    primary_path: b"src/new.rs".to_vec(),
                    secondary_path: None,
                    expected_hash: None,
                    intended_hash: Some([0x9b; 32]),
                    applied: false,
                    revision: 1,
                }],
            },
        ];
        Ok(HomeTransferSourceInventory {
            version: 1,
            request_digest: *request.request_digest().as_bytes(),
            workspace_id,
            workspace_revision: 7,
            session_ids: vec![session_id],
            agents: vec![agent],
            reservations,
            assignments,
            writer_leases,
            executions,
            closed_execution_count: 1,
            closed_execution_digest: [0x9c; 32],
            closed_execution_high_water_ms: 27,
            approvals,
            change_sets,
            affected_activity_ids: vec![activity_id],
            affected_agent_ids: vec![agent_id],
            source_high_water_ms: 42,
        })
    }

    #[test]
    fn round_trips_populated_inventory_and_preserves_optional_provenance()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = request()?;
        let inventory = populated_inventory(&request)?;
        let encoded = encode(&inventory)?;
        assert_eq!(decode(&encoded, &request)?, inventory);
        assert_eq!(encoded[5], 1, "the populated legacy fixture stays v1");
        assert_eq!(encode(&decode(&encoded, &request)?)?, encoded);
        Ok(())
    }

    #[test]
    fn empty_v1_inventory_keeps_the_original_canonical_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = request()?;
        let request = HomeTransferSourceRequest::new(
            source.witness(),
            source.scope(),
            source.subject(),
            source.sessions().to_vec(),
            Vec::new(),
        )?;
        let inventory = empty_inventory(&request, 1);
        let encoded = encode(&inventory)?;

        let mut legacy = Vec::new();
        legacy.extend_from_slice(MAGIC);
        legacy.push(CODEC_VERSION);
        legacy.push(1);
        legacy.extend_from_slice(request.request_digest().as_bytes());
        legacy.extend_from_slice(request.scope().workspace_id().into_uuid().as_bytes());
        legacy.extend_from_slice(&request.scope().workspace_revision().get().to_be_bytes());
        legacy.extend_from_slice(&1_u32.to_be_bytes());
        legacy.extend_from_slice(request.sessions()[0].into_uuid().as_bytes());
        for _ in 0..5 {
            legacy.extend_from_slice(&0_u32.to_be_bytes());
        }
        legacy.extend_from_slice(&0_u64.to_be_bytes());
        legacy.extend_from_slice(&[0; 32]);
        legacy.extend_from_slice(&0_i64.to_be_bytes());
        for _ in 0..4 {
            legacy.extend_from_slice(&0_u32.to_be_bytes());
        }
        legacy.extend_from_slice(&0_i64.to_be_bytes());

        assert_eq!(encoded, legacy);
        assert_eq!(decode(&encoded, &request)?, inventory);
        Ok(())
    }

    #[test]
    fn v2_retirement_round_trips_and_v1_rejects_its_tag() -> Result<(), Box<dyn std::error::Error>>
    {
        let request = request()?;
        let mut inventory = populated_inventory(&request)?;
        inventory.version = 2;
        inventory.reservations[0].outcome = SourceReservationOutcome::Retired {
            preparation_id: id(120),
            request_digest: [0xA1; 32],
            receipt_digest: [0xA2; 32],
            observed_at_ms: 15,
        };
        let encoded = encode(&inventory)?;
        assert_eq!(encoded[5], 2);
        assert_eq!(decode(&encoded, &request)?, inventory);
        assert_eq!(encode(&decode(&encoded, &request)?)?, encoded);

        let mut v1_inventory = inventory.clone();
        v1_inventory.version = 1;
        assert!(matches!(
            encode(&v1_inventory),
            Err(Error::Corrupt("retirement requires inventory version 2"))
        ));

        let mut retired_tag_in_v1 = encoded;
        retired_tag_in_v1[5] = 1;
        assert!(matches!(
            decode(&retired_tag_in_v1, &request),
            Err(Error::Corrupt("retirement requires inventory version 2"))
        ));
        Ok(())
    }

    #[test]
    fn current_writer_preserves_v2_unless_home_origin_requires_v3()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = request()?;
        let mut inventory = populated_inventory(&request)?;
        assert_eq!(
            super::super::inventory::current_inventory_version(&inventory.assignments,),
            super::super::inventory::CURRENT_NON_HOME_INVENTORY_VERSION
        );

        inventory.reservations[0].outcome = SourceReservationOutcome::Retired {
            preparation_id: id(120),
            request_digest: [0xA1; 32],
            receipt_digest: [0xA2; 32],
            observed_at_ms: 15,
        };
        assert_eq!(
            super::super::inventory::current_inventory_version(&inventory.assignments,),
            2
        );

        inventory.assignments[0].origin = SourceAssignmentOrigin::HomeHandoff {
            preparation_id: id(121),
            handoff_id: id(122),
            predecessor_id: id(123),
            root_assignment_id: id(124),
        };
        assert_eq!(
            super::super::inventory::current_inventory_version(&inventory.assignments,),
            3
        );
        Ok(())
    }

    #[test]
    fn v3_home_handoff_origin_round_trips_and_earlier_versions_reject_its_tag()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = request()?;
        let mut inventory = populated_inventory(&request)?;
        inventory.version = 3;
        inventory.assignments[0].origin = SourceAssignmentOrigin::HomeHandoff {
            preparation_id: id(130),
            handoff_id: id(131),
            predecessor_id: id(132),
            root_assignment_id: id(133),
        };

        let encoded = encode(&inventory)?;
        assert_eq!(encoded[5], 3);
        assert_eq!(decode(&encoded, &request)?, inventory);
        assert_eq!(encode(&decode(&encoded, &request)?)?, encoded);

        for version in [1, 2] {
            let mut earlier_inventory = inventory.clone();
            earlier_inventory.version = version;
            assert!(matches!(
                encode(&earlier_inventory),
                Err(Error::Corrupt(
                    "Home handoff origin requires inventory version 3"
                ))
            ));

            let mut home_tag_in_earlier_version = encoded.clone();
            home_tag_in_earlier_version[5] = version;
            assert!(matches!(
                decode(&home_tag_in_earlier_version, &request),
                Err(Error::Corrupt(
                    "Home handoff origin requires inventory version 3"
                ))
            ));
        }
        Ok(())
    }

    #[test]
    fn rejects_invalid_home_handoff_origin_identities() -> Result<(), Box<dyn std::error::Error>> {
        let request = request()?;
        let invalid_origins = [
            SourceAssignmentOrigin::HomeHandoff {
                preparation_id: Uuid::nil(),
                handoff_id: id(140),
                predecessor_id: id(141),
                root_assignment_id: id(142),
            },
            SourceAssignmentOrigin::HomeHandoff {
                preparation_id: id(140),
                handoff_id: Uuid::nil(),
                predecessor_id: id(141),
                root_assignment_id: id(142),
            },
            SourceAssignmentOrigin::HomeHandoff {
                preparation_id: id(140),
                handoff_id: id(141),
                predecessor_id: Uuid::nil(),
                root_assignment_id: id(142),
            },
            SourceAssignmentOrigin::HomeHandoff {
                preparation_id: id(140),
                handoff_id: id(141),
                predecessor_id: id(142),
                root_assignment_id: Uuid::nil(),
            },
            SourceAssignmentOrigin::HomeHandoff {
                preparation_id: id(140),
                handoff_id: id(141),
                predecessor_id: id(70),
                root_assignment_id: id(142),
            },
            SourceAssignmentOrigin::HomeHandoff {
                preparation_id: id(140),
                handoff_id: id(141),
                predecessor_id: id(142),
                root_assignment_id: id(70),
            },
        ];

        for origin in invalid_origins {
            let mut inventory = populated_inventory(&request)?;
            inventory.version = 3;
            inventory.assignments[0].origin = origin;
            assert!(matches!(
                encode(&inventory),
                Err(Error::Corrupt("assignment Home handoff origin"))
            ));
        }
        Ok(())
    }

    #[test]
    fn rejects_wrong_request_digest_truncation_tail_unknown_version_and_count_overflow()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = request()?;
        let inventory = populated_inventory(&request)?;
        let encoded = encode(&inventory)?;

        let mut wrong_digest = encoded.clone();
        wrong_digest[6] ^= 1;
        assert!(matches!(
            decode(&wrong_digest, &request),
            Err(Error::RequestMismatch)
        ));

        let mut truncated = encoded.clone();
        truncated.pop();
        assert!(matches!(
            decode(&truncated, &request),
            Err(Error::Corrupt(_))
        ));

        let mut tailed = encoded.clone();
        tailed.push(0);
        assert!(matches!(
            decode(&tailed, &request),
            Err(Error::Corrupt("trailing bytes"))
        ));

        let mut unknown_version = encoded.clone();
        unknown_version[4] = CODEC_VERSION + 1;
        assert!(matches!(
            decode(&unknown_version, &request),
            Err(Error::Corrupt("codec version"))
        ));

        let mut unknown_inventory_version = encoded.clone();
        unknown_inventory_version[5] = super::super::inventory::INVENTORY_VERSION + 1;
        assert!(matches!(
            decode(&unknown_inventory_version, &request),
            Err(Error::Corrupt("inventory version"))
        ));

        // Header (62), one Session (20), Agent count (4), then three UUIDs
        // and the optional Session field (17) place the principal tag here.
        let mut unknown_tag = encoded.clone();
        unknown_tag[151] = u8::MAX;
        assert!(matches!(
            decode(&unknown_tag, &request),
            Err(Error::Corrupt("principal tag"))
        ));

        let mut excessive_sessions = encoded.clone();
        excessive_sessions[62..66].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            decode(&excessive_sessions, &request),
            Err(Error::Bounds("sessions"))
        ));

        let oversized = vec![0; MAX_HOME_SOURCE_INVENTORY_BYTES + 1];
        assert!(matches!(
            decode(&oversized, &request),
            Err(Error::PayloadTooLarge { .. })
        ));
        Ok(())
    }
}
