//! Bounded portable snapshots for exact terminal acceptance records.

use forge_domain::{AgentAssignmentId, OrchestrationIssuerId, TimestampMillis, WorkspaceId};

use super::schema::{
    MAX_GRANT_SNAPSHOT_BYTES, MAX_REQUEST_SNAPSHOT_BYTES, MAX_SUCCESSOR_SNAPSHOT_BYTES,
};
use super::{HomeHandoffAcceptanceOutcomeRecord, HomeHandoffApplicationStoreError as Error, codec};

const MAGIC: &[u8; 4] = b"HHAT";
const VERSION: u8 = 1;
const MAX_SNAPSHOT_BYTES: usize = 2_048;

impl HomeHandoffAcceptanceOutcomeRecord {
    /// Encode this terminal record as a bounded, versioned portable snapshot.
    ///
    /// The snapshot proves only internal consistency among its encoded fields.
    /// It does not authenticate the issuer, establish a Source commit, or
    /// validate external parents, current assignment state, or custody. Native
    /// readers must obtain it through the authenticated exact-owner read path.
    pub fn to_snapshot_bytes(&self) -> Result<Vec<u8>, Error> {
        let request = self.request().canonical_snapshot();
        let mut bytes = Vec::with_capacity(MAX_SNAPSHOT_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        codec::append_len_prefixed(&mut bytes, &request)?;
        bytes.extend_from_slice(self.request().request_digest().as_bytes());
        codec::append_uuid(&mut bytes, self.issuer().into_uuid());
        codec::append_uuid(&mut bytes, self.preparation_id());
        codec::append_uuid(&mut bytes, self.workspace_id().into_uuid());
        codec::append_uuid(&mut bytes, self.predecessor_id().into_uuid());
        codec::append_uuid(&mut bytes, self.root_assignment_id().into_uuid());
        codec::append_i64(&mut bytes, self.source_at().get());
        bytes.push(
            u8::try_from(self.outcome_kind().encode())
                .map_err(|_| Error::Corrupt("acceptance outcome kind"))?,
        );
        if let Some(applied) = self.applied() {
            codec::append_i64(&mut bytes, applied.predecessor_revision_before().get());
            codec::append_i64(&mut bytes, applied.predecessor_revision_after().get());
            bytes.push(codec::encode_state(
                applied.predecessor_terminal_disposition(),
            ));
            let successor = codec::encode_successor_snapshot(applied.successor());
            codec::append_len_prefixed(&mut bytes, &successor)?;
            let grant = codec::encode_grant_snapshot(applied.grant())?;
            codec::append_len_prefixed(&mut bytes, &grant)?;
        }
        bytes.extend_from_slice(self.payload_digest());
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(Error::Corrupt("acceptance snapshot exceeds its bound"));
        }
        Ok(bytes)
    }

    /// Decode a canonical terminal snapshot and verify its existing payload
    /// digest. This data-only decoder does not replace Source owner readback or
    /// authorize a new application.
    pub fn from_snapshot_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(Error::Corrupt("acceptance snapshot bound"));
        }
        let mut reader = codec::Reader::new(bytes);
        if reader.take(MAGIC.len())? != MAGIC || reader.u8()? != VERSION {
            return Err(Error::Corrupt("acceptance snapshot version"));
        }
        let request_snapshot = reader.length_prefixed(MAX_REQUEST_SNAPSHOT_BYTES)?;
        let request_digest = reader.digest()?;
        let issuer = OrchestrationIssuerId::from_uuid(reader.uuid()?);
        let preparation_id = reader.uuid()?;
        let workspace_id = WorkspaceId::from_uuid(reader.uuid()?);
        let predecessor_id = AgentAssignmentId::from_uuid(reader.uuid()?);
        let root_assignment_id = AgentAssignmentId::from_uuid(reader.uuid()?);
        let source_at = TimestampMillis::new(reader.i64()?)
            .map_err(|_| Error::Corrupt("acceptance source time"))?;

        let (outcome_kind, before, after, disposition, successor, grant) = match reader.u8()? {
            2 => (2, None, None, None, None, None),
            1 => {
                let before = reader.i64()?;
                let after = reader.i64()?;
                let disposition = i64::from(reader.u8()?);
                let successor = reader.length_prefixed(MAX_SUCCESSOR_SNAPSHOT_BYTES)?;
                let grant = reader.length_prefixed(MAX_GRANT_SNAPSHOT_BYTES)?;
                (
                    1,
                    Some(before),
                    Some(after),
                    Some(disposition),
                    Some(successor),
                    Some(grant),
                )
            }
            _ => return Err(Error::Corrupt("acceptance outcome tag")),
        };
        let expected_payload_digest = reader.digest()?;
        if !reader.is_finished() {
            return Err(Error::Corrupt("acceptance snapshot trailing bytes"));
        }

        let record = codec::decode_stored_record(
            request_snapshot,
            &request_digest,
            issuer,
            preparation_id,
            workspace_id,
            predecessor_id,
            root_assignment_id,
            source_at,
            outcome_kind,
            before,
            after,
            disposition,
            successor,
            grant,
        )?;
        if record.outcome_kind().encode() != outcome_kind
            || record.payload_digest() != &expected_payload_digest
            || record.to_snapshot_bytes()?.as_slice() != bytes
        {
            return Err(Error::Corrupt(
                "acceptance snapshot digest or canonical form",
            ));
        }
        Ok(record)
    }
}
