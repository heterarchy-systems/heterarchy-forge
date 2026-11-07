//! Bounded portable snapshots for exact proposal readback records.

use forge_domain::{HomeArtifactId, TimestampMillis};

use super::super::HomeHandoffProposalStoreError as Error;
use super::super::proposal_codec;
use super::super::proposal_model::{HomeHandoffProposalEvidence, HomeHandoffProposalRecord};
use super::super::proposal_schema::{MAX_REQUEST_SNAPSHOT_BYTES, MAX_SOURCE_SNAPSHOT_BYTES};

const MAGIC: &[u8; 4] = b"HHPT";
const VERSION: u8 = 1;
const MAX_SNAPSHOT_BYTES: usize = 2_048;

impl HomeHandoffProposalRecord {
    /// Encode this exact proposal as a bounded, versioned portable snapshot.
    ///
    /// The embedded payload digest proves only that these fields are internally
    /// consistent. It does not authenticate the issuer or establish that the
    /// Prepared parent, Source commit, or external custody is current.
    pub fn to_snapshot_bytes(&self) -> Result<Vec<u8>, Error> {
        let request = self.request().canonical_snapshot();
        let source = proposal_codec::encode_source(self.source())?;

        let mut bytes = Vec::with_capacity(MAX_SNAPSHOT_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        proposal_codec::append_len_prefixed(&mut bytes, &request)?;
        bytes.extend_from_slice(self.request().request_digest().as_bytes());
        proposal_codec::append_i64(&mut bytes, self.case_revision());
        proposal_codec::append_len_prefixed(&mut bytes, &source)?;
        bytes.extend_from_slice(self.prepared_outcome_digest());
        match self.evidence() {
            HomeHandoffProposalEvidence::NoArtifactRequested => bytes.push(0),
            HomeHandoffProposalEvidence::SealedArtifact {
                artifact_id,
                archive_digest,
            } => {
                bytes.push(1);
                bytes.extend_from_slice(artifact_id.into_uuid().as_bytes());
                bytes.extend_from_slice(&archive_digest);
            }
        }
        proposal_codec::append_i64(&mut bytes, self.created_at().get());
        bytes.extend_from_slice(self.payload_digest());
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(Error::Corrupt("proposal snapshot exceeds its bound"));
        }
        Ok(bytes)
    }

    /// Decode a canonical proposal snapshot and verify its existing payload
    /// digest. Native callers must still fetch through Source's authenticated
    /// exact-owner read path to establish durable parent and case validity.
    pub fn from_snapshot_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(Error::Corrupt("proposal snapshot bound"));
        }
        let mut reader = proposal_codec::Reader::new(bytes);
        if reader.take(MAGIC.len())? != MAGIC || reader.u8()? != VERSION {
            return Err(Error::Corrupt("proposal snapshot version"));
        }

        let request_snapshot = reader.length_prefixed(MAX_REQUEST_SNAPSHOT_BYTES)?;
        let request_digest = reader.array32()?;
        let request = proposal_codec::decode_request(request_snapshot, &request_digest)?;
        let case_revision = reader.i64()?;
        let source_snapshot = reader.length_prefixed(MAX_SOURCE_SNAPSHOT_BYTES)?;
        let source = proposal_codec::decode_source(source_snapshot)?;
        let prepared_outcome_digest = reader.array32()?;
        let evidence = match reader.u8()? {
            0 => HomeHandoffProposalEvidence::NoArtifactRequested,
            1 => {
                let artifact_id = HomeArtifactId::new(reader.uuid()?)
                    .map_err(|_| Error::Corrupt("proposal artifact identity"))?;
                HomeHandoffProposalEvidence::SealedArtifact {
                    artifact_id,
                    archive_digest: reader.array32()?,
                }
            }
            _ => return Err(Error::Corrupt("proposal evidence tag")),
        };
        let created_at = TimestampMillis::new(reader.i64()?)
            .map_err(|_| Error::Corrupt("proposal created_at"))?;
        let expected_payload_digest = reader.array32()?;
        if !reader.is_finished() {
            return Err(Error::Corrupt("proposal snapshot trailing bytes"));
        }

        let record = HomeHandoffProposalRecord::new(
            request,
            case_revision,
            source,
            prepared_outcome_digest,
            evidence,
            created_at,
        )?;
        if record.payload_digest() != &expected_payload_digest
            || record.to_snapshot_bytes()?.as_slice() != bytes
        {
            return Err(Error::Corrupt("proposal snapshot digest or canonical form"));
        }
        Ok(record)
    }
}
