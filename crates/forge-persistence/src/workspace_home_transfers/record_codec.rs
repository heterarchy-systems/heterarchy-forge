//! Closed, bounded wire-independent snapshot bytes for a checked source record.

use forge_domain::{OrchestrationIssuerId, TimestampMillis};
use uuid::Uuid;

use super::{
    HomeTransferSourceRecord, HomeTransferSourceRecordParts, HomeTransferSourceState,
    HomeTransferStoreError, request_codec, schema,
};

const MAGIC: &[u8; 5] = b"FHTS\x01";
const MAX_SNAPSHOT_BYTES: usize = 1_048_576;

pub(super) fn encode(record: &HomeTransferSourceRecord) -> Result<Vec<u8>, HomeTransferStoreError> {
    let request = request_codec::encode(record.request())?;
    let request_len = u32::try_from(request.len())
        .map_err(|_| HomeTransferStoreError::Bounds("Home source snapshot request"))?;
    let mut bytes = Vec::with_capacity(request.len() + 160);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&request_len.to_be_bytes());
    bytes.extend_from_slice(&request);
    bytes.extend_from_slice(record.issuer().into_uuid().as_bytes());
    bytes.push(encode_state(record.state()));
    bytes.extend_from_slice(&record.observed_at().get().to_be_bytes());
    bytes.extend_from_slice(&record.grant_issued_at().get().to_be_bytes());
    bytes.extend_from_slice(&record.grant_expires_at().get().to_be_bytes());
    bytes.extend_from_slice(record.migration_id().as_bytes());
    bytes.extend_from_slice(&record.freeze_revision().to_be_bytes());
    bytes.extend_from_slice(record.delegation_digest());
    match (record.inventory_payload(), record.inventory_digest()) {
        (Some(payload), Some(digest)) => {
            let payload_len = u32::try_from(payload.len())
                .map_err(|_| HomeTransferStoreError::Bounds("Home source inventory"))?;
            bytes.push(1);
            bytes.extend_from_slice(&payload_len.to_be_bytes());
            bytes.extend_from_slice(payload);
            bytes.extend_from_slice(digest);
        }
        (None, None) => bytes.push(0),
        _ => return Err(HomeTransferStoreError::Corrupt("snapshot inventory shape")),
    }
    bytes.extend_from_slice(record.outcome_digest());
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(HomeTransferStoreError::Bounds("Home source snapshot"));
    }
    Ok(bytes)
}

pub(super) fn decode(bytes: &[u8]) -> Result<HomeTransferSourceRecord, HomeTransferStoreError> {
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(HomeTransferStoreError::Bounds("Home source snapshot"));
    }
    let mut reader = Reader::new(bytes);
    if reader.take(MAGIC.len())? != MAGIC.as_slice() {
        return Err(HomeTransferStoreError::Corrupt("snapshot version"));
    }
    let request_len = usize::try_from(reader.u32()?)
        .map_err(|_| HomeTransferStoreError::Corrupt("snapshot request length"))?;
    if request_len == 0 || request_len > schema::MAX_REQUEST_BYTES {
        return Err(HomeTransferStoreError::Bounds(
            "Home source snapshot request",
        ));
    }
    let request = request_codec::decode(reader.take(request_len)?)?;
    let issuer = OrchestrationIssuerId::from_uuid(reader.uuid()?);
    let state = decode_state(reader.u8()?)?;
    let observed_at = reader.timestamp()?;
    let grant_issued_at = reader.timestamp()?;
    let grant_expires_at = reader.timestamp()?;
    let migration_id = reader.uuid()?;
    let freeze_revision = reader.u64()?;
    let delegation_digest = reader.array32()?;
    let (inventory_payload, inventory_digest) = match reader.u8()? {
        0 => (None, None),
        1 => {
            let payload_len = usize::try_from(reader.u32()?)
                .map_err(|_| HomeTransferStoreError::Corrupt("snapshot inventory length"))?;
            if payload_len == 0 || payload_len > super::inventory::MAX_HOME_SOURCE_INVENTORY_BYTES {
                return Err(HomeTransferStoreError::Bounds("Home source inventory"));
            }
            let payload = reader.take(payload_len)?.to_vec();
            let digest = reader.array32()?;
            (Some(payload), Some(digest))
        }
        _ => return Err(HomeTransferStoreError::Corrupt("snapshot inventory tag")),
    };
    let outcome_digest = reader.array32()?;
    if !reader.is_finished() {
        return Err(HomeTransferStoreError::Corrupt("snapshot trailing bytes"));
    }

    let record = HomeTransferSourceRecord::from_parts(HomeTransferSourceRecordParts {
        request,
        issuer,
        state,
        observed_at,
        grant_issued_at,
        grant_expires_at,
        migration_id,
        freeze_revision,
        delegation_digest,
        inventory_payload,
        inventory_digest,
        outcome_digest,
    })?;
    if encode(&record)?.as_slice() != bytes {
        return Err(HomeTransferStoreError::Corrupt("noncanonical snapshot"));
    }
    Ok(record)
}

fn encode_state(state: HomeTransferSourceState) -> u8 {
    match state {
        HomeTransferSourceState::Prepared => 0,
        HomeTransferSourceState::AbortedUnstarted => 1,
    }
}

fn decode_state(value: u8) -> Result<HomeTransferSourceState, HomeTransferStoreError> {
    match value {
        0 => Ok(HomeTransferSourceState::Prepared),
        1 => Ok(HomeTransferSourceState::AbortedUnstarted),
        _ => Err(HomeTransferStoreError::Corrupt("snapshot outcome state")),
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], HomeTransferStoreError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(HomeTransferStoreError::Corrupt("snapshot length overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(HomeTransferStoreError::Corrupt("truncated snapshot"))?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, HomeTransferStoreError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, HomeTransferStoreError> {
        let bytes = self
            .take(4)?
            .try_into()
            .map_err(|_| HomeTransferStoreError::Corrupt("snapshot integer width"))?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, HomeTransferStoreError> {
        let bytes = self
            .take(8)?
            .try_into()
            .map_err(|_| HomeTransferStoreError::Corrupt("snapshot integer width"))?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn timestamp(&mut self) -> Result<TimestampMillis, HomeTransferStoreError> {
        let bytes = self
            .take(8)?
            .try_into()
            .map_err(|_| HomeTransferStoreError::Corrupt("snapshot timestamp width"))?;
        TimestampMillis::new(i64::from_be_bytes(bytes))
            .map_err(|_| HomeTransferStoreError::Corrupt("snapshot timestamp"))
    }

    fn uuid(&mut self) -> Result<Uuid, HomeTransferStoreError> {
        Uuid::from_slice(self.take(16)?)
            .map_err(|_| HomeTransferStoreError::Corrupt("snapshot UUID"))
    }

    fn array32(&mut self) -> Result<[u8; 32], HomeTransferStoreError> {
        self.take(32)?
            .try_into()
            .map_err(|_| HomeTransferStoreError::Corrupt("snapshot digest width"))
    }

    const fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
