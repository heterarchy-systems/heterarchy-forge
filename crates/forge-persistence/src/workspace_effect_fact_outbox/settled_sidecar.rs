//! Shared checksummed sidecar I/O, binary envelope codec, and `StaticSql` outbox
//! row helpers for `DAG_SETTLED_KIND = 5` and `SWARM_SETTLED_KIND = 6`.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use forge_domain::WorkspaceId;
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{DIGEST_BYTES, EffectFactOutboxError, MAX_PAGE_SIZE, UUID_BYTES, decode_uuid};
use crate::swarm_settled::sql;
use crate::workspace_agent_delegation::AgentOperationsDelegation;

pub(crate) const ENVELOPE_HEADER_LEN: usize = 8 + 8 + UUID_BYTES * 3;

static NEXT_TEMP_NONCE: AtomicU64 = AtomicU64::new(1);

type MemoryKey = (i64, Uuid, Uuid, i64);

/// Process-local fallback sidecar storage used exclusively when SQLite reports no backing file
/// path (such as `:memory:` connections in tests). Production `WorkspaceStore` connections always
/// persist checksummed `.fact` sidecars under `<state_dir>/<subdir>/`.
fn memory_sidecars() -> &'static Mutex<BTreeMap<MemoryKey, Box<[u8]>>> {
    static STORE: OnceLock<Mutex<BTreeMap<MemoryKey, Box<[u8]>>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Static configuration and diagnostic field tags for one sidecar-backed settlement outbox kind.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SettledSidecarSpec {
    pub(crate) fact_kind: i64,
    pub(crate) magic: &'static [u8; 8],
    pub(crate) subdir: &'static str,
    pub(crate) dir_err: &'static str,
    pub(crate) write_err: &'static str,
    pub(crate) sync_err: &'static str,
    pub(crate) rename_err: &'static str,
    pub(crate) missing_err: &'static str,
    pub(crate) read_err: &'static str,
    pub(crate) length_err: &'static str,
    pub(crate) checksum_err: &'static str,
    pub(crate) magic_err: &'static str,
    pub(crate) envelope_err: &'static str,
}

struct TempFileGuard(Option<PathBuf>);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_file(path);
        }
    }
}

fn sidecar_dir_for_connection(
    connection: &Connection,
    subdir: &str,
) -> Result<Option<PathBuf>, EffectFactOutboxError> {
    let Some(db_path) = connection.path() else {
        return Ok(None);
    };
    if db_path.is_empty() {
        return Ok(None);
    }
    let parent = Path::new(db_path)
        .parent()
        .ok_or(EffectFactOutboxError::CorruptRecord("effect_fact.db_path"))?;
    Ok(Some(parent.join(subdir)))
}

fn sidecar_file_path(dir: &Path, sequence: i64) -> PathBuf {
    dir.join(format!("seq-{sequence}.fact"))
}

pub(crate) fn persist_sidecar<const RECORD_LEN: usize>(
    connection: &Connection,
    spec: &SettledSidecarSpec,
    sequence: i64,
    migration_id: Uuid,
    workspace_id: WorkspaceId,
    encoded: &[u8; RECORD_LEN],
) -> Result<(), EffectFactOutboxError> {
    let Some(dir) = sidecar_dir_for_connection(connection, spec.subdir)? else {
        let mut guard = memory_sidecars()
            .lock()
            .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.memory_lock"))?;
        guard.insert(
            (
                spec.fact_kind,
                migration_id,
                workspace_id.into_uuid(),
                sequence,
            ),
            encoded.to_vec().into_boxed_slice(),
        );
        return Ok(());
    };
    fs::create_dir_all(&dir).map_err(|_| EffectFactOutboxError::CorruptRecord(spec.dir_err))?;
    let nonce = NEXT_TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
    let temp_path = dir.join(format!(
        ".tmp-seq-{sequence}-{}-{nonce}",
        std::process::id()
    ));
    let mut temp_guard = TempFileGuard(Some(temp_path.clone()));
    let final_path = sidecar_file_path(&dir, sequence);
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|_| EffectFactOutboxError::CorruptRecord(spec.write_err))?;
        file.write_all(encoded)
            .and_then(|()| file.sync_all())
            .map_err(|_| EffectFactOutboxError::CorruptRecord(spec.sync_err))?;
    }
    fs::rename(&temp_path, &final_path)
        .map_err(|_| EffectFactOutboxError::CorruptRecord(spec.rename_err))?;
    temp_guard.0 = None;
    if let Ok(dir_handle) = File::open(&dir) {
        let _ = dir_handle.sync_all();
    }
    Ok(())
}

pub(crate) fn read_sidecar<const RECORD_LEN: usize>(
    connection: &Connection,
    spec: &SettledSidecarSpec,
    sequence: i64,
    migration_id: Uuid,
    workspace_id: WorkspaceId,
) -> Result<[u8; RECORD_LEN], EffectFactOutboxError> {
    let Some(dir) = sidecar_dir_for_connection(connection, spec.subdir)? else {
        let guard = memory_sidecars()
            .lock()
            .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.memory_lock"))?;
        let raw = guard
            .get(&(
                spec.fact_kind,
                migration_id,
                workspace_id.into_uuid(),
                sequence,
            ))
            .ok_or(EffectFactOutboxError::CorruptRecord(spec.missing_err))?;
        return raw
            .as_ref()
            .try_into()
            .map_err(|_| EffectFactOutboxError::CorruptRecord(spec.length_err));
    };
    let path = sidecar_file_path(&dir, sequence);
    let file =
        File::open(&path).map_err(|_| EffectFactOutboxError::CorruptRecord(spec.missing_err))?;
    let mut buf = Vec::with_capacity(RECORD_LEN + 1);
    file.take((RECORD_LEN + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|_| EffectFactOutboxError::CorruptRecord(spec.read_err))?;
    buf.try_into()
        .map_err(|_| EffectFactOutboxError::CorruptRecord(spec.length_err))
}

pub(crate) struct ByteWriter<'a> {
    buf: &'a mut [u8],
    cursor: usize,
}

impl<'a> ByteWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, cursor: 0 }
    }

    pub(crate) fn push(&mut self, slice: &[u8]) {
        self.buf[self.cursor..self.cursor + slice.len()].copy_from_slice(slice);
        self.cursor += slice.len();
    }

    pub(crate) fn push_uuid(&mut self, value: Uuid) {
        self.push(value.as_bytes());
    }

    pub(crate) fn push_optional_uuid(&mut self, value: Option<Uuid>) {
        if let Some(id) = value {
            self.push(&[1_u8]);
            self.push(id.as_bytes());
        } else {
            self.push(&[0_u8]);
            self.push(&[0_u8; UUID_BYTES]);
        }
    }

    pub(crate) fn push_i64(&mut self, value: i64) {
        self.push(&value.to_be_bytes());
    }

    pub(crate) fn push_u64(&mut self, value: u64) {
        self.push(&value.to_be_bytes());
    }
}

pub(crate) fn encode_record_with<const PAYLOAD_LEN: usize, const RECORD_LEN: usize>(
    spec: &SettledSidecarSpec,
    sequence: i64,
    migration_id: Uuid,
    destination_id: Uuid,
    workspace_id: WorkspaceId,
    write_body: impl FnOnce(&mut ByteWriter<'_>),
) -> [u8; RECORD_LEN] {
    const {
        assert!(PAYLOAD_LEN + DIGEST_BYTES == RECORD_LEN);
    }
    let mut out = [0_u8; RECORD_LEN];
    {
        let mut writer = ByteWriter::new(&mut out[..PAYLOAD_LEN]);
        writer.push(spec.magic);
        writer.push_i64(sequence);
        writer.push_uuid(migration_id);
        writer.push_uuid(destination_id);
        writer.push_uuid(workspace_id.into_uuid());
        debug_assert_eq!(writer.cursor, ENVELOPE_HEADER_LEN);
        write_body(&mut writer);
        debug_assert_eq!(writer.cursor, PAYLOAD_LEN);
    }
    let checksum: [u8; DIGEST_BYTES] = Sha256::digest(&out[..PAYLOAD_LEN]).into();
    out[PAYLOAD_LEN..].copy_from_slice(&checksum);
    out
}

pub(crate) struct ByteReader<'a> {
    buf: &'a [u8],
    cursor: usize,
}

impl<'a> ByteReader<'a> {
    #[cfg(test)]
    pub(crate) const fn from_slice(buf: &'a [u8]) -> Self {
        Self { buf, cursor: 0 }
    }

    fn take(&mut self, len: usize, field: &'static str) -> Result<&'a [u8], EffectFactOutboxError> {
        let end = self
            .cursor
            .checked_add(len)
            .filter(|&end| end <= self.buf.len())
            .ok_or(EffectFactOutboxError::CorruptRecord(field))?;
        let slice = &self.buf[self.cursor..end];
        self.cursor = end;
        Ok(slice)
    }

    pub(crate) fn read_uuid(&mut self, field: &'static str) -> Result<Uuid, EffectFactOutboxError> {
        let bytes = self.take(UUID_BYTES, field)?;
        decode_uuid(bytes, field)
    }

    pub(crate) fn read_optional_uuid(
        &mut self,
        flag_field: &'static str,
        uuid_field: &'static str,
    ) -> Result<Option<Uuid>, EffectFactOutboxError> {
        let flag = self.take(1, flag_field)?[0];
        let bytes = self.take(UUID_BYTES, uuid_field)?;
        match flag {
            0 => {
                if bytes != [0_u8; UUID_BYTES] {
                    return Err(EffectFactOutboxError::CorruptRecord(uuid_field));
                }
                Ok(None)
            }
            1 => Ok(Some(decode_uuid(bytes, uuid_field)?)),
            _ => Err(EffectFactOutboxError::CorruptRecord(flag_field)),
        }
    }

    pub(crate) fn read_i64(&mut self, field: &'static str) -> Result<i64, EffectFactOutboxError> {
        let raw: [u8; 8] = self
            .take(8, field)?
            .try_into()
            .map_err(|_| EffectFactOutboxError::CorruptRecord(field))?;
        Ok(i64::from_be_bytes(raw))
    }

    pub(crate) fn read_u64(&mut self, field: &'static str) -> Result<u64, EffectFactOutboxError> {
        let raw: [u8; 8] = self
            .take(8, field)?
            .try_into()
            .map_err(|_| EffectFactOutboxError::CorruptRecord(field))?;
        Ok(u64::from_be_bytes(raw))
    }

    pub(crate) fn read_digest(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; DIGEST_BYTES], EffectFactOutboxError> {
        self.take(DIGEST_BYTES, field)?
            .try_into()
            .map_err(|_| EffectFactOutboxError::CorruptRecord(field))
    }

    pub(crate) fn ensure_exhausted(
        &self,
        field: &'static str,
    ) -> Result<(), EffectFactOutboxError> {
        if self.cursor == self.buf.len() {
            Ok(())
        } else {
            Err(EffectFactOutboxError::CorruptRecord(field))
        }
    }
}

pub(crate) fn verify_envelope<'a, const PAYLOAD_LEN: usize, const RECORD_LEN: usize>(
    bytes: &'a [u8; RECORD_LEN],
    spec: &SettledSidecarSpec,
    expected_sequence: i64,
    expected_migration_id: Uuid,
    expected_destination_id: Uuid,
    expected_workspace_id: WorkspaceId,
) -> Result<ByteReader<'a>, EffectFactOutboxError> {
    const {
        assert!(PAYLOAD_LEN + DIGEST_BYTES == RECORD_LEN);
    }
    let expected_checksum: [u8; DIGEST_BYTES] = Sha256::digest(&bytes[..PAYLOAD_LEN]).into();
    if bytes[PAYLOAD_LEN..] != expected_checksum {
        return Err(EffectFactOutboxError::CorruptRecord(spec.checksum_err));
    }
    if &bytes[..8] != spec.magic {
        return Err(EffectFactOutboxError::CorruptRecord(spec.magic_err));
    }
    let sequence = i64::from_be_bytes(
        bytes[8..16]
            .try_into()
            .map_err(|_| EffectFactOutboxError::CorruptRecord("effect_fact.sequence"))?,
    );
    let migration_id = decode_uuid(&bytes[16..32], "effect_fact.migration_id")?;
    let destination_id = decode_uuid(&bytes[32..48], "effect_fact.destination_id")?;
    let workspace_id =
        WorkspaceId::from_uuid(decode_uuid(&bytes[48..64], "effect_fact.workspace_id")?);
    if sequence != expected_sequence
        || migration_id != expected_migration_id
        || destination_id != expected_destination_id
        || workspace_id != expected_workspace_id
    {
        return Err(EffectFactOutboxError::CorruptRecord(spec.envelope_err));
    }
    Ok(ByteReader {
        buf: &bytes[ENVELOPE_HEADER_LEN..PAYLOAD_LEN],
        cursor: 0,
    })
}

pub(crate) fn select_entries_by_kind(
    connection: &Connection,
    workspace_id: WorkspaceId,
    fact_kind: i64,
) -> Result<Vec<(i64, Uuid, Uuid)>, EffectFactOutboxError> {
    let mut statement = connection.prepare(sql::SELECT_SETTLED_ENTRIES.as_str())?;
    let rows = statement
        .query_map(
            params![workspace_id.into_uuid().as_bytes(), fact_kind],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(sequence, raw_migration, raw_destination)| {
            Ok((
                sequence,
                decode_uuid(&raw_migration, "effect_fact.migration_id")?,
                decode_uuid(&raw_destination, "effect_fact.destination_id")?,
            ))
        })
        .collect()
}

pub(crate) fn select_page_by_kind(
    connection: &Connection,
    workspace_id: WorkspaceId,
    fact_kind: i64,
    after: u64,
    limit: u32,
) -> Result<Vec<(i64, Uuid, Uuid)>, EffectFactOutboxError> {
    if limit == 0 || limit > MAX_PAGE_SIZE {
        return Err(EffectFactOutboxError::InvalidLimit { limit });
    }
    let after = i64::try_from(after).map_err(|_| EffectFactOutboxError::InvalidCursor)?;
    let mut statement = connection.prepare(sql::SELECT_SETTLED_PAGE.as_str())?;
    let rows = statement
        .query_map(
            params![workspace_id.into_uuid().as_bytes(), fact_kind, after, limit],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(sequence, raw_migration, raw_destination)| {
            Ok((
                sequence,
                decode_uuid(&raw_migration, "effect_fact.migration_id")?,
                decode_uuid(&raw_destination, "effect_fact.destination_id")?,
            ))
        })
        .collect()
}

pub(crate) fn insert_entry_by_kind(
    connection: &Connection,
    delegation: &AgentOperationsDelegation,
    fact_kind: i64,
) -> Result<i64, EffectFactOutboxError> {
    connection.execute(
        sql::INSERT_SETTLED_ENTRY.as_str(),
        params![
            delegation.migration_id().as_bytes(),
            delegation.destination_id().as_bytes(),
            delegation.workspace_id().into_uuid().as_bytes(),
            fact_kind,
        ],
    )?;
    Ok(connection.last_insert_rowid())
}
