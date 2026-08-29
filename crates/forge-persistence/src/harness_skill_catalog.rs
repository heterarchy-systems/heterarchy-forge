//! Durable optional Harness Skill records stored in the app-global Harness Catalog.
//!
//! Database opening/binding authority remains owned by `HarnessCatalog`; this
//! module owns only the v2 Skill table contract and bounded record CRUD.

use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use forge_domain::{
    HarnessContentHash, HarnessSkillDescriptor, HarnessSkillId, HarnessSkillName,
    HarnessSkillRevision, RegisteredHarnessSkill, TimestampMillis,
};
use forge_workspace::InspectedHarnessSkill;
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};
use uuid::Uuid;

use crate::harness_catalog::HarnessCatalogError;

pub(crate) const SKILLS_INDEX_NAME: &str = "harness_skills_name_idx";
pub(crate) const EXPECTED_SKILLS_TABLE_SQL: &str = "CREATE TABLE harness_skills (skill_id BLOB PRIMARY KEY NOT NULL CHECK(length(skill_id) = 16), display_name TEXT NOT NULL CHECK(length(CAST(display_name AS BLOB)) BETWEEN 1 AND 128), source_root BLOB NOT NULL UNIQUE CHECK(length(source_root) BETWEEN 1 AND 4096), content_hash BLOB NOT NULL CHECK(length(content_hash) = 32), file_count INTEGER NOT NULL CHECK(file_count BETWEEN 1 AND 128), registered_at_ms INTEGER NOT NULL CHECK(registered_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= registered_at_ms), revision INTEGER NOT NULL CHECK(revision >= 1))";
pub(crate) const EXPECTED_SKILLS_INDEX_SQL: &str =
    "CREATE INDEX harness_skills_name_idx ON harness_skills(display_name COLLATE NOCASE, skill_id)";
const EXPECTED_SKILL_COLUMNS: [(&str, &str, i64, i64); 8] = [
    ("skill_id", "BLOB", 1, 1),
    ("display_name", "TEXT", 1, 0),
    ("source_root", "BLOB", 1, 0),
    ("content_hash", "BLOB", 1, 0),
    ("file_count", "INTEGER", 1, 0),
    ("registered_at_ms", "INTEGER", 1, 0),
    ("updated_at_ms", "INTEGER", 1, 0),
    ("revision", "INTEGER", 1, 0),
];
const ID_BYTES: usize = 16;
const HASH_BYTES: usize = HarnessContentHash::BYTE_LEN;
const MAX_SOURCE_ROOT_BYTES: usize = 4_096;

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessSkillCatalogEntry {
    skill: RegisteredHarnessSkill,
    source_root: PathBuf,
}

impl HarnessSkillCatalogEntry {
    pub const fn skill(&self) -> &RegisteredHarnessSkill {
        &self.skill
    }

    pub fn source_root(&self) -> &Path {
        &self.source_root
    }
}

#[derive(Debug)]
struct RawSkillCatalogEntry {
    skill_id: Vec<u8>,
    display_name: String,
    source_root: Vec<u8>,
    content_hash: Vec<u8>,
    file_count: i64,
    registered_at: i64,
    updated_at: i64,
    revision: i64,
}

pub(crate) fn create_schema(connection: &Connection) -> Result<(), HarnessCatalogError> {
    connection.execute_batch(EXPECTED_SKILLS_TABLE_SQL)?;
    connection.execute_batch(EXPECTED_SKILLS_INDEX_SQL)?;
    Ok(())
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), HarnessCatalogError> {
    super::harness_catalog::validate_schema_sql(
        connection,
        "table",
        "harness_skills",
        EXPECTED_SKILLS_TABLE_SQL,
    )?;
    super::harness_catalog::validate_schema_sql(
        connection,
        "index",
        SKILLS_INDEX_NAME,
        EXPECTED_SKILLS_INDEX_SQL,
    )?;
    let mut statement = connection.prepare("PRAGMA table_info(harness_skills)")?;
    let columns = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let columns_match = columns.len() == EXPECTED_SKILL_COLUMNS.len()
        && columns.iter().zip(EXPECTED_SKILL_COLUMNS).all(
            |((name, data_type, not_null, primary_key), expected)| {
                name == expected.0
                    && data_type == expected.1
                    && *not_null == expected.2
                    && *primary_key == expected.3
            },
        );
    if !columns_match {
        return Err(HarnessCatalogError::DamagedSchema(
            "harness_skills columns do not match the expected shape",
        ));
    }
    let mut index = connection.prepare("PRAGMA index_info(harness_skills_name_idx)")?;
    let index_columns = index
        .query_map([], |row| row.get::<_, String>(2))?
        .collect::<Result<Vec<_>, _>>()?;
    if index_columns != ["display_name", "skill_id"] {
        return Err(HarnessCatalogError::DamagedSchema(
            "harness_skills_name_idx columns do not match the expected shape",
        ));
    }
    Ok(())
}

pub(crate) fn register(
    connection: &mut Connection,
    inspected: &InspectedHarnessSkill,
    observed_at: TimestampMillis,
) -> Result<HarnessSkillCatalogEntry, HarnessCatalogError> {
    let descriptor = inspected.descriptor();
    let source_root = source_root_bytes(inspected.source_root())?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(raw) = query_raw_by_id(&transaction, descriptor.id())? {
        let existing = decode_entry(raw)?;
        if existing.skill().descriptor() == descriptor
            && existing.source_root() == inspected.source_root()
        {
            transaction.commit()?;
            return Ok(existing);
        }
        return Err(HarnessCatalogError::SkillIdConflict(descriptor.id()));
    }
    if let Some(existing_id) = query_id_by_source(&transaction, &source_root)? {
        return Err(HarnessCatalogError::SkillSourceAlreadyRegistered(
            existing_id,
        ));
    }
    let skill = RegisteredHarnessSkill::create(descriptor.clone(), observed_at);
    insert_entry(&transaction, &skill, &source_root)?;
    transaction.commit()?;
    get(connection, descriptor.id())?
        .ok_or(HarnessCatalogError::SkillRecordMissing(descriptor.id()))
}

pub(crate) fn refresh(
    connection: &mut Connection,
    inspected: &InspectedHarnessSkill,
    expected_revision: HarnessSkillRevision,
    observed_at: TimestampMillis,
) -> Result<HarnessSkillCatalogEntry, HarnessCatalogError> {
    let id = inspected.descriptor().id();
    let current = get(connection, id)?.ok_or(HarnessCatalogError::SkillRecordMissing(id))?;
    if current.source_root() != inspected.source_root() {
        return Err(HarnessCatalogError::SkillSourceMismatch(id));
    }
    let next = current
        .skill()
        .refresh(
            inspected.descriptor().clone(),
            expected_revision,
            observed_at,
        )
        .map_err(HarnessCatalogError::SkillTransition)?;
    let source_root = source_root_bytes(inspected.source_root())?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let changed = update_entry(&transaction, &next, &source_root, expected_revision)?;
    if changed != 1 {
        return Err(HarnessCatalogError::SkillCompareAndSwapConflict);
    }
    transaction.commit()?;
    get(connection, id)?.ok_or(HarnessCatalogError::SkillRecordMissing(id))
}

pub(crate) fn get(
    connection: &Connection,
    id: HarnessSkillId,
) -> Result<Option<HarnessSkillCatalogEntry>, HarnessCatalogError> {
    query_raw_by_id(connection, id)?
        .map(decode_entry)
        .transpose()
}

pub(crate) fn list(
    connection: &Connection,
    limit: usize,
) -> Result<Vec<HarnessSkillCatalogEntry>, HarnessCatalogError> {
    if limit == 0 || limit > super::harness_catalog::MAX_HARNESS_CATALOG_RESULTS {
        return Err(HarnessCatalogError::InvalidSkillListLimit {
            actual: limit,
            maximum: super::harness_catalog::MAX_HARNESS_CATALOG_RESULTS,
        });
    }
    let sql_limit =
        i64::try_from(limit).map_err(|_| HarnessCatalogError::InvalidSkillListLimit {
            actual: limit,
            maximum: super::harness_catalog::MAX_HARNESS_CATALOG_RESULTS,
        })?;
    let mut statement = connection.prepare(
        "SELECT length(skill_id), length(CAST(display_name AS BLOB)), length(source_root),
                length(content_hash), skill_id, display_name, source_root, content_hash,
                file_count, registered_at_ms, updated_at_ms, revision
         FROM harness_skills
         ORDER BY display_name COLLATE NOCASE, skill_id
         LIMIT ?1",
    )?;
    statement
        .query_map(params![sql_limit], decode_raw_row)?
        .map(|row| {
            row.map_err(HarnessCatalogError::from)
                .and_then(decode_entry)
        })
        .collect()
}

fn query_raw_by_id(
    connection: &Connection,
    id: HarnessSkillId,
) -> Result<Option<RawSkillCatalogEntry>, HarnessCatalogError> {
    connection
        .query_row(
            "SELECT length(skill_id), length(CAST(display_name AS BLOB)), length(source_root),
                    length(content_hash), skill_id, display_name, source_root, content_hash,
                    file_count, registered_at_ms, updated_at_ms, revision
             FROM harness_skills WHERE skill_id = ?1",
            params![id.into_uuid().as_bytes()],
            decode_raw_row,
        )
        .optional()
        .map_err(HarnessCatalogError::from)
}

fn query_id_by_source(
    connection: &Connection,
    source_root: &[u8],
) -> Result<Option<HarnessSkillId>, HarnessCatalogError> {
    let raw: Option<Vec<u8>> = connection
        .query_row(
            "SELECT skill_id FROM harness_skills WHERE source_root = ?1",
            params![source_root],
            |row| row.get(0),
        )
        .optional()?;
    raw.map(|value| decode_uuid("skill_id", &value).map(HarnessSkillId::from_uuid))
        .transpose()
}

fn insert_entry(
    transaction: &Transaction<'_>,
    skill: &RegisteredHarnessSkill,
    source_root: &[u8],
) -> Result<(), HarnessCatalogError> {
    let descriptor = skill.descriptor();
    transaction.execute(
        "INSERT INTO harness_skills (
            skill_id, display_name, source_root, content_hash, file_count,
            registered_at_ms, updated_at_ms, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            descriptor.id().into_uuid().as_bytes(),
            descriptor.name().as_str(),
            source_root,
            descriptor.content_hash().as_bytes().as_slice(),
            i64::from(descriptor.file_count()),
            skill.registered_at().get(),
            skill.updated_at().get(),
            skill.revision().get(),
        ],
    )?;
    Ok(())
}

fn update_entry(
    transaction: &Transaction<'_>,
    skill: &RegisteredHarnessSkill,
    source_root: &[u8],
    expected_revision: HarnessSkillRevision,
) -> Result<usize, HarnessCatalogError> {
    let descriptor = skill.descriptor();
    transaction
        .execute(
            "UPDATE harness_skills
             SET display_name = ?2, source_root = ?3, content_hash = ?4, file_count = ?5,
                 updated_at_ms = ?6, revision = ?7
             WHERE skill_id = ?1 AND revision = ?8",
            params![
                descriptor.id().into_uuid().as_bytes(),
                descriptor.name().as_str(),
                source_root,
                descriptor.content_hash().as_bytes().as_slice(),
                i64::from(descriptor.file_count()),
                skill.updated_at().get(),
                skill.revision().get(),
                expected_revision.get(),
            ],
        )
        .map_err(HarnessCatalogError::from)
}

fn decode_raw_row(row: &Row<'_>) -> rusqlite::Result<RawSkillCatalogEntry> {
    validate_exact_length("skill_id", row.get(0)?, ID_BYTES).map_err(sql_decode_error)?;
    validate_max_length(
        "display_name",
        row.get(1)?,
        forge_domain::MAX_HARNESS_SKILL_NAME_BYTES,
    )
    .map_err(sql_decode_error)?;
    validate_max_length("source_root", row.get(2)?, MAX_SOURCE_ROOT_BYTES)
        .map_err(sql_decode_error)?;
    validate_exact_length("content_hash", row.get(3)?, HASH_BYTES).map_err(sql_decode_error)?;
    Ok(RawSkillCatalogEntry {
        skill_id: row.get(4)?,
        display_name: row.get(5)?,
        source_root: row.get(6)?,
        content_hash: row.get(7)?,
        file_count: row.get(8)?,
        registered_at: row.get(9)?,
        updated_at: row.get(10)?,
        revision: row.get(11)?,
    })
}

fn decode_entry(
    raw: RawSkillCatalogEntry,
) -> Result<HarnessSkillCatalogEntry, HarnessCatalogError> {
    let hash: [u8; HASH_BYTES] = raw.content_hash.as_slice().try_into().map_err(|_| {
        HarnessCatalogError::SkillCorruptRecord {
            field: "content_hash",
        }
    })?;
    let file_count =
        u16::try_from(raw.file_count).map_err(|_| HarnessCatalogError::SkillCorruptRecord {
            field: "file_count",
        })?;
    let descriptor = HarnessSkillDescriptor::new(
        HarnessSkillId::from_uuid(decode_uuid("skill_id", &raw.skill_id)?),
        HarnessSkillName::new(raw.display_name).map_err(HarnessCatalogError::SkillName)?,
        HarnessContentHash::from_bytes(hash),
        file_count,
    )
    .map_err(HarnessCatalogError::SkillDescriptor)?;
    let skill = RegisteredHarnessSkill::from_parts(
        descriptor,
        TimestampMillis::new(raw.registered_at).map_err(HarnessCatalogError::Timestamp)?,
        TimestampMillis::new(raw.updated_at).map_err(HarnessCatalogError::Timestamp)?,
        HarnessSkillRevision::new(raw.revision).map_err(HarnessCatalogError::SkillRevision)?,
    )
    .map_err(HarnessCatalogError::SkillTransition)?;
    Ok(HarnessSkillCatalogEntry {
        skill,
        source_root: PathBuf::from(std::ffi::OsString::from_vec(raw.source_root)),
    })
}

fn source_root_bytes(path: &Path) -> Result<Vec<u8>, HarnessCatalogError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_SOURCE_ROOT_BYTES {
        return Err(HarnessCatalogError::SkillSourceRootTooLarge {
            actual: bytes.len(),
            maximum: MAX_SOURCE_ROOT_BYTES,
        });
    }
    Ok(bytes.to_vec())
}

fn decode_uuid(field: &'static str, bytes: &[u8]) -> Result<Uuid, HarnessCatalogError> {
    Uuid::from_slice(bytes).map_err(|_| HarnessCatalogError::SkillCorruptRecord { field })
}

fn validate_exact_length(
    field: &'static str,
    actual: i64,
    expected: usize,
) -> Result<(), HarnessCatalogError> {
    if usize::try_from(actual).ok() == Some(expected) {
        Ok(())
    } else {
        Err(HarnessCatalogError::SkillCorruptRecord { field })
    }
}

fn validate_max_length(
    field: &'static str,
    actual: i64,
    maximum: usize,
) -> Result<(), HarnessCatalogError> {
    if usize::try_from(actual).is_ok_and(|value| value >= 1 && value <= maximum) {
        Ok(())
    } else {
        Err(HarnessCatalogError::SkillCorruptRecord { field })
    }
}

fn sql_decode_error(error: HarnessCatalogError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(error))
}
