use forge_domain::{
    LocationId, LocationRevision, LocationRoot, RegisteredLocation, TimestampMillis,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::{
    GlobalRegistry, RegistryError, decode_location, decode_location_id, ensure_live_paths,
    path_to_bytes_bounded, query_location_row, validate_location_id_length,
};

pub(super) fn relocate_location_root(
    registry: &mut GlobalRegistry,
    id: LocationId,
    expected_revision: LocationRevision,
    expected_root: &LocationRoot,
    new_root: &LocationRoot,
    observed_at: TimestampMillis,
) -> Result<RegisteredLocation, RegistryError> {
    registry.ensure_live_binding()?;
    let expected_root_bytes = path_to_bytes_bounded(expected_root.as_path())?;
    let new_root_bytes = path_to_bytes_bounded(new_root.as_path())?;
    let transaction = registry
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = query_location_row(&transaction, id)?
        .map(decode_location)
        .transpose()?
        .ok_or(RegistryError::LocationNotFound(id))?;
    validate_relocation_preconditions(
        &current,
        expected_revision,
        expected_root,
        new_root,
        observed_at,
    )?;

    let existing_root: Option<(i64, Vec<u8>)> = transaction
        .query_row(
            "SELECT length(CAST(location_id AS BLOB)), location_id
             FROM locations
             WHERE root_path = ?1",
            params![new_root_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((id_length, existing_id)) = existing_root {
        validate_location_id_length(id_length)?;
        return Err(RegistryError::LocationAlreadyRegistered {
            existing_id: decode_location_id(&existing_id)?,
        });
    }

    let next_revision =
        current
            .revision()
            .checked_next()
            .map_err(|_| RegistryError::RevisionOverflow {
                id,
                current: current.revision(),
            })?;
    let id_bytes = id.into_uuid().into_bytes();
    let changed = transaction.execute(
        "UPDATE locations
         SET root_path = ?1, updated_at_ms = ?2, revision = ?3
         WHERE location_id = ?4 AND root_path = ?5 AND revision = ?6",
        params![
            new_root_bytes.as_slice(),
            observed_at.get(),
            next_revision.get(),
            id_bytes.as_slice(),
            expected_root_bytes.as_slice(),
            expected_revision.get(),
        ],
    )?;
    if changed == 0 {
        return Err(RegistryError::RevisionConflict {
            id,
            expected: expected_revision,
            actual: current.revision(),
        });
    }

    let relocated = query_location_row(&transaction, id)?
        .map(decode_location)
        .transpose()?
        .ok_or(RegistryError::LocationNotFound(id))?;
    ensure_live_paths(
        &registry.database_parent,
        registry.database_parent_identity,
        &registry.path,
        registry.database_identity,
        registry.wal_identity,
        registry.shm_identity,
    )?;
    transaction
        .commit()
        .map_err(|source| RegistryError::LocationRootCommittedUnconfirmed {
            id,
            expected_revision,
            new_root: new_root.clone(),
            source: Box::new(source.into()),
        })?;
    registry
        .ensure_live_binding()
        .and_then(|()| registry.capture_sidecar_identities())
        .and_then(|()| registry.ensure_live_binding())
        .map_err(|source| RegistryError::LocationRootCommittedUnconfirmed {
            id,
            expected_revision,
            new_root: new_root.clone(),
            source: Box::new(source),
        })?;
    Ok(relocated)
}

fn validate_relocation_preconditions(
    current: &RegisteredLocation,
    expected_revision: LocationRevision,
    expected_root: &LocationRoot,
    new_root: &LocationRoot,
    observed_at: TimestampMillis,
) -> Result<(), RegistryError> {
    let id = current.id();
    if current.revision() != expected_revision {
        return Err(RegistryError::RevisionConflict {
            id,
            expected: expected_revision,
            actual: current.revision(),
        });
    }
    if current.root() != expected_root {
        return Err(RegistryError::LocationRootConflict { id });
    }
    if current.root() == new_root {
        return Err(RegistryError::LocationRootUnchanged { id });
    }
    let minimum_updated_at = current.created_at().max(current.updated_at());
    if observed_at < minimum_updated_at {
        return Err(RegistryError::LocationTimestampRegression {
            id,
            minimum: minimum_updated_at,
            observed: observed_at,
        });
    }
    Ok(())
}
