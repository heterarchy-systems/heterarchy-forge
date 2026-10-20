//! Checked client-side projections for Workspace root-recovery commands.
//!
//! The server owns root recovery authority.  These validators only correlate
//! a successful HTTP result with the original intent and reject a peer result
//! whose identity, revision, witness, status, or receipt shape cannot be
//! proven from the response.

use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use forge_control::{
    WorkspaceRootRecoveryCommitRequest, WorkspaceRootRecoveryPrepareRequest,
    WorkspaceRootRecoveryProbeRequest, WorkspaceRootRecoveryReadbackRequest,
};
use forge_domain::{
    RegisteredWorkspace, WorkspaceRoot, WorkspaceRootRecoveryAuthorityMode,
    WorkspaceRootRecoveryRequest,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::client::ForgeHttpClientError;
use crate::ops::workspace_root_recovery::{
    WorkspaceRootRecoveryCommitStatus, WorkspaceRootRecoveryCommitWire,
    WorkspaceRootRecoveryProbeStatus, WorkspaceRootRecoveryProbeWire,
    WorkspaceRootRecoveryReadbackStatus, WorkspaceRootRecoveryReadbackWire,
    WorkspaceRootRecoveryReceiptWire, WorkspaceRootRecoveryWorkspaceWire,
};

const CURRENT_SCHEMA_VERSION: i64 = 63;
const OPERATOR_KIND_EXPLICIT_OWNER: i64 = 0;
const INTENT_DOMAIN: &[u8] = b"forge.workspace.root-recovery.intent.v1\0";
const INTENT_V2_DOMAIN: &[u8] = b"forge.workspace.root-recovery.intent.v2\0";
const RECEIPT_DOMAIN: &[u8] = b"forge.workspace.root-recovery.receipt.v1\0";
const RECEIPT_V2_DOMAIN: &[u8] = b"forge.workspace.root-recovery.receipt.v2\0";

pub(super) fn validate_probe(
    response: &WorkspaceRootRecoveryProbeWire,
    request: &WorkspaceRootRecoveryProbeRequest,
) -> Result<(), ForgeHttpClientError> {
    if response.status != WorkspaceRootRecoveryProbeStatus::Observed
        || response.locator != request.locator().encode()
        || response.location_revision != request.locator().expected_revision().get()
        || response.requires_schema_upgrade != (response.schema_version < CURRENT_SCHEMA_VERSION)
        || !(1..=CURRENT_SCHEMA_VERSION).contains(&response.schema_version)
        || response.authority_mode != expected_authority_wire(request.authority_mode())?
        || request
            .expected_workspace_id()
            .is_some_and(|expected| expected.into_uuid() != response.workspace.workspace_id)
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    validate_workspace(
        &response.workspace,
        request.locator().location_id().into_uuid(),
    )?;
    validate_observation(&response.observation, request.authority_mode())?;
    if response.workspace.root_path_base64 != response.observation.root_path_base64 {
        return Err(ForgeHttpClientError::Protocol);
    }
    Ok(())
}

pub(super) fn validate_prepare(
    response: &WorkspaceRootRecoveryProbeWire,
    request: &WorkspaceRootRecoveryPrepareRequest,
) -> Result<(), ForgeHttpClientError> {
    if response.status != WorkspaceRootRecoveryProbeStatus::Prepared
        || response.locator != request.locator().encode()
        || response.location_revision != request.locator().expected_revision().get()
        || response.schema_version != CURRENT_SCHEMA_VERSION
        || response.requires_schema_upgrade
        || response.authority_mode != expected_authority_wire(request.authority_mode())?
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    validate_workspace(
        &response.workspace,
        request.locator().location_id().into_uuid(),
    )?;
    let expected = request.expected_workspace();
    if response.workspace.workspace_id != expected.id().into_uuid()
        || response.workspace.location_id != expected.location_id().into_uuid()
        || response.workspace.root_path_base64
            != crate::ops::workspace_root_recovery::encode_path(expected.root().as_path())
        || response.workspace.root_fingerprint != hex(expected.root_fingerprint().as_bytes())
        || response.workspace.created_at_ms != expected.created_at().get()
        || response.workspace.updated_at_ms != expected.updated_at().get()
        || response.workspace.workspace_revision != expected.revision().get()
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    if response.observation.root_path_base64
        != crate::ops::workspace_root_recovery::encode_path(request.observation().root().as_path())
        || response.observation.root_fingerprint
            != hex(request.observation().fingerprint().as_bytes())
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    // A schema 61 -> 62 migration may legitimately refresh the witness while
    // preserving the selected root and fingerprint.
    validate_observation(&response.observation, request.authority_mode())?;
    if response.workspace.root_path_base64 != response.observation.root_path_base64 {
        return Err(ForgeHttpClientError::Protocol);
    }
    Ok(())
}

pub(super) fn validate_commit(
    response: &WorkspaceRootRecoveryCommitWire,
    request: &WorkspaceRootRecoveryCommitRequest,
) -> Result<(), ForgeHttpClientError> {
    let intent = request.intent();
    let receipt = &response.receipt;
    validate_receipt_shape(
        receipt,
        intent.expected().location_id().into_uuid(),
        intent.location_revision().get(),
    )?;
    if receipt.request_id != intent.request_id()
        || receipt.location_revision != intent.location_revision().get()
        || receipt.expected_workspace_revision != intent.expected().revision().get()
        || receipt.old_root_fingerprint != hex(intent.expected().root_fingerprint().as_bytes())
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    validate_receipt_workspace(&receipt.workspace, intent)?;
    validate_intent_receipt_digests(receipt, intent)?;
    match response.status {
        WorkspaceRootRecoveryCommitStatus::Committed
        | WorkspaceRootRecoveryCommitStatus::Replayed => {
            if !response.confirmed
                || response.recovery_action.is_some()
                || response.reason.is_some()
            {
                return Err(ForgeHttpClientError::Protocol);
            }
        }
        WorkspaceRootRecoveryCommitStatus::CommittedButUnconfirmed => {
            if response.confirmed
                || response.recovery_action.as_deref() != Some("read_back")
                || response.reason.as_deref().is_none_or(str::is_empty)
            {
                return Err(ForgeHttpClientError::Protocol);
            }
        }
    }
    Ok(())
}

pub(super) fn validate_readback(
    response: &WorkspaceRootRecoveryReadbackWire,
    request: &WorkspaceRootRecoveryReadbackRequest,
) -> Result<(), ForgeHttpClientError> {
    if response.status != WorkspaceRootRecoveryReadbackStatus::HistoricalReceipt {
        return Err(ForgeHttpClientError::Protocol);
    }
    match (response.found, response.receipt.as_ref(), request.intent()) {
        (false, None, _) => Ok(()),
        (false, Some(_), _) | (true, None, _) => Err(ForgeHttpClientError::Protocol),
        (true, Some(receipt), intent) => {
            if receipt.request_id != request.request_id()
                || receipt.workspace.location_id != request.locator().location_id().into_uuid()
            {
                return Err(ForgeHttpClientError::Protocol);
            }
            if let Some(intent) = intent {
                validate_receipt_shape(
                    receipt,
                    intent.expected().location_id().into_uuid(),
                    intent.location_revision().get(),
                )?;
                if receipt.request_id != intent.request_id()
                    || receipt.location_revision != intent.location_revision().get()
                    || receipt.expected_workspace_revision != intent.expected().revision().get()
                    || receipt.old_root_fingerprint
                        != hex(intent.expected().root_fingerprint().as_bytes())
                {
                    return Err(ForgeHttpClientError::Protocol);
                }
                validate_receipt_workspace(&receipt.workspace, intent)?;
                validate_intent_receipt_digests(receipt, intent)?;
            } else {
                validate_receipt_shape(
                    receipt,
                    request.locator().location_id().into_uuid(),
                    request.locator().expected_revision().get(),
                )?;
                match (
                    request.authority_mode(),
                    receipt.delegation_receipt.as_ref(),
                ) {
                    (WorkspaceRootRecoveryAuthorityMode::Quiescent, None)
                    | (WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(_), Some(_)) => {
                    }
                    _ => return Err(ForgeHttpClientError::Protocol),
                }
            }
            Ok(())
        }
    }
}

fn validate_workspace(
    workspace: &WorkspaceRootRecoveryWorkspaceWire,
    location_id: Uuid,
) -> Result<(), ForgeHttpClientError> {
    if workspace.location_id != location_id
        || workspace.root_path_base64.is_empty()
        || workspace.created_at_ms < 0
        || workspace.updated_at_ms < 0
        || workspace.workspace_revision < 1
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    validate_root_path(&workspace.root_path_base64)?;
    decode_fixed::<16>(&workspace.root_fingerprint).map(|_| ())
}

fn validate_observation(
    observation: &crate::ops::workspace_root_recovery::WorkspaceRootRecoveryObservationWire,
    mode: WorkspaceRootRecoveryAuthorityMode,
) -> Result<(), ForgeHttpClientError> {
    if observation.root_path_base64.is_empty() {
        return Err(ForgeHttpClientError::Protocol);
    }
    validate_root_path(&observation.root_path_base64)?;
    let _fingerprint = decode_fixed::<16>(&observation.root_fingerprint)?;
    match mode {
        WorkspaceRootRecoveryAuthorityMode::Quiescent if observation.witness_version.is_some() => {
            return Err(ForgeHttpClientError::Protocol);
        }
        WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(_)
            if observation.witness_version != Some(2) =>
        {
            return Err(ForgeHttpClientError::Protocol);
        }
        _ => {}
    }
    validate_digest(&observation.witness)
}

fn expected_authority_wire(
    mode: WorkspaceRootRecoveryAuthorityMode,
) -> Result<
    crate::ops::workspace_root_recovery::WorkspaceRootRecoveryAuthorityModeWire,
    ForgeHttpClientError,
> {
    let value = crate::ops::workspace_root_recovery::authority_mode_json(mode, true)
        .unwrap_or_else(|| serde_json::json!({"kind":"quiescent"}));
    serde_json::from_value(value).map_err(|_| ForgeHttpClientError::Protocol)
}

fn validate_receipt_shape(
    receipt: &WorkspaceRootRecoveryReceiptWire,
    location_id: Uuid,
    location_revision: i64,
) -> Result<(), ForgeHttpClientError> {
    if receipt.location_revision != location_revision
        || receipt.expected_workspace_revision < 1
        || receipt
            .expected_workspace_revision
            .checked_add(1)
            .is_none_or(|revision| revision != receipt.workspace.workspace_revision)
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    validate_workspace(&receipt.workspace, location_id)?;
    let _old_fingerprint = decode_fixed::<16>(&receipt.old_root_fingerprint)?;
    validate_digest(&receipt.request_digest)?;
    validate_digest(&receipt.witness_digest)?;
    validate_digest(&receipt.receipt_digest)?;
    if let Some(delegation) = receipt.delegation_receipt.as_ref() {
        validate_digest(&delegation.authority_digest)?;
        validate_digest(&delegation.normal_request_intent_digest)?;
        validate_digest(&delegation.witness_v2_digest)?;
    }
    if receipt.old_root_fingerprint == receipt.workspace.root_fingerprint {
        return Err(ForgeHttpClientError::Protocol);
    }
    Ok(())
}

fn validate_receipt_workspace(
    workspace: &WorkspaceRootRecoveryWorkspaceWire,
    intent: &WorkspaceRootRecoveryRequest,
) -> Result<(), ForgeHttpClientError> {
    validate_workspace(workspace, intent.expected().location_id().into_uuid())?;
    let result_revision = intent
        .expected()
        .revision()
        .checked_next()
        .map_err(|_| ForgeHttpClientError::Protocol)?
        .get();
    if workspace.workspace_id != intent.expected().id().into_uuid()
        || workspace.root_path_base64
            != crate::ops::workspace_root_recovery::encode_path(intent.observed().root().as_path())
        || workspace.root_fingerprint != hex(intent.observed().fingerprint().as_bytes())
        || workspace.created_at_ms != intent.expected().created_at().get()
        || workspace.updated_at_ms != intent.observed_at().get()
        || workspace.workspace_revision != result_revision
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    Ok(())
}

fn validate_intent_receipt_digests(
    receipt: &WorkspaceRootRecoveryReceiptWire,
    intent: &WorkspaceRootRecoveryRequest,
) -> Result<(), ForgeHttpClientError> {
    let request_digest = request_intent_digest(intent);
    let witness = intent.observed().witness();
    let witness_digest = witness.as_bytes();
    if receipt.request_digest != hex(&request_digest)
        || receipt.witness_digest != hex(witness_digest)
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    match (intent.authority_mode(), receipt.delegation_receipt.as_ref()) {
        (WorkspaceRootRecoveryAuthorityMode::Quiescent, None) => {}
        (WorkspaceRootRecoveryAuthorityMode::Quiescent, Some(_))
        | (WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(_), None) => {
            return Err(ForgeHttpClientError::Protocol);
        }
        (
            WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(authority),
            Some(delegation_receipt),
        ) => {
            let expected = expected_authority_wire(intent.authority_mode())?;
            let crate::ops::workspace_root_recovery::WorkspaceRootRecoveryAuthorityModeWire::PreserveDelegatedFreeze {
                freeze,
                delegation,
                authority_digest,
                ..
            } = expected else {
                return Err(ForgeHttpClientError::Protocol);
            };
            let digest = hex(&forge_persistence::delegated_authority_digest(authority));
            if delegation_receipt.version != 2
                || delegation_receipt.kind != "preserve_delegated_freeze"
                || delegation_receipt.freeze != *freeze
                || delegation_receipt.delegation != delegation
                || delegation_receipt.authority_digest != digest
                || authority_digest.as_deref() != Some(digest.as_str())
                || delegation_receipt.normal_request_intent_digest != hex(&request_digest)
                || delegation_receipt.witness_v2_digest != hex(witness_digest)
            {
                return Err(ForgeHttpClientError::Protocol);
            }
        }
    }
    let expected_receipt_digest = receipt_digest(
        receipt,
        intent.authority_mode(),
        intent.expected().updated_at().get(),
        intent.observed_at().get(),
        intent.observed().root().as_path(),
        &request_digest,
        witness_digest,
    )?;
    if receipt.receipt_digest != hex(&expected_receipt_digest) {
        return Err(ForgeHttpClientError::Protocol);
    }
    Ok(())
}

fn request_intent_digest(request: &WorkspaceRootRecoveryRequest) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(match request.authority_mode() {
        WorkspaceRootRecoveryAuthorityMode::Quiescent => INTENT_DOMAIN,
        WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(_) => INTENT_V2_DOMAIN,
    });
    hasher.update(request.request_id().as_bytes());
    hash_i64(&mut hasher, request.location_revision().get());
    hash_workspace(&mut hasher, request.expected());
    hash_path(&mut hasher, request.observed().root().as_path());
    hash_bytes(&mut hasher, request.observed().fingerprint().as_bytes());
    hash_bytes(&mut hasher, request.observed().witness().as_bytes());
    hash_i64(&mut hasher, request.observed_at().get());
    hash_i64(&mut hasher, OPERATOR_KIND_EXPLICIT_OWNER);
    if let WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(authority) =
        request.authority_mode()
    {
        hash_i64(&mut hasher, 2);
        hash_bytes(
            &mut hasher,
            &forge_persistence::delegated_authority_digest(authority),
        );
    }
    hasher.finalize().into()
}

fn receipt_digest(
    receipt: &WorkspaceRootRecoveryReceiptWire,
    authority_mode: WorkspaceRootRecoveryAuthorityMode,
    expected_updated_at_ms: i64,
    observed_at_ms: i64,
    root_path: &Path,
    request_digest: &[u8; 32],
    witness_digest: &[u8],
) -> Result<[u8; 32], ForgeHttpClientError> {
    let old_root_fingerprint = decode_fixed::<16>(&receipt.old_root_fingerprint)?;
    let new_root_fingerprint = decode_fixed::<16>(&receipt.workspace.root_fingerprint)?;
    let mut hasher = Sha256::new();
    hasher.update(match authority_mode {
        WorkspaceRootRecoveryAuthorityMode::Quiescent => RECEIPT_DOMAIN,
        WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(_) => RECEIPT_V2_DOMAIN,
    });
    hasher.update(receipt.request_id.as_bytes());
    hash_bytes(&mut hasher, receipt.workspace.workspace_id.as_bytes());
    hash_bytes(&mut hasher, receipt.workspace.location_id.as_bytes());
    hash_i64(&mut hasher, receipt.location_revision);
    hash_i64(&mut hasher, receipt.expected_workspace_revision);
    hash_i64(&mut hasher, receipt.workspace.workspace_revision);
    hash_path(&mut hasher, root_path);
    hash_bytes(&mut hasher, &old_root_fingerprint);
    hash_bytes(&mut hasher, &new_root_fingerprint);
    hash_i64(&mut hasher, receipt.workspace.created_at_ms);
    hash_i64(&mut hasher, expected_updated_at_ms);
    hash_i64(&mut hasher, observed_at_ms);
    hash_bytes(&mut hasher, request_digest);
    hash_bytes(&mut hasher, witness_digest);
    hash_i64(&mut hasher, OPERATOR_KIND_EXPLICIT_OWNER);
    if let WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(authority) = authority_mode {
        hash_i64(&mut hasher, 2);
        hash_bytes(
            &mut hasher,
            &forge_persistence::delegated_authority_digest(authority),
        );
    }
    Ok(hasher.finalize().into())
}

fn hash_workspace(hasher: &mut Sha256, workspace: &RegisteredWorkspace) {
    hash_bytes(hasher, workspace.id().into_uuid().as_bytes());
    hash_bytes(hasher, workspace.location_id().into_uuid().as_bytes());
    hash_i64(hasher, workspace.created_at().get());
    hash_i64(hasher, workspace.updated_at().get());
    hash_i64(hasher, workspace.revision().get());
    hash_bytes(hasher, workspace.root_fingerprint().as_bytes());
}

fn hash_path(hasher: &mut Sha256, path: &Path) {
    hash_bytes(hasher, path.as_os_str().as_bytes());
}

fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hash_u64(hasher, u64::try_from(bytes.len()).unwrap_or(u64::MAX));
    hasher.update(bytes);
}

fn hash_i64(hasher: &mut Sha256, value: i64) {
    hasher.update(value.to_le_bytes());
}

fn hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

fn validate_root_path(value: &str) -> Result<(), ForgeHttpClientError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| ForgeHttpClientError::Protocol)?;
    if bytes.is_empty() || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(ForgeHttpClientError::Protocol);
    }
    WorkspaceRoot::from_canonical(PathBuf::from(OsString::from_vec(bytes)))
        .map(|_| ())
        .map_err(|_| ForgeHttpClientError::Protocol)
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], ForgeHttpClientError> {
    let mut bytes = [0_u8; N];
    if value.len() != N * 2
        || value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .enumerate()
            .try_for_each(|(index, pair)| {
                let high = hex_nibble(pair[0])?;
                let low = hex_nibble(pair[1])?;
                bytes[index] = (high << 4) | low;
                Ok::<(), ForgeHttpClientError>(())
            })
            .is_err()
    {
        return Err(ForgeHttpClientError::Protocol);
    }
    Ok(bytes)
}

fn hex_nibble(value: u8) -> Result<u8, ForgeHttpClientError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ForgeHttpClientError::Protocol),
    }
}

fn validate_digest(value: &str) -> Result<(), ForgeHttpClientError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(ForgeHttpClientError::Protocol)
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(value, "{byte:02x}");
    }
    value
}

#[cfg(test)]
mod tests {
    use std::{error::Error, path::Path};

    use forge_control::WorkspaceLocator;
    use forge_domain::{
        LocationId, LocationRevision, RegisteredWorkspace, TimestampMillis, WorkspaceId,
        WorkspaceRevision, WorkspaceRoot, WorkspaceRootFingerprint,
        WorkspaceRootRecoveryObservation, WorkspaceRootRecoveryRequest,
        WorkspaceRootRecoveryWitness,
    };

    use super::*;

    struct Fixture {
        locator: WorkspaceLocator,
        expected: RegisteredWorkspace,
        observation: WorkspaceRootRecoveryObservation,
        prepare: WorkspaceRootRecoveryPrepareRequest,
        commit: WorkspaceRootRecoveryCommitRequest,
    }

    fn fixture() -> Result<Fixture, Box<dyn Error>> {
        let locator = WorkspaceLocator::new(
            LocationId::from_uuid(Uuid::from_u128(0x101)),
            LocationRevision::new(2)?,
            Path::new("workspace"),
        )?;
        let expected = RegisteredWorkspace::from_parts_with_revision(
            WorkspaceId::from_uuid(Uuid::from_u128(0x102)),
            locator.location_id(),
            WorkspaceRoot::from_canonical("/tmp/recovery".into())?,
            WorkspaceRootFingerprint::from_bytes([1; 16]),
            TimestampMillis::new(1)?,
            TimestampMillis::new(1)?,
            WorkspaceRevision::new(1)?,
        );
        let observation = WorkspaceRootRecoveryObservation::new(
            expected.root().clone(),
            WorkspaceRootFingerprint::from_bytes([2; 16]),
            WorkspaceRootRecoveryWitness::from_bytes([3; 32]),
        );
        let recovery = WorkspaceRootRecoveryRequest::new(
            Uuid::from_u128(0x103),
            locator.expected_revision(),
            expected.clone(),
            observation.clone(),
            TimestampMillis::new(2)?,
        )?;
        Ok(Fixture {
            locator: locator.clone(),
            expected: expected.clone(),
            observation: observation.clone(),
            prepare: WorkspaceRootRecoveryPrepareRequest::new(
                locator.clone(),
                expected,
                observation,
                true,
            ),
            commit: WorkspaceRootRecoveryCommitRequest::new(locator, recovery, true),
        })
    }

    fn workspace_wire(workspace: &RegisteredWorkspace) -> WorkspaceRootRecoveryWorkspaceWire {
        WorkspaceRootRecoveryWorkspaceWire {
            workspace_id: workspace.id().into_uuid(),
            location_id: workspace.location_id().into_uuid(),
            root_path_base64: crate::ops::workspace_root_recovery::encode_path(
                workspace.root().as_path(),
            ),
            root_fingerprint: hex(workspace.root_fingerprint().as_bytes()),
            created_at_ms: workspace.created_at().get(),
            updated_at_ms: workspace.updated_at().get(),
            workspace_revision: workspace.revision().get(),
        }
    }

    fn observation_wire(
        observation: &WorkspaceRootRecoveryObservation,
    ) -> crate::ops::workspace_root_recovery::WorkspaceRootRecoveryObservationWire {
        crate::ops::workspace_root_recovery::WorkspaceRootRecoveryObservationWire {
            root_path_base64: crate::ops::workspace_root_recovery::encode_path(
                observation.root().as_path(),
            ),
            root_fingerprint: hex(observation.fingerprint().as_bytes()),
            witness: hex(observation.witness().as_bytes()),
            witness_version: None,
        }
    }

    #[test]
    fn probe_rejects_a_workspace_identity_mismatch() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let response = WorkspaceRootRecoveryProbeWire {
            status: WorkspaceRootRecoveryProbeStatus::Observed,
            locator: fixture.locator.encode(),
            location_revision: fixture.locator.expected_revision().get(),
            schema_version: CURRENT_SCHEMA_VERSION,
            requires_schema_upgrade: false,
            workspace: WorkspaceRootRecoveryWorkspaceWire {
                workspace_id: Uuid::from_u128(0x999),
                ..workspace_wire(&fixture.expected)
            },
            observation: observation_wire(&fixture.observation),
            authority_mode: crate::WorkspaceRootRecoveryAuthorityModeWire::Quiescent,
        };
        assert_eq!(
            validate_probe(
                &response,
                &WorkspaceRootRecoveryProbeRequest::new(
                    fixture.locator,
                    Some(fixture.expected.id()),
                ),
            ),
            Err(ForgeHttpClientError::Protocol)
        );
        Ok(())
    }

    #[test]
    fn prepare_accepts_a_fresh_post_migration_witness() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let mut observation = observation_wire(&fixture.observation);
        observation.witness = hex(&[4; 32]);
        let response = WorkspaceRootRecoveryProbeWire {
            status: WorkspaceRootRecoveryProbeStatus::Prepared,
            locator: fixture.prepare.locator().encode(),
            location_revision: fixture.prepare.locator().expected_revision().get(),
            schema_version: CURRENT_SCHEMA_VERSION,
            requires_schema_upgrade: false,
            workspace: workspace_wire(fixture.prepare.expected_workspace()),
            observation,
            authority_mode: crate::WorkspaceRootRecoveryAuthorityModeWire::Quiescent,
        };
        assert_eq!(validate_prepare(&response, &fixture.prepare), Ok(()));
        Ok(())
    }

    #[test]
    fn commit_rejects_a_receipt_workspace_identity_mismatch() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let intent = fixture.commit.intent();
        let response = WorkspaceRootRecoveryCommitWire {
            status: WorkspaceRootRecoveryCommitStatus::Committed,
            confirmed: true,
            receipt: WorkspaceRootRecoveryReceiptWire {
                request_id: intent.request_id(),
                location_revision: intent.location_revision().get(),
                expected_workspace_revision: intent.expected().revision().get(),
                workspace: WorkspaceRootRecoveryWorkspaceWire {
                    workspace_id: Uuid::from_u128(0x999),
                    ..workspace_wire(intent.expected())
                },
                old_root_fingerprint: hex(intent.expected().root_fingerprint().as_bytes()),
                request_digest: "00".repeat(32),
                witness_digest: "00".repeat(32),
                receipt_digest: "00".repeat(32),
                delegation_receipt: None,
            },
            recovery_action: None,
            reason: None,
        };
        assert_eq!(
            validate_commit(&response, &fixture.commit),
            Err(ForgeHttpClientError::Protocol)
        );
        Ok(())
    }
}
