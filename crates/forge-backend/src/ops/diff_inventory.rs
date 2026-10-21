//! Bounded GUI inventory; full durable evidence remains available via diff.read.

use super::{Command, ParseResult, ScopeDto};
use crate::error::ForgeError;
use forge_control::{DiffListRequest, ForgeControlClient, ResolvedWorkspaceScope};
use forge_domain::{ActivityId, DiffListLimit, RegisteredDiffEvidence};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

pub(super) fn parse(request_id: Uuid, payload: &Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        activity_id: Uuid,
    }
    let body: Body = super::parse_body(payload, "diff.inventory payload is invalid")?;
    if body.activity_id.is_nil()
        || body.scope.workspace_id.is_nil()
        || body.scope.locator.location_id.is_nil()
    {
        return Err(ForgeError::invalid_input(
            "Diff inventory identities must not be nil",
        ));
    }
    Ok(Command::DiffInventory {
        request_id,
        scope: super::decode_scope(&body.scope)?,
        activity_id: ActivityId::from_uuid(body.activity_id),
    })
}

pub(super) fn execute(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    activity_id: ActivityId,
) -> Result<Value, ForgeError> {
    let result = client
        .diff_list(DiffListRequest {
            scope: scope.clone(),
            activity_id,
            limit: DiffListLimit::DEFAULT,
        })
        .map_err(|error| super::forge_error_of_client(&error))?;
    let diffs = result
        .diffs()
        .iter()
        .map(inventory_json)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(
        json!({"scope": super::source::scope_json(result.scope())?, "activity_id":activity_id.into_uuid(),
        "diff_count":diffs.len(),"diffs":diffs}),
    )
}

fn inventory_json(evidence: &RegisteredDiffEvidence) -> Result<Value, ForgeError> {
    let first = evidence
        .entries()
        .first()
        .ok_or_else(ForgeError::internal)?;
    let (origin, mutation_id) = match evidence.origin() {
        forge_domain::DiffOrigin::FileMutation(id) => ("file_mutation", Some(id.into_uuid())),
        forge_domain::DiffOrigin::TreeChangeSet => ("tree_change_set", None),
    };
    let uniform_kind = evidence
        .entries()
        .iter()
        .all(|entry| entry.kind() == first.kind())
        .then_some(first.kind());
    let (additions, deletions) =
        evidence
            .entries()
            .iter()
            .fold((0_u64, 0_u64), |(additions, deletions), entry| {
                (
                    additions + u64::from(entry.additions().get()),
                    deletions + u64::from(entry.deletions().get()),
                )
            });
    Ok(json!({
        "diff_id": evidence.id().into_uuid(),"workspace_id":evidence.workspace_id().into_uuid(),
        "activity_id":evidence.activity_id().into_uuid(),"change_set_id":evidence.change_set_id().into_uuid(),
        "origin":origin,"origin_mutation_id":mutation_id,"revision":evidence.revision().get(),
        "entry_count":evidence.entries().len(),"first_entry":super::diff_entry_json(first),
        "uniform_change_kind":uniform_kind.map(super::diff_change_kind_json),
        "additions":additions,"deletions":deletions,
        "state":super::diff_state_json(evidence.state()),"render_kind":super::diff_render_kind_json(evidence.payload().render_kind()),
    }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn payload_paths_survive_the_remote_evidence_projection()
    -> Result<(), Box<dyn std::error::Error>> {
        use base64::Engine as _;
        use forge_domain::*;
        let change_set = ChangeSetId::from_uuid(uuid::Uuid::from_u128(1));
        let id = DiffId::for_change_set(change_set);
        let reference = std::path::PathBuf::from(format!("diffs/diff_{id}.diff.zst"));
        let evidence = RegisteredDiffEvidence::from_parts(
            DiffAttribution::for_tree_change_set(
                id,
                WorkspaceId::from_uuid(uuid::Uuid::from_u128(2)),
                ActivityId::from_uuid(uuid::Uuid::from_u128(3)),
                change_set,
            ),
            vec![DiffEntrySummary::new(
                DiffEntrySubject::File,
                WorkspaceRelativePath::new("a.rs".into())?,
                None,
                DiffChangeKind::Modified,
                DiffLineCount::new(1),
                DiffLineCount::new(1),
            )?],
            DiffPayloadProjection::Ready {
                relative_path: DiffArtifactRelativePath::new(reference.clone())?,
                compressed_hash: DiffPayloadHash::from_bytes([1; 32]),
                uncompressed_hash: DiffPayloadHash::from_bytes([2; 32]),
                compressed_size: DiffByteCount::new(1),
                uncompressed_size: DiffByteCount::new(1),
            },
            DiffEvidenceTimestamps::new(TimestampMillis::new(1)?, TimestampMillis::new(2)?),
            DiffContractVersions::V2,
            DiffRevision::new(2)?,
        );
        let wire = super::super::diff_evidence_json(&evidence);
        assert_eq!(
            wire["relative_path_base64"],
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(reference.as_os_str().as_encoded_bytes())
        );
        Ok(())
    }
}
