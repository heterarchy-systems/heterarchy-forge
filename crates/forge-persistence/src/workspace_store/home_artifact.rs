//! Workspace-bound Home-artifact stage, publication, seal and member-read facade.

use forge_domain::{
    ActivityCoordinatorActor, HomeArtifactArchive, HomeArtifactCaptureIntent,
    HomeArtifactPathState, TimestampMillis, WorkspaceRelativePath,
};
use forge_workspace::{
    GitCheckpointStore, HomeArtifactPathRead, HomeArtifactStore, WorkspaceStateLayout,
};

use crate::{
    HomeArtifactCaptureOutcome, HomeArtifactJournalError, HomeArtifactReadback,
    HomeArtifactStageRecord, workspace_coordinators, workspace_home_transfers::artifacts,
};

use super::{WorkspaceStore, WorkspaceStoreError};

struct StagedHomeArtifactCapture {
    stage: HomeArtifactStageRecord,
    existing: HomeArtifactReadback,
    initial_publication_permit: bool,
}

impl WorkspaceStore {
    /// Durably stage one exact capture intent before initializing or accessing
    /// the Home-artifact Git store. Only the transaction that creates a stage
    /// receives one initial publication permit; replay reads the exact ref and
    /// never captures changed live files.
    pub fn capture_home_transfer_artifact<C>(
        &mut self,
        intent: &HomeArtifactCaptureIntent,
        coordinator: ActivityCoordinatorActor,
        sample_clock: C,
    ) -> Result<HomeArtifactCaptureOutcome, WorkspaceStoreError>
    where
        C: FnMut() -> Result<TimestampMillis, HomeArtifactJournalError>,
    {
        let mut sample_clock = sample_clock;
        let staged = self.stage_home_artifact_capture(intent, coordinator, &mut sample_clock)?;
        let Some(git) = self.open_home_artifact_git_for_capture(&staged)? else {
            return Ok(HomeArtifactCaptureOutcome::Pending(Box::new(staged.stage)));
        };
        self.ensure_live_binding().map_err(|source| {
            home_artifact_error(HomeArtifactJournalError::LiveBindingReadbackRequired {
                handoff_id: intent.handoff_id(),
                source: Box::new(source),
            })
        })?;
        let Some(archive) = read_or_publish_home_artifact(
            &git,
            intent,
            &staged.stage,
            staged.initial_publication_permit,
            staged.existing.seal().is_some(),
        )?
        else {
            return Ok(HomeArtifactCaptureOutcome::Pending(Box::new(staged.stage)));
        };
        self.ensure_live_binding().map_err(|source| {
            home_artifact_error(HomeArtifactJournalError::LiveBindingReadbackRequired {
                handoff_id: intent.handoff_id(),
                source: Box::new(source),
            })
        })?;

        let seal = artifacts::seal(
            &mut self.connection,
            intent,
            coordinator,
            &archive,
            &mut sample_clock,
        )
        .map_err(home_artifact_error)?;
        self.ensure_live_binding()
            .and_then(|()| self.capture_sidecar_identities())
            .and_then(|()| self.ensure_live_binding())
            .map_err(|source| {
                home_artifact_error(HomeArtifactJournalError::LiveBindingReadbackRequired {
                    handoff_id: intent.handoff_id(),
                    source: Box::new(source),
                })
            })?;
        Ok(HomeArtifactCaptureOutcome::Sealed(Box::new(seal)))
    }

    fn stage_home_artifact_capture<C>(
        &mut self,
        intent: &HomeArtifactCaptureIntent,
        coordinator: ActivityCoordinatorActor,
        sample_clock: &mut C,
    ) -> Result<StagedHomeArtifactCapture, WorkspaceStoreError>
    where
        C: FnMut() -> Result<TimestampMillis, HomeArtifactJournalError>,
    {
        self.ensure_live_binding()?;
        let staged = artifacts::stage(
            &mut self.connection,
            intent,
            coordinator,
            &mut *sample_clock,
        )
        .map_err(home_artifact_error)?;
        let stage = staged.record().clone();
        self.ensure_live_binding()
            .and_then(|()| self.capture_sidecar_identities())
            .and_then(|()| self.ensure_live_binding())
            .map_err(|source| {
                home_artifact_error(HomeArtifactJournalError::LiveBindingReadbackRequired {
                    handoff_id: intent.handoff_id(),
                    source: Box::new(source),
                })
            })?;

        let initial_publication_permit = staged.may_publish();
        if !initial_publication_permit {
            authorize_home_artifact_coordinator(
                &self.connection,
                &stage,
                coordinator,
                &mut *sample_clock,
            )
            .map_err(home_artifact_error)?;
        }
        let existing = artifacts::get(&self.connection, intent)
            .map_err(home_artifact_error)?
            .ok_or_else(|| {
                home_artifact_error(HomeArtifactJournalError::Corrupt(
                    "durable stage disappeared after commit",
                ))
            })?;
        if let Some(seal) = existing.seal()
            && seal.stage() != &stage
        {
            return Err(home_artifact_error(HomeArtifactJournalError::Corrupt(
                "seal refers to a different immutable stage",
            )));
        }
        Ok(StagedHomeArtifactCapture {
            stage,
            existing,
            initial_publication_permit,
        })
    }

    fn open_home_artifact_git_for_capture(
        &self,
        staged: &StagedHomeArtifactCapture,
    ) -> Result<Option<GitCheckpointStore>, WorkspaceStoreError> {
        if staged.initial_publication_permit {
            return GitCheckpointStore::new(
                &self.workspace_root,
                self.state_root.join("checkpoints"),
            )
            .map(Some)
            .map_err(external_error);
        }
        let Some(layout) =
            WorkspaceStateLayout::inspect_existing(&self.workspace_root).map_err(external_error)?
        else {
            return Err(home_artifact_error(HomeArtifactJournalError::Corrupt(
                "Workspace state layout disappeared after durable stage",
            )));
        };
        match GitCheckpointStore::open_existing_read_only(&layout).map_err(external_error)? {
            Some(git) => Ok(Some(git)),
            None if staged.existing.seal().is_some() => Err(home_artifact_error(
                HomeArtifactJournalError::Corrupt("sealed Home artifact has no retained Git store"),
            )),
            None => Ok(None),
        }
    }

    /// Read exact durable stage/seal history. This operation never publishes,
    /// initializes Git storage, or grants a new publication attempt.
    pub fn get_home_transfer_artifact(
        &self,
        intent: &HomeArtifactCaptureIntent,
    ) -> Result<Option<HomeArtifactReadback>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let readback = artifacts::get(&self.connection, intent).map_err(home_artifact_error)?;
        self.ensure_live_binding()?;
        Ok(readback)
    }

    /// Read one sealed manifest member after authenticating the exact current
    /// Coordinator and rechecking its live Activity lease in the Source owner.
    /// The returned bytes are restricted to the member declared by the stage.
    pub fn read_home_transfer_artifact_member<C>(
        &self,
        intent: &HomeArtifactCaptureIntent,
        coordinator: ActivityCoordinatorActor,
        path: &WorkspaceRelativePath,
        sample_clock: C,
    ) -> Result<Option<HomeArtifactPathRead>, WorkspaceStoreError>
    where
        C: FnMut() -> Result<TimestampMillis, HomeArtifactJournalError>,
    {
        let mut sample_clock = sample_clock;
        self.ensure_live_binding()?;
        let readback = artifacts::get(&self.connection, intent).map_err(home_artifact_error)?;
        let Some(readback) = readback else {
            self.ensure_live_binding()?;
            return Ok(None);
        };
        let Some(seal) = readback.seal() else {
            self.ensure_live_binding()?;
            return Ok(None);
        };
        if coordinator.workspace_id() != seal.stage().workspace_id()
            || coordinator.activity_id() != seal.stage().activity_id()
        {
            return Err(home_artifact_error(HomeArtifactJournalError::Conflict(
                "member read Coordinator scope differs from staged Workspace and Activity",
            )));
        }
        let transaction = self.connection.unchecked_transaction()?;
        let observed_at = sample_clock().map_err(home_artifact_error)?;
        if observed_at < seal.stage().staged_at() || observed_at < seal.stage().source_observed_at()
        {
            return Err(home_artifact_error(HomeArtifactJournalError::Conflict(
                "member read time precedes immutable stage",
            )));
        }
        if observed_at < seal.sealed_at() {
            return Err(home_artifact_error(HomeArtifactJournalError::Conflict(
                "member read time precedes immutable seal",
            )));
        }
        let _authorized_coordinator = workspace_coordinators::authorize_live_in_transaction(
            &transaction,
            coordinator,
            observed_at,
        )
        .map_err(|error| home_artifact_error(HomeArtifactJournalError::Coordinator(error)))?;
        transaction.commit()?;

        let git = self.open_home_artifact_git_read_only()?;
        let store = HomeArtifactStore::new(&git);
        if !intent.paths().contains(path) {
            return Err(home_artifact_error(HomeArtifactJournalError::Conflict(
                "member path is not declared by the exact stage",
            )));
        }
        let (archive, member) = store
            .read_member_with_archive(intent, path)
            .map_err(external_error)?
            .ok_or_else(|| {
                home_artifact_error(HomeArtifactJournalError::Corrupt(
                    "sealed Home artifact member disappeared",
                ))
            })?;
        if &archive != seal.archive() {
            return Err(home_artifact_error(HomeArtifactJournalError::Corrupt(
                "Git archive differs from immutable SQL seal",
            )));
        }
        let manifest_entry = archive
            .manifest()
            .entries()
            .iter()
            .find(|entry| entry.path() == path)
            .ok_or_else(|| {
                home_artifact_error(HomeArtifactJournalError::Conflict(
                    "member path is not declared by the exact stage",
                ))
            })?;
        validate_member_read(manifest_entry.state(), &member)?;
        self.ensure_live_binding()?;

        let transaction = self.connection.unchecked_transaction()?;
        let revalidated_at = sample_clock().map_err(home_artifact_error)?;
        if revalidated_at < observed_at {
            return Err(home_artifact_error(HomeArtifactJournalError::Conflict(
                "member read clock moved backwards during Git read",
            )));
        }
        let _authorized_coordinator = workspace_coordinators::authorize_live_in_transaction(
            &transaction,
            coordinator,
            revalidated_at,
        )
        .map_err(|error| home_artifact_error(HomeArtifactJournalError::Coordinator(error)))?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        Ok(Some(member))
    }

    fn open_home_artifact_git_read_only(&self) -> Result<GitCheckpointStore, WorkspaceStoreError> {
        let layout = WorkspaceStateLayout::inspect_existing(&self.workspace_root)
            .map_err(|source| {
                home_artifact_error(HomeArtifactJournalError::External(Box::new(source)))
            })?
            .ok_or_else(|| {
                home_artifact_error(HomeArtifactJournalError::Corrupt(
                    "Workspace state layout disappeared before member read",
                ))
            })?;
        GitCheckpointStore::open_existing_read_only(&layout)
            .map_err(external_error)?
            .ok_or_else(|| {
                home_artifact_error(HomeArtifactJournalError::Corrupt(
                    "Home artifact Git store is missing for sealed member read",
                ))
            })
    }
}

fn read_or_publish_home_artifact(
    git: &GitCheckpointStore,
    intent: &HomeArtifactCaptureIntent,
    stage: &HomeArtifactStageRecord,
    initial_publication_permit: bool,
    already_sealed: bool,
) -> Result<Option<HomeArtifactArchive>, WorkspaceStoreError> {
    let store = HomeArtifactStore::new(git);
    let publish_result = if initial_publication_permit {
        Some(store.publish(intent, stage.staged_at()))
    } else {
        None
    };
    match store.read(intent) {
        Ok(Some(archive)) => {
            if let Some(Ok(published)) = publish_result.as_ref()
                && published != &archive
            {
                return Err(home_artifact_error(HomeArtifactJournalError::Corrupt(
                    "published Home artifact differs from exact ref readback",
                )));
            }
            store.harden_archive(&archive).map_err(external_error)?;
            Ok(Some(archive))
        }
        Ok(None) if already_sealed => Err(home_artifact_error(HomeArtifactJournalError::Corrupt(
            "sealed SQL pin has no exact retained Git ref",
        ))),
        Ok(None) if !initial_publication_permit => Ok(None),
        Ok(None) => {
            let source = match publish_result {
                Some(Err(error)) => Box::new(error) as Box<dyn std::error::Error + Send + Sync>,
                _ => Box::new(std::io::Error::other(
                    "initial Home artifact publication returned without an exact ref",
                )),
            };
            Err(home_artifact_error(
                HomeArtifactJournalError::PublicationUnconfirmed {
                    handoff_id: intent.handoff_id(),
                    source,
                },
            ))
        }
        Err(read_error) => Err(home_artifact_error(
            HomeArtifactJournalError::PublicationUnconfirmed {
                handoff_id: intent.handoff_id(),
                source: Box::new(read_error),
            },
        )),
    }
}

fn validate_member_read(
    expected: &HomeArtifactPathState,
    actual: &HomeArtifactPathRead,
) -> Result<(), WorkspaceStoreError> {
    let matches = match (expected, actual) {
        (HomeArtifactPathState::Absent, HomeArtifactPathRead::Absent) => true,
        (
            HomeArtifactPathState::Regular {
                hash: expected_hash,
                size: expected_size,
                mode: expected_mode,
                ..
            },
            HomeArtifactPathRead::Regular {
                hash,
                size,
                mode,
                content,
            },
        ) => {
            hash == expected_hash
                && size == expected_size
                && mode == expected_mode
                && u64::try_from(content.len()).ok() == Some(size.get())
        }
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(home_artifact_error(HomeArtifactJournalError::Corrupt(
            "Git member differs from sealed manifest",
        )))
    }
}

fn home_artifact_error(error: HomeArtifactJournalError) -> WorkspaceStoreError {
    WorkspaceStoreError::HomeArtifact(Box::new(error))
}

fn external_error<E>(error: E) -> WorkspaceStoreError
where
    E: std::error::Error + Send + Sync + 'static,
{
    home_artifact_error(HomeArtifactJournalError::External(Box::new(error)))
}

fn authorize_home_artifact_coordinator<C>(
    connection: &rusqlite::Connection,
    stage: &HomeArtifactStageRecord,
    coordinator: ActivityCoordinatorActor,
    sample_clock: &mut C,
) -> Result<(), HomeArtifactJournalError>
where
    C: FnMut() -> Result<TimestampMillis, HomeArtifactJournalError>,
{
    if coordinator.workspace_id() != stage.workspace_id()
        || coordinator.activity_id() != stage.activity_id()
    {
        return Err(HomeArtifactJournalError::Conflict(
            "current Coordinator scope differs from immutable stage",
        ));
    }
    let transaction = connection.unchecked_transaction()?;
    let observed_at = sample_clock()?;
    if observed_at < stage.staged_at() || observed_at < stage.source_observed_at() {
        return Err(HomeArtifactJournalError::Conflict(
            "recovery time precedes immutable stage",
        ));
    }
    let _authorized_coordinator = workspace_coordinators::authorize_live_in_transaction(
        &transaction,
        coordinator,
        observed_at,
    )?;
    transaction.commit()?;
    Ok(())
}
