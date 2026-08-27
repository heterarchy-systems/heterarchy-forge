use std::io;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::{self, JoinHandle};

use forge_domain::{
    EstablishWorkspace, LocationId, LocationListLimit, LocationName, LocationRevision,
    RegisteredLocation, RegisteredWorkspace, SetLocationState, TimestampMillis, WorkspaceId,
    WorkspaceRoot, WorkspaceRootError,
};
use forge_persistence::{WorkspaceStore, WorkspaceStoreError};
use forge_workspace::{
    LocationRepository, LocationRepositoryError, LocationService, LocationServiceError,
    StateLayoutError, WorkspaceCandidateKey, WorkspaceDiscovery, WorkspaceDiscoveryError,
    WorkspaceKeyResolveError, WorkspaceStateLayout,
};
use thiserror::Error;

const REQUEST_QUEUE_CAPACITY: usize = 16;
const FIRST_REQUEST_ID: u64 = 1;

pub type LocationWorkerReply = Result<LocationOutcome, LocationWorkerError>;

/// Ephemeral identity for correlating one UI request with one terminal reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UiRequestId(u64);

impl UiRequestId {
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Typed actions admitted by the single-owner Location service worker.
#[derive(Debug)]
pub enum LocationAction {
    List {
        limit: LocationListLimit,
    },
    Register {
        id: LocationId,
        name: LocationName,
        root: PathBuf,
        observed_at: TimestampMillis,
    },
    Discover {
        id: LocationId,
        expected_revision: LocationRevision,
    },
    SelectWorkspace {
        key: WorkspaceCandidateKey,
        location_id: LocationId,
        expected_revision: LocationRevision,
        proposed_workspace_id: WorkspaceId,
        observed_at: TimestampMillis,
    },
    SetState {
        command: SetLocationState,
    },
}

impl LocationAction {
    pub const fn list(limit: LocationListLimit) -> Self {
        Self::List { limit }
    }

    pub const fn list_default() -> Self {
        Self::list(LocationListLimit::DEFAULT)
    }

    pub fn register(
        id: LocationId,
        name: LocationName,
        root: PathBuf,
        observed_at: TimestampMillis,
    ) -> Self {
        Self::Register {
            id,
            name,
            root,
            observed_at,
        }
    }

    pub const fn discover(id: LocationId, expected_revision: LocationRevision) -> Self {
        Self::Discover {
            id,
            expected_revision,
        }
    }

    pub fn select_workspace(
        key: WorkspaceCandidateKey,
        location_id: LocationId,
        expected_revision: LocationRevision,
        proposed_workspace_id: WorkspaceId,
        observed_at: TimestampMillis,
    ) -> Self {
        Self::SelectWorkspace {
            key,
            location_id,
            expected_revision,
            proposed_workspace_id,
            observed_at,
        }
    }

    pub const fn set_state(command: SetLocationState) -> Self {
        Self::SetState { command }
    }
}

/// Typed terminal outcomes produced by a Location service action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocationOutcome {
    Locations(Vec<RegisteredLocation>),
    Registered(RegisteredLocation),
    Discovered(WorkspaceDiscovery),
    WorkspaceRegistered(RegisteredWorkspace),
    StateChanged(RegisteredLocation),
}

/// Why a durable Workspace identity could not be promoted to a committed UI
/// selection after the post-store revalidation boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WorkspaceRevalidationReason {
    #[error("Location revision changed")]
    LocationRevisionChanged,
    #[error("Location is unavailable")]
    LocationUnavailable,
    #[error("Location is disabled")]
    LocationDisabled,
    #[error("Workspace candidate is stale")]
    CandidateStale,
    #[error("Workspace root changed")]
    CandidateRootChanged,
    #[error("Workspace root physical identity changed")]
    CandidateFingerprintChanged,
    #[error("Workspace layout could not be revalidated")]
    LayoutInvalid,
}

/// Errors at the worker boundary, preserving application-service failures.
#[derive(Debug, Error)]
pub enum LocationWorkerError {
    #[error(transparent)]
    Service(#[from] LocationServiceError),
    #[error(transparent)]
    StateLayout(#[from] StateLayoutError),
    #[error(transparent)]
    WorkspaceStore(#[from] WorkspaceStoreError),
    #[error(transparent)]
    WorkspaceRoot(#[from] WorkspaceRootError),
    #[error(
        "Workspace {workspace_id} was durably committed but UI selection remains unconfirmed: {reason}"
    )]
    WorkspaceIdentityCommittedSelectionUnconfirmed {
        workspace_id: WorkspaceId,
        reason: WorkspaceRevalidationReason,
    },
    #[error("Location service worker is shutting down")]
    ShuttingDown,
    #[error("Location service worker is unavailable")]
    Unavailable,
    #[error("Location service worker request queue is full")]
    QueueFull,
    #[error("Location service worker request id space is exhausted")]
    RequestIdExhausted,
    #[error("failed to spawn Location service worker thread")]
    ThreadSpawn(#[source] io::Error),
    #[error("Location service worker thread panicked")]
    ThreadPanicked,
}

/// One-shot reply receiver for an admitted UI request.
#[derive(Debug)]
pub struct PendingRequest {
    id: UiRequestId,
    receiver: Receiver<LocationWorkerReply>,
}

impl PendingRequest {
    pub const fn id(&self) -> UiRequestId {
        self.id
    }

    pub fn recv(self) -> LocationWorkerReply {
        self.receiver
            .recv()
            .map_err(|_| LocationWorkerError::Unavailable)
            .and_then(|reply| reply)
    }

    pub fn try_recv(&self) -> Result<Option<LocationWorkerReply>, LocationWorkerError> {
        match self.receiver.try_recv() {
            Ok(reply) => Ok(Some(reply)),
            Err(std::sync::mpsc::TryRecvError::Empty) => Ok(None),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                Err(LocationWorkerError::Unavailable)
            }
        }
    }
}

#[derive(Debug)]
struct WorkerLifecycle {
    accepting: AtomicBool,
    shutdown_requested: AtomicBool,
}

#[derive(Debug)]
struct WorkRequest {
    id: UiRequestId,
    action: LocationAction,
    reply: SyncSender<LocationWorkerReply>,
}

#[derive(Debug)]
enum QueueItem {
    Request(WorkRequest),
    Shutdown,
}

/// Cloneable nonblocking admission capability for the Location worker.
#[derive(Debug, Clone)]
pub struct LocationServiceClient {
    queue: SyncSender<QueueItem>,
    lifecycle: Arc<WorkerLifecycle>,
    next_request_id: Arc<AtomicU64>,
}

impl LocationServiceClient {
    pub fn submit(&self, action: LocationAction) -> Result<PendingRequest, LocationWorkerError> {
        if !self.lifecycle.accepting.load(Ordering::Acquire) {
            return Err(LocationWorkerError::ShuttingDown);
        }

        let id = self.allocate_request_id()?;
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        if !self.lifecycle.accepting.load(Ordering::Acquire) {
            return Err(LocationWorkerError::ShuttingDown);
        }

        let request = QueueItem::Request(WorkRequest {
            id,
            action,
            reply: reply_tx,
        });
        match self.queue.try_send(request) {
            Ok(()) => Ok(PendingRequest {
                id,
                receiver: reply_rx,
            }),
            Err(mpsc::TrySendError::Full(_)) => {
                if self.lifecycle.accepting.load(Ordering::Acquire) {
                    Err(LocationWorkerError::QueueFull)
                } else {
                    Err(LocationWorkerError::ShuttingDown)
                }
            }
            Err(mpsc::TrySendError::Disconnected(_)) => Err(LocationWorkerError::Unavailable),
        }
    }

    fn allocate_request_id(&self) -> Result<UiRequestId, LocationWorkerError> {
        self.next_request_id
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map(UiRequestId)
            .map_err(|_| LocationWorkerError::RequestIdExhausted)
    }
}

/// Owns the only mutable `LocationService` instance and its bounded worker thread.
#[derive(Debug)]
pub struct LocationServiceWorker<R>
where
    R: LocationRepository + Send + 'static,
{
    client: LocationServiceClient,
    lifecycle: Arc<WorkerLifecycle>,
    thread: Option<JoinHandle<()>>,
    _repository: PhantomData<fn() -> R>,
}

impl<R> LocationServiceWorker<R>
where
    R: LocationRepository + Send + 'static,
{
    pub fn start(service: LocationService<R>) -> Result<Self, LocationWorkerError> {
        let (queue_tx, queue_rx) = mpsc::sync_channel(REQUEST_QUEUE_CAPACITY);
        let lifecycle = Arc::new(WorkerLifecycle {
            accepting: AtomicBool::new(true),
            shutdown_requested: AtomicBool::new(false),
        });
        let next_request_id = Arc::new(AtomicU64::new(FIRST_REQUEST_ID));
        let client = LocationServiceClient {
            queue: queue_tx,
            lifecycle: Arc::clone(&lifecycle),
            next_request_id,
        };
        let worker_lifecycle = Arc::clone(&lifecycle);
        let thread = thread::Builder::new()
            .name("heterarchy-forge-location-service".to_owned())
            .spawn(move || run_worker(service, &queue_rx, worker_lifecycle.as_ref()))
            .map_err(LocationWorkerError::ThreadSpawn)?;

        Ok(Self {
            client,
            lifecycle,
            thread: Some(thread),
            _repository: PhantomData,
        })
    }

    pub fn client(&self) -> LocationServiceClient {
        self.client.clone()
    }

    pub fn shutdown(&mut self) -> Result<(), LocationWorkerError> {
        self.request_shutdown();

        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        if thread.join().is_err() {
            Err(LocationWorkerError::ThreadPanicked)
        } else {
            Ok(())
        }
    }

    fn request_shutdown(&self) {
        self.lifecycle.accepting.store(false, Ordering::Release);
        let first_shutdown = !self
            .lifecycle
            .shutdown_requested
            .swap(true, Ordering::AcqRel);
        if first_shutdown {
            let _ = self.client.queue.try_send(QueueItem::Shutdown);
        }
    }
}

impl<R> Drop for LocationServiceWorker<R>
where
    R: LocationRepository + Send + 'static,
{
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn run_worker<R>(
    service: LocationService<R>,
    queue: &Receiver<QueueItem>,
    lifecycle: &WorkerLifecycle,
) where
    R: LocationRepository + Send + 'static,
{
    let mut service = service;
    loop {
        let Ok(item) = queue.recv() else { break };

        if lifecycle.shutdown_requested.load(Ordering::Acquire) {
            reject_item(item);
            drain_queue(queue);
            break;
        }

        match item {
            QueueItem::Shutdown => {
                lifecycle.shutdown_requested.store(true, Ordering::Release);
                drain_queue(queue);
                break;
            }
            QueueItem::Request(request) => {
                if lifecycle.shutdown_requested.load(Ordering::Acquire) {
                    reject_item(QueueItem::Request(request));
                    drain_queue(queue);
                    break;
                }
                let _request_id = request.id;
                let result = execute_action(&mut service, request.action);
                let _ = request.reply.send(result);
                if lifecycle.shutdown_requested.load(Ordering::Acquire) {
                    drain_queue(queue);
                    break;
                }
            }
        }
    }
    lifecycle.accepting.store(false, Ordering::Release);
}

fn execute_action<R>(
    service: &mut LocationService<R>,
    action: LocationAction,
) -> LocationWorkerReply
where
    R: LocationRepository,
{
    match action {
        LocationAction::List { limit } => service
            .list_locations(limit)
            .map(LocationOutcome::Locations)
            .map_err(LocationWorkerError::Service),
        LocationAction::Register {
            id,
            name,
            root,
            observed_at,
        } => service
            .register_selected_path(id, name.as_str(), root, observed_at)
            .map(LocationOutcome::Registered)
            .map_err(LocationWorkerError::Service),
        LocationAction::Discover {
            id,
            expected_revision,
        } => service
            .discover_current(id, expected_revision)
            .map(LocationOutcome::Discovered)
            .map_err(LocationWorkerError::Service),
        LocationAction::SelectWorkspace {
            key,
            location_id,
            expected_revision,
            proposed_workspace_id,
            observed_at,
        } => select_workspace(
            service,
            &key,
            location_id,
            expected_revision,
            proposed_workspace_id,
            observed_at,
        )
        .map(LocationOutcome::WorkspaceRegistered),
        LocationAction::SetState { command } => service
            .set_location_state(&command)
            .map(LocationOutcome::StateChanged)
            .map_err(LocationWorkerError::Service),
    }
}

/// Establish one explicitly selected Workspace outside the Slint event-loop
/// thread. Every path is revalidated against the current Location revision
/// before and after the durable Workspace store operation; only the returned
/// `RegisteredWorkspace` is eligible for a committed UI projection.
fn select_workspace<R>(
    service: &mut LocationService<R>,
    key: &WorkspaceCandidateKey,
    location_id: LocationId,
    expected_revision: LocationRevision,
    proposed_workspace_id: WorkspaceId,
    observed_at: TimestampMillis,
) -> Result<RegisteredWorkspace, LocationWorkerError>
where
    R: LocationRepository,
{
    select_workspace_with_hook(
        service,
        key,
        location_id,
        expected_revision,
        proposed_workspace_id,
        observed_at,
        |_| {},
    )
}

/// Testable seam immediately after `WorkspaceStore` has durably opened or
/// established identity and before the worker revalidates the external
/// Location/candidate observation. Production passes a no-op hook; tests use
/// it only to deterministically mutate the Location or candidate path. The
/// hook intentionally has no compensation path because the durable identity
/// is the semantic authority once `WorkspaceStore` commits it.
fn select_workspace_with_hook<R, Hook>(
    service: &mut LocationService<R>,
    key: &WorkspaceCandidateKey,
    location_id: LocationId,
    expected_revision: LocationRevision,
    proposed_workspace_id: WorkspaceId,
    observed_at: TimestampMillis,
    after_store: Hook,
) -> Result<RegisteredWorkspace, LocationWorkerError>
where
    R: LocationRepository,
    Hook: FnOnce(&mut LocationService<R>),
{
    let candidate = service.resolve_candidate_current(location_id, expected_revision, key)?;
    let layout = WorkspaceStateLayout::initialize(candidate.absolute_root())?;
    let workspace_root = WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?;
    let root_fingerprint = layout.root_fingerprint()?;
    let command = EstablishWorkspace::new(
        proposed_workspace_id,
        location_id,
        workspace_root,
        root_fingerprint,
        observed_at,
    );
    let store = WorkspaceStore::open(&layout, &command)?;
    let committed = store.workspace()?;
    after_store(service);

    // Re-resolve the opaque key and observe the root again after the durable
    // commit. A candidate can be deleted, replaced by a symlink, or rebound
    // while SQLite is opening; none of those outcomes may become a UI
    // selection. `resolve_candidate_current` also rechecks Location state and
    // the expected revision, so this is a fresh boundary observation rather
    // than a cached precondition.
    let current_candidate = service
        .resolve_candidate_current(location_id, expected_revision, key)
        .map_err(|error| {
            committed_selection_unconfirmed(committed.id(), revalidation_reason(&error))
        })?;
    let current_layout = WorkspaceStateLayout::initialize(current_candidate.absolute_root())
        .map_err(|_| {
            committed_selection_unconfirmed(
                committed.id(),
                WorkspaceRevalidationReason::LayoutInvalid,
            )
        })?;
    let current_root = WorkspaceRoot::from_canonical(current_layout.workspace_root().to_path_buf())
        .map_err(|_| {
            committed_selection_unconfirmed(
                committed.id(),
                WorkspaceRevalidationReason::CandidateRootChanged,
            )
        })?;
    let current_fingerprint = current_layout.root_fingerprint().map_err(|_| {
        committed_selection_unconfirmed(committed.id(), WorkspaceRevalidationReason::LayoutInvalid)
    })?;
    if committed.root() != &current_root {
        return Err(committed_selection_unconfirmed(
            committed.id(),
            WorkspaceRevalidationReason::CandidateRootChanged,
        ));
    }
    if committed.root_fingerprint() != current_fingerprint {
        return Err(committed_selection_unconfirmed(
            committed.id(),
            WorkspaceRevalidationReason::CandidateFingerprintChanged,
        ));
    }

    Ok(committed)
}

fn committed_selection_unconfirmed(
    workspace_id: WorkspaceId,
    reason: WorkspaceRevalidationReason,
) -> LocationWorkerError {
    LocationWorkerError::WorkspaceIdentityCommittedSelectionUnconfirmed {
        workspace_id,
        reason,
    }
}

fn revalidation_reason(error: &LocationServiceError) -> WorkspaceRevalidationReason {
    match error {
        LocationServiceError::Repository(LocationRepositoryError::RevisionConflict { .. }) => {
            WorkspaceRevalidationReason::LocationRevisionChanged
        }
        LocationServiceError::Repository(LocationRepositoryError::NotFound(_)) => {
            WorkspaceRevalidationReason::LocationUnavailable
        }
        LocationServiceError::Discovery(WorkspaceDiscoveryError::LocationDisabled(_)) => {
            WorkspaceRevalidationReason::LocationDisabled
        }
        LocationServiceError::Discovery(
            WorkspaceDiscoveryError::LocationIdentityMoved { .. }
            | WorkspaceDiscoveryError::LocationIsNotDirectory(_)
            | WorkspaceDiscoveryError::CanonicalizeLocation { .. },
        ) => WorkspaceRevalidationReason::CandidateRootChanged,
        LocationServiceError::WorkspaceKey(
            WorkspaceKeyResolveError::NotFound { .. }
            | WorkspaceKeyResolveError::LocationMismatch { .. },
        )
        | LocationServiceError::WorkspaceResolve(_)
        | LocationServiceError::WorkspaceLocator(_) => WorkspaceRevalidationReason::CandidateStale,
        LocationServiceError::Discovery(_)
        | LocationServiceError::InspectSelectedPath { .. }
        | LocationServiceError::SelectedPathIsNotDirectory(_)
        | LocationServiceError::CanonicalizeSelectedPath { .. }
        | LocationServiceError::InvalidName(_)
        | LocationServiceError::InvalidRoot(_)
        | LocationServiceError::Repository(_) => WorkspaceRevalidationReason::LocationUnavailable,
    }
}

fn reject_item(item: QueueItem) {
    if let QueueItem::Request(request) = item {
        let _ = request.reply.send(Err(LocationWorkerError::ShuttingDown));
    }
}

fn drain_queue(queue: &Receiver<QueueItem>) {
    while let Ok(item) = queue.try_recv() {
        reject_item(item);
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::sync::{Arc, mpsc};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use forge_domain::{
        ActivityListLimit, EstablishWorkspace, LocationId, LocationListLimit, LocationName,
        LocationRevision, LocationState, RegisterLocation, RegisteredLocation, RegisteredWorkspace,
        SetLocationState, TimestampMillis, WorkspaceId, WorkspaceRoot,
    };
    use forge_persistence::{GlobalRegistry, WorkspaceStore};
    use forge_workspace::{
        LocationRepository, LocationRepositoryError, LocationService, WorkspaceCandidateKey,
        WorkspaceDiscovery, WorkspaceStateLayout,
    };
    use uuid::Uuid;

    use super::{
        LocationAction, LocationOutcome, LocationServiceClient, LocationServiceWorker,
        LocationWorkerError, PendingRequest, REQUEST_QUEUE_CAPACITY, UiRequestId, WorkerLifecycle,
        WorkspaceRevalidationReason, select_workspace_with_hook,
    };

    #[derive(Debug, Default)]
    struct MemoryRepository {
        locations: Vec<RegisteredLocation>,
    }

    impl LocationRepository for MemoryRepository {
        fn register_location(
            &mut self,
            command: &RegisterLocation,
        ) -> Result<RegisteredLocation, LocationRepositoryError> {
            if let Some(existing) = self
                .locations
                .iter()
                .find(|location| location.root() == command.root())
            {
                return Err(LocationRepositoryError::AlreadyRegistered {
                    existing_id: existing.id(),
                });
            }
            let location = RegisteredLocation::from_parts_with_revision(
                command.id(),
                command.name().clone(),
                command.root().clone(),
                LocationState::Enabled,
                command.observed_at(),
                command.observed_at(),
                LocationRevision::INITIAL,
            );
            self.locations.push(location.clone());
            Ok(location)
        }

        fn list_locations(
            &self,
            limit: LocationListLimit,
        ) -> Result<Vec<RegisteredLocation>, LocationRepositoryError> {
            let mut locations = self.locations.clone();
            let maximum = usize::try_from(limit.get()).map_err(|source| {
                LocationRepositoryError::Backend {
                    operation: "convert Location list limit",
                    source: Box::new(source),
                }
            })?;
            locations.truncate(maximum);
            Ok(locations)
        }

        fn get_location(
            &self,
            id: LocationId,
        ) -> Result<Option<RegisteredLocation>, LocationRepositoryError> {
            Ok(self
                .locations
                .iter()
                .find(|location| location.id() == id)
                .cloned())
        }

        fn set_location_state(
            &mut self,
            command: &SetLocationState,
        ) -> Result<RegisteredLocation, LocationRepositoryError> {
            let location = self
                .locations
                .iter_mut()
                .find(|location| location.id() == command.id())
                .ok_or(LocationRepositoryError::NotFound(command.id()))?;
            if location.revision() != command.expected_revision() {
                return Err(LocationRepositoryError::RevisionConflict {
                    id: command.id(),
                    expected: command.expected_revision(),
                    actual: location.revision(),
                });
            }
            let revision = location.revision().checked_next().map_err(|_| {
                LocationRepositoryError::RevisionOverflow {
                    id: command.id(),
                    current: location.revision(),
                }
            })?;
            *location = RegisteredLocation::from_parts_with_revision(
                location.id(),
                location.name().clone(),
                location.root().clone(),
                command.state(),
                location.created_at(),
                command.observed_at(),
                revision,
            );
            Ok(location.clone())
        }
    }

    #[derive(Debug)]
    struct BlockingRepository {
        entered: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
    }

    #[test]
    fn select_workspace_action_carries_key_location_revision_proposal_and_observation()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("selection-action")?;
        let child = root.join("child");
        fs::create_dir_all(&child)?;
        let location_id = location_id(10)?;
        let mut worker =
            LocationServiceWorker::start(LocationService::new(MemoryRepository::default()))?;
        let client = worker.client();
        let registered = client
            .submit(LocationAction::register(
                location_id,
                LocationName::new("Selection action")?,
                root.clone(),
                TimestampMillis::new(1)?,
            ))?
            .recv()?;
        let location = match registered {
            LocationOutcome::Registered(location) => location,
            other => return Err(format!("unexpected register outcome: {other:?}").into()),
        };
        let discovery = match client
            .submit(LocationAction::discover(location_id, location.revision()))?
            .recv()?
        {
            LocationOutcome::Discovered(discovery) => discovery,
            other => return Err(format!("unexpected discover outcome: {other:?}").into()),
        };
        let key = discovery
            .candidates()
            .iter()
            .find(|candidate| candidate.relative_root() == std::path::Path::new("child"))
            .ok_or("child candidate missing")?
            .key();
        let proposed_workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(11));
        let observed_at = TimestampMillis::new(12)?;
        let action = LocationAction::select_workspace(
            key.clone(),
            location_id,
            location.revision(),
            proposed_workspace_id,
            observed_at,
        );
        match action {
            LocationAction::SelectWorkspace {
                key: actual_key,
                location_id: actual_location_id,
                expected_revision,
                proposed_workspace_id: actual_proposed_id,
                observed_at: actual_observed_at,
            } => {
                assert_eq!(actual_key, key);
                assert_eq!(actual_location_id, location_id);
                assert_eq!(expected_revision, location.revision());
                assert_eq!(actual_proposed_id, proposed_workspace_id);
                assert_eq!(actual_observed_at, observed_at);
            }
            other => return Err(format!("unexpected action: {other:?}").into()),
        }
        worker.shutdown()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn post_store_location_revision_mutation_is_committed_but_not_ui_confirmed()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("post-store-revalidation")?;
        let child = root.join("child");
        fs::create_dir_all(&child)?;
        let location_id = location_id(12)?;
        let mut service = LocationService::new(MemoryRepository::default());
        let location = service.register_selected_path(
            location_id,
            "Post-store revalidation",
            &root,
            TimestampMillis::new(1)?,
        )?;
        let discovery = service.discover(&location)?;
        let candidate = discovery
            .candidates()
            .iter()
            .find(|candidate| candidate.relative_root() == std::path::Path::new("child"))
            .ok_or("child candidate missing")?;
        let key = candidate.key();
        let candidate_root = candidate.absolute_root().to_path_buf();
        let proposed_workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(13));
        let mutation_observed_at = TimestampMillis::new(3)?;
        let result = select_workspace_with_hook(
            &mut service,
            &key,
            location_id,
            location.revision(),
            proposed_workspace_id,
            TimestampMillis::new(2)?,
            |service| {
                assert!(
                    service
                        .set_location_state(&SetLocationState::new(
                            location_id,
                            LocationRevision::INITIAL,
                            LocationState::Disabled,
                            mutation_observed_at,
                        ))
                        .is_ok()
                );
            },
        );
        assert!(matches!(
            result,
            Err(LocationWorkerError::WorkspaceIdentityCommittedSelectionUnconfirmed {
                workspace_id,
                reason: WorkspaceRevalidationReason::LocationRevisionChanged,
            }) if workspace_id == proposed_workspace_id
        ));

        let layout = WorkspaceStateLayout::initialize(&candidate_root)?;
        let reopened = WorkspaceStore::open(
            &layout,
            EstablishWorkspace::new(
                proposed_workspace_id,
                location_id,
                WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
                layout.root_fingerprint()?,
                TimestampMillis::new(4)?,
            ),
        )?;
        assert_eq!(reopened.workspace()?.id(), proposed_workspace_id);
        assert!(
            reopened
                .list_activities(ActivityListLimit::DEFAULT)?
                .is_empty()
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn post_store_candidate_replacement_is_committed_but_not_ui_confirmed()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("post-store-candidate-replacement")?;
        let child = root.join("child");
        let moved_child = root.join("child-moved");
        fs::create_dir_all(&child)?;
        let location_id = location_id(14)?;
        let mut service = LocationService::new(MemoryRepository::default());
        let location = service.register_selected_path(
            location_id,
            "Candidate replacement",
            &root,
            TimestampMillis::new(1)?,
        )?;
        let discovery = service.discover(&location)?;
        let candidate = discovery
            .candidates()
            .iter()
            .find(|candidate| candidate.relative_root() == std::path::Path::new("child"))
            .ok_or("child candidate missing")?;
        let key = candidate.key();
        let proposed_workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(15));
        let result = select_workspace_with_hook(
            &mut service,
            &key,
            location_id,
            location.revision(),
            proposed_workspace_id,
            TimestampMillis::new(2)?,
            |_: &mut LocationService<MemoryRepository>| {
                assert!(fs::rename(&child, &moved_child).is_ok());
                assert!(fs::create_dir_all(&child).is_ok());
            },
        );
        assert!(matches!(
            result,
            Err(LocationWorkerError::WorkspaceIdentityCommittedSelectionUnconfirmed {
                workspace_id,
                reason: WorkspaceRevalidationReason::CandidateFingerprintChanged,
            }) if workspace_id == proposed_workspace_id
        ));

        let moved_layout = WorkspaceStateLayout::initialize(&moved_child)?;
        let recovered = WorkspaceStore::open(
            &moved_layout,
            EstablishWorkspace::new(
                proposed_workspace_id,
                location_id,
                WorkspaceRoot::from_canonical(moved_layout.workspace_root().to_path_buf())?,
                moved_layout.root_fingerprint()?,
                TimestampMillis::new(4)?,
            ),
        )?;
        let recovered_workspace = recovered.workspace()?;
        assert_eq!(recovered_workspace.id(), proposed_workspace_id);
        assert_eq!(
            recovered_workspace.root().as_path(),
            fs::canonicalize(&moved_child)?.as_path()
        );
        assert_eq!(recovered_workspace.revision().get(), 2);
        assert!(
            recovered
                .list_activities(ActivityListLimit::DEFAULT)?
                .is_empty()
        );
        assert!(moved_layout.database_path().is_file());
        assert!(!child.join(".heterarchy-forge/state.sqlite3").exists());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    impl LocationRepository for BlockingRepository {
        fn register_location(
            &mut self,
            _command: &RegisterLocation,
        ) -> Result<RegisteredLocation, LocationRepositoryError> {
            Err(LocationRepositoryError::Backend {
                operation: "blocking test register",
                source: Box::new(io::Error::other("not implemented")),
            })
        }

        fn list_locations(
            &self,
            _limit: LocationListLimit,
        ) -> Result<Vec<RegisteredLocation>, LocationRepositoryError> {
            let _ = self.entered.send(());
            let _ = self.release.recv();
            Ok(Vec::new())
        }

        fn get_location(
            &self,
            _id: LocationId,
        ) -> Result<Option<RegisteredLocation>, LocationRepositoryError> {
            Ok(None)
        }

        fn set_location_state(
            &mut self,
            _command: &SetLocationState,
        ) -> Result<RegisteredLocation, LocationRepositoryError> {
            Err(LocationRepositoryError::Backend {
                operation: "blocking test set state",
                source: Box::new(io::Error::other("not implemented")),
            })
        }
    }

    #[test]
    fn worker_executes_each_typed_action_with_one_reply() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = unique_test_root("actions")?;
        let child = root.join("child");
        fs::create_dir_all(&child)?;
        let id = location_id(1)?;
        let mut worker =
            LocationServiceWorker::start(LocationService::new(MemoryRepository::default()))?;
        let client = worker.client();

        let registered_request = client.submit(LocationAction::Register {
            id,
            name: LocationName::new("Actions")?,
            root: root.clone(),
            observed_at: TimestampMillis::new(1)?,
        })?;
        assert_eq!(registered_request.id().get(), 1);
        let registered = registered_request.recv()?;
        let location = match registered {
            LocationOutcome::Registered(location) => location,
            other => return Err(format!("unexpected register outcome: {other:?}").into()),
        };
        assert_eq!(location.revision(), LocationRevision::INITIAL);

        let listed = client.submit(LocationAction::list_default())?.recv()?;
        assert!(
            matches!(listed, LocationOutcome::Locations(ref locations) if locations.len() == 1)
        );

        let discovered = client
            .submit(LocationAction::Discover {
                id,
                expected_revision: location.revision(),
            })?
            .recv()?;
        assert!(
            matches!(discovered, LocationOutcome::Discovered(discovery) if discovery.candidates().len() == 2)
        );

        let changed = client
            .submit(LocationAction::SetState {
                command: SetLocationState::new(
                    id,
                    location.revision(),
                    LocationState::Disabled,
                    TimestampMillis::new(2)?,
                ),
            })?
            .recv()?;
        assert!(
            matches!(changed, LocationOutcome::StateChanged(location) if location.state() == LocationState::Disabled && location.revision().get() == 2)
        );

        worker.shutdown()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn pending_try_recv_reports_idle_ready_and_disconnected_states()
    -> Result<(), Box<dyn std::error::Error>> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        let pending = PendingRequest {
            id: UiRequestId(77),
            receiver: reply_rx,
        };
        assert!(pending.try_recv()?.is_none());
        reply_tx.send(Ok(LocationOutcome::Locations(Vec::new())))?;
        assert!(matches!(
            pending.try_recv()?,
            Some(Ok(LocationOutcome::Locations(locations))) if locations.is_empty()
        ));

        let (disconnected_tx, disconnected_rx) = mpsc::sync_channel(1);
        let disconnected = PendingRequest {
            id: UiRequestId(78),
            receiver: disconnected_rx,
        };
        drop(disconnected_tx);
        assert!(matches!(
            disconnected.try_recv(),
            Err(LocationWorkerError::Unavailable)
        ));
        Ok(())
    }

    #[test]
    fn real_registry_worker_registers_then_reopens_durable_location()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("registry-durability")?;
        let workspace = root.join("workspace");
        let database = root.join("registry.sqlite3");
        fs::create_dir_all(&workspace)?;
        let canonical_workspace = fs::canonicalize(&workspace)?;

        let service = LocationService::new(GlobalRegistry::open(&database)?);
        let mut worker = LocationServiceWorker::start(service)?;
        let id = location_id(3)?;
        let reply = worker.client().submit(LocationAction::Register {
            id,
            name: LocationName::new("Durable worker location")?,
            root: workspace.clone(),
            observed_at: TimestampMillis::new(7)?,
        })?;
        let outcome = reply.recv()?;
        assert!(
            matches!(outcome, LocationOutcome::Registered(ref location)
            if location.id() == id && location.root().as_path() == canonical_workspace),
            "{outcome:?}"
        );
        worker.shutdown()?;

        let reopened = LocationService::new(GlobalRegistry::open(&database)?);
        let locations = reopened.list_locations(LocationListLimit::DEFAULT)?;
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].id(), id);
        assert_eq!(locations[0].root().as_path(), canonical_workspace);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn real_registry_selection_establishes_and_reopens_durable_workspace_id()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("workspace-selection")?;
        let location_root = root.join("location");
        let workspace_root = location_root.join("workspace");
        let database = root.join("registry.sqlite3");
        fs::create_dir_all(&workspace_root)?;
        let location_id = location_id(20)?;

        let mut worker =
            LocationServiceWorker::start(LocationService::new(GlobalRegistry::open(&database)?))?;
        let client = worker.client();
        let location = match client
            .submit(LocationAction::register(
                location_id,
                LocationName::new("Workspace selection")?,
                location_root.clone(),
                TimestampMillis::new(1)?,
            ))?
            .recv()?
        {
            LocationOutcome::Registered(location) => location,
            other => return Err(format!("unexpected register outcome: {other:?}").into()),
        };
        let discovery = match client
            .submit(LocationAction::discover(location_id, location.revision()))?
            .recv()?
        {
            LocationOutcome::Discovered(discovery) => discovery,
            other => return Err(format!("unexpected discover outcome: {other:?}").into()),
        };
        let key = workspace_key(&discovery)?;
        let first_proposal = WorkspaceId::from_uuid(Uuid::from_u128(21));
        let first = selected_workspace(client.submit(LocationAction::select_workspace(
            key.clone(),
            location_id,
            location.revision(),
            first_proposal,
            TimestampMillis::new(2)?,
        ))?)?;
        assert_eq!(first.id(), first_proposal);
        assert_eq!(first.revision().get(), 1);
        assert_eq!(first.root().as_path(), fs::canonicalize(&workspace_root)?);
        worker.shutdown()?;

        let mut reopened_worker =
            LocationServiceWorker::start(LocationService::new(GlobalRegistry::open(&database)?))?;
        let reopened_client = reopened_worker.client();
        let reopened_discovery = match reopened_client
            .submit(LocationAction::discover(location_id, location.revision()))?
            .recv()?
        {
            LocationOutcome::Discovered(discovery) => discovery,
            other => return Err(format!("unexpected reopen discover outcome: {other:?}").into()),
        };
        let reopened_key = workspace_key(&reopened_discovery)?;
        let second_proposal = WorkspaceId::from_uuid(Uuid::from_u128(22));
        let second =
            selected_workspace(reopened_client.submit(LocationAction::select_workspace(
                reopened_key,
                location_id,
                location.revision(),
                second_proposal,
                TimestampMillis::new(3)?,
            ))?)?;
        assert_eq!(second.id(), first.id());
        assert_ne!(second.id(), second_proposal);
        assert_eq!(second.revision(), first.revision());
        assert!(
            workspace_root
                .join(".heterarchy-forge/state.sqlite3")
                .is_file()
        );
        let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
        assert!(layout.database_path().is_file());
        let reopened_store = WorkspaceStore::open(
            &layout,
            EstablishWorkspace::new(
                second.id(),
                second.location_id(),
                second.root().clone(),
                second.root_fingerprint(),
                TimestampMillis::new(4)?,
            ),
        )?;
        assert!(
            reopened_store
                .list_activities(ActivityListLimit::DEFAULT)?
                .is_empty()
        );
        reopened_worker.shutdown()?;

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn stale_deleted_or_symlink_candidate_does_not_commit_selection_or_create_local_database()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("stale-selection")?;
        let child = root.join("child");
        fs::create_dir_all(&child)?;
        let location_id = location_id(30)?;
        let mut worker =
            LocationServiceWorker::start(LocationService::new(MemoryRepository::default()))?;
        let client = worker.client();
        let location = match client
            .submit(LocationAction::register(
                location_id,
                LocationName::new("Stale selection")?,
                root.clone(),
                TimestampMillis::new(1)?,
            ))?
            .recv()?
        {
            LocationOutcome::Registered(location) => location,
            other => return Err(format!("unexpected register outcome: {other:?}").into()),
        };
        let discovery = match client
            .submit(LocationAction::discover(location_id, location.revision()))?
            .recv()?
        {
            LocationOutcome::Discovered(discovery) => discovery,
            other => return Err(format!("unexpected discover outcome: {other:?}").into()),
        };
        let key = discovery
            .candidates()
            .iter()
            .find(|candidate| candidate.relative_root() == std::path::Path::new("child"))
            .ok_or("child candidate missing")?
            .key();
        fs::remove_dir_all(&child)?;
        let replacement = root.join("replacement");
        fs::create_dir_all(&replacement)?;
        symlink(&replacement, &child)?;
        let stale = client
            .submit(LocationAction::select_workspace(
                key,
                location_id,
                location.revision(),
                WorkspaceId::from_uuid(Uuid::from_u128(31)),
                TimestampMillis::new(2)?,
            ))?
            .recv();
        assert!(matches!(
            stale,
            Err(LocationWorkerError::Service(
                forge_workspace::LocationServiceError::WorkspaceKey(
                    forge_workspace::WorkspaceKeyResolveError::NotFound { .. }
                )
            ))
        ));
        assert!(!replacement.join(".heterarchy-forge/state.sqlite3").exists());
        worker.shutdown()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn stale_discover_rejects_before_filesystem_scan_and_abandoned_reply_is_normal()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("stale-discover")?;
        fs::create_dir_all(&root)?;
        let id = location_id(2)?;
        let mut worker =
            LocationServiceWorker::start(LocationService::new(MemoryRepository::default()))?;
        let client = worker.client();
        let registered = client
            .submit(LocationAction::Register {
                id,
                name: LocationName::new("Stale")?,
                root: root.clone(),
                observed_at: TimestampMillis::new(1)?,
            })?
            .recv()?;
        let location = match registered {
            LocationOutcome::Registered(location) => location,
            other => return Err(format!("unexpected register outcome: {other:?}").into()),
        };
        let _ = client
            .submit(LocationAction::SetState {
                command: SetLocationState::new(
                    id,
                    location.revision(),
                    LocationState::Disabled,
                    TimestampMillis::new(2)?,
                ),
            })?
            .recv()?;
        fs::remove_dir_all(&root)?;

        let stale = client
            .submit(LocationAction::Discover {
                id,
                expected_revision: location.revision(),
            })?
            .recv();
        assert!(matches!(
            stale,
            Err(LocationWorkerError::Service(
                forge_workspace::LocationServiceError::Repository(
                    LocationRepositoryError::RevisionConflict { .. }
                )
            ))
        ));

        drop(client.submit(LocationAction::list_default())?);
        worker.shutdown()?;
        Ok(())
    }

    #[test]
    fn full_queue_rejects_without_blocking_and_request_ids_exhaust_closed_space()
    -> Result<(), Box<dyn std::error::Error>> {
        let (queue, _receiver) = mpsc::sync_channel(REQUEST_QUEUE_CAPACITY);
        let lifecycle = Arc::new(WorkerLifecycle {
            accepting: std::sync::atomic::AtomicBool::new(true),
            shutdown_requested: std::sync::atomic::AtomicBool::new(false),
        });
        let client = LocationServiceClient {
            queue,
            lifecycle: Arc::clone(&lifecycle),
            next_request_id: Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
        };
        assert!(matches!(
            client.submit(LocationAction::list_default()),
            Err(LocationWorkerError::RequestIdExhausted)
        ));

        let (queue, _receiver) = mpsc::sync_channel(REQUEST_QUEUE_CAPACITY);
        let client = LocationServiceClient {
            queue,
            lifecycle,
            next_request_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        };
        let mut pending = Vec::new();
        for _ in 0..REQUEST_QUEUE_CAPACITY {
            pending.push(client.submit(LocationAction::list_default())?);
        }
        let started = std::time::Instant::now();
        assert!(matches!(
            client.submit(LocationAction::list_default()),
            Err(LocationWorkerError::QueueFull)
        ));
        assert!(started.elapsed() < Duration::from_millis(100));
        drop(pending);
        Ok(())
    }

    #[test]
    fn shutdown_rejects_new_requests_drains_queue_and_is_idempotent()
    -> Result<(), Box<dyn std::error::Error>> {
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let mut worker = LocationServiceWorker::start(LocationService::new(BlockingRepository {
            entered: entered_tx,
            release: release_rx,
        }))?;
        let client = worker.client();
        let current = client.submit(LocationAction::list_default())?;
        entered_rx.recv_timeout(Duration::from_secs(1))?;
        let mut queued = Vec::new();
        for _ in 0..REQUEST_QUEUE_CAPACITY {
            queued.push(client.submit(LocationAction::list_default())?);
        }

        worker.request_shutdown();
        release_tx.send(())?;
        worker.shutdown()?;
        assert!(matches!(current.recv(), Ok(LocationOutcome::Locations(_))));
        for pending in queued {
            assert!(matches!(
                pending.recv(),
                Err(LocationWorkerError::ShuttingDown)
            ));
        }
        assert!(matches!(
            client.submit(LocationAction::list_default()),
            Err(LocationWorkerError::ShuttingDown)
        ));
        worker.shutdown()?;
        Ok(())
    }

    #[test]
    fn worker_source_has_no_ui_or_slint_types() {
        let source = include_str!("location_worker.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(!production.contains("slint"));
        assert!(!production.contains("AppWindow"));
        assert!(!production.contains("ForgeTray"));
    }

    fn workspace_key(
        discovery: &WorkspaceDiscovery,
    ) -> Result<WorkspaceCandidateKey, Box<dyn std::error::Error>> {
        Ok(discovery
            .candidates()
            .iter()
            .find(|candidate| candidate.relative_root() == std::path::Path::new("workspace"))
            .ok_or_else(|| io::Error::other("workspace candidate missing"))
            .map(forge_workspace::WorkspaceCandidate::key)?)
    }

    fn selected_workspace(
        pending: PendingRequest,
    ) -> Result<RegisteredWorkspace, Box<dyn std::error::Error>> {
        match pending.recv()? {
            LocationOutcome::WorkspaceRegistered(workspace) => Ok(workspace),
            other => Err(format!("unexpected selection outcome: {other:?}").into()),
        }
    }

    fn location_id(value: u128) -> Result<LocationId, Box<dyn std::error::Error>> {
        let value = format!("00000000-0000-0000-0000-{value:012x}");
        Ok(LocationId::from_str(&value)?)
    }

    fn unique_test_root(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        Ok(std::env::temp_dir().join(format!("heterarchy-forge-worker-{label}-{unique}")))
    }
}
