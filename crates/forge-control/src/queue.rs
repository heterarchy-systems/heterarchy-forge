//! Bounded five-lane control mailbox and runtime queue metrics.
//!
//! The mailbox owns only queue storage and short synchronization. Request
//! classification, effects, persistence, and worker execution remain with the
//! control worker. The packaged Orchestration policy owns admission and class
//! dispatch decisions; this adapter preserves FIFO order within each class.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};

use forge_domain::{LocationId, WorkspaceId};
use heterarchy_orchestration_policy::{
    QueueAdmissionInput, QueueCapacity, QueueDepths, QueueDispatchInput, QueueDispatchOutcome,
    QueueHeads, ServiceClass, TimestampMicros, evaluate_queue_admission, evaluate_queue_dispatch,
};

const QUEUE_OPERATION: &str = "forge_control.queue";
const MAX_QUEUE_PARTITIONS: usize = 64;
const GLOBAL_QUEUE_CAPACITY: QueueCapacity = QueueCapacity::C256;

/// Server-owned queue attribution. UI selection is never consulted here.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum QueueAttribution {
    Global,
    Location(LocationId),
    Workspace(WorkspaceId),
}

/// Source of the currently effective general queue capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueCapacitySource {
    Default,
    UserProvided,
}

/// Read-only bounded queue projection for runtime/UI consumers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueStatus {
    target_capacity: QueueCapacity,
    source: QueueCapacitySource,
    config_revision: u64,
    draining: bool,
    depths: QueueDepths,
    oldest_age_micros: [Option<u64>; 5],
    active_worker: bool,
    rejected_count: u64,
    high_water: u16,
    aging_count: u64,
    initialized: bool,
    global_depth: u16,
    global_rejected_count: u64,
    global_high_water: u16,
    persisted_revision: Option<u64>,
}

impl QueueStatus {
    #[must_use]
    pub const fn target_capacity(self) -> QueueCapacity {
        self.target_capacity
    }

    #[must_use]
    pub const fn source(self) -> QueueCapacitySource {
        self.source
    }

    #[must_use]
    pub const fn config_revision(self) -> u64 {
        self.config_revision
    }

    #[must_use]
    pub const fn draining(self) -> bool {
        self.draining
    }

    #[must_use]
    pub const fn depths(self) -> QueueDepths {
        self.depths
    }

    #[must_use]
    pub const fn oldest_age_micros(self) -> [Option<u64>; 5] {
        self.oldest_age_micros
    }

    #[must_use]
    pub const fn active_worker(self) -> bool {
        self.active_worker
    }

    #[must_use]
    pub const fn rejected_count(self) -> u64 {
        self.rejected_count
    }

    #[must_use]
    pub const fn high_water(self) -> u16 {
        self.high_water
    }

    #[must_use]
    pub const fn aging_count(self) -> u64 {
        self.aging_count
    }

    #[must_use]
    pub const fn initialized(self) -> bool {
        self.initialized
    }

    #[must_use]
    pub const fn global_depth(self) -> u16 {
        self.global_depth
    }

    #[must_use]
    pub const fn global_capacity(self) -> QueueCapacity {
        GLOBAL_QUEUE_CAPACITY
    }

    #[must_use]
    pub const fn global_rejected_count(self) -> u64 {
        self.global_rejected_count
    }

    #[must_use]
    pub const fn global_high_water(self) -> u16 {
        self.global_high_water
    }

    #[must_use]
    pub const fn persisted_revision(self) -> Option<u64> {
        self.persisted_revision
    }
}

/// Typed resize/configuration failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueueConfigError {
    Closed,
    PartitionLimit,
    StaleRevision { expected: u64, actual: u64 },
    StalePersistedRevision { incoming: u64, current: u64 },
    PersistedPreferenceConflict,
    Policy(heterarchy_orchestration_policy::ErrorCode),
    RevisionOverflow,
    Poisoned,
}

/// Typed admission failures from the bounded mailbox.
#[derive(Debug)]
pub(crate) enum QueueEnqueueError {
    Closed,
    PartitionLimit,
    Rejected,
    Policy,
    CounterOverflow,
    Poisoned,
}

/// Typed dequeue/runtime failures. `Empty` is a normal nonblocking result.
#[derive(Debug)]
pub(crate) enum QueueDequeue<T> {
    Empty,
    Item { item: T },
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueueRuntimeError {
    Closed,
    PartitionLimit,
    Policy(heterarchy_orchestration_policy::ErrorCode),
    CounterOverflow,
    Poisoned,
}

struct QueueEntry<T> {
    item: T,
    enqueued_at: TimestampMicros,
}

struct QueueState<T> {
    lanes: [VecDeque<QueueEntry<T>>; 5],
    target_capacity: QueueCapacity,
    draining_ceiling: u16,
    source: QueueCapacitySource,
    initialized: bool,
    config_revision: u64,
    persisted_revision: Option<u64>,
    rejected_count: u64,
    high_water: u16,
    aging_count: u64,
}

impl<T> QueueState<T> {
    fn new(target_capacity: QueueCapacity, source: QueueCapacitySource, initialized: bool) -> Self {
        Self {
            lanes: std::array::from_fn(|_| VecDeque::new()),
            target_capacity,
            draining_ceiling: target_capacity.slots(),
            source,
            initialized,
            config_revision: 0,
            persisted_revision: None,
            rejected_count: 0,
            high_water: 0,
            aging_count: 0,
        }
    }

    fn depths(&self) -> QueueDepths {
        QueueDepths::new(
            bounded_depth(self.lanes[0].len()),
            bounded_depth(self.lanes[1].len()),
            bounded_depth(self.lanes[2].len()),
            bounded_depth(self.lanes[3].len()),
            bounded_depth(self.lanes[4].len()),
        )
    }

    fn heads(&self) -> QueueHeads {
        QueueHeads::new(
            self.lanes[0].front().map(|entry| entry.enqueued_at),
            self.lanes[1].front().map(|entry| entry.enqueued_at),
            self.lanes[2].front().map(|entry| entry.enqueued_at),
            self.lanes[3].front().map(|entry| entry.enqueued_at),
            self.lanes[4].front().map(|entry| entry.enqueued_at),
        )
    }

    fn status(
        &self,
        observed_at: TimestampMicros,
        active_worker: bool,
        global_depth: u16,
        global_rejected_count: u64,
        global_high_water: u16,
    ) -> Result<QueueStatus, QueueRuntimeError> {
        let depths = self.depths();
        let mut oldest_age_micros = [None; 5];
        for (index, lane) in self.lanes.iter().enumerate() {
            let Some(entry) = lane.front() else {
                continue;
            };
            let age =
                observed_at
                    .0
                    .checked_sub(entry.enqueued_at.0)
                    .ok_or(QueueRuntimeError::Policy(
                        heterarchy_orchestration_policy::ErrorCode::QueueInvalidSnapshot,
                    ))?;
            oldest_age_micros[index] = Some(age);
        }
        Ok(QueueStatus {
            target_capacity: self.target_capacity,
            source: self.source,
            config_revision: self.config_revision,
            draining: depths.total() > u32::from(self.target_capacity.slots()),
            depths,
            oldest_age_micros,
            active_worker,
            rejected_count: self.rejected_count,
            high_water: self.high_water,
            aging_count: self.aging_count,
            initialized: self.initialized,
            global_depth,
            global_rejected_count,
            global_high_water,
            persisted_revision: self.persisted_revision,
        })
    }
}

struct QueuePartition<T> {
    attribution: QueueAttribution,
    state: QueueState<T>,
}

struct QueueManagerState<T> {
    partitions: Vec<QueuePartition<T>>,
    schedule_cursor: u8,
    dispatch_count: u64,
    bucket_cursors: [usize; 5],
    closed: bool,
    active_worker: bool,
    inflight_partition: Option<usize>,
    last_observed_at: TimestampMicros,
    global_rejected_count: u64,
    global_high_water: u16,
    global_aging_count: u64,
}

impl<T> QueueManagerState<T> {
    fn new() -> Self {
        Self {
            partitions: vec![QueuePartition {
                attribution: QueueAttribution::Global,
                state: QueueState::new(GLOBAL_QUEUE_CAPACITY, QueueCapacitySource::Default, true),
            }],
            schedule_cursor: 0,
            dispatch_count: 0,
            bucket_cursors: [0; 5],
            closed: false,
            active_worker: false,
            inflight_partition: None,
            last_observed_at: TimestampMicros(0),
            global_rejected_count: 0,
            global_high_water: 0,
            global_aging_count: 0,
        }
    }

    fn total_depths(&self) -> QueueDepths {
        let mut depths = QueueDepths::default();
        for partition in &self.partitions {
            let current = partition.state.depths();
            depths.liveness = depths.liveness.saturating_add(current.liveness);
            depths.authority_control = depths
                .authority_control
                .saturating_add(current.authority_control);
            depths.interactive = depths.interactive.saturating_add(current.interactive);
            depths.work = depths.work.saturating_add(current.work);
            depths.background = depths.background.saturating_add(current.background);
        }
        depths
    }

    fn partition_index(&self, attribution: QueueAttribution) -> Option<usize> {
        self.partitions
            .iter()
            .position(|partition| partition.attribution == attribution)
    }

    fn ensure_partition(
        &mut self,
        attribution: QueueAttribution,
    ) -> Result<usize, QueueEnqueueError> {
        if let Some(index) = self.partition_index(attribution) {
            return Ok(index);
        }
        if self.partitions.len() >= MAX_QUEUE_PARTITIONS {
            if let Some((index, _)) =
                self.partitions
                    .iter()
                    .enumerate()
                    .find(|(index, partition)| {
                        partition.attribution != QueueAttribution::Global
                            && partition.state.depths().total() == 0
                            && partition.state.source != QueueCapacitySource::UserProvided
                            && self.inflight_partition != Some(*index)
                    })
            {
                let old_last = self.partitions.len() - 1;
                self.partitions.swap_remove(index);
                let new_len = self.partitions.len();
                if let Some(inflight) = self.inflight_partition
                    && inflight == old_last
                {
                    self.inflight_partition = Some(index);
                }
                for cursor in &mut self.bucket_cursors {
                    if *cursor == old_last {
                        *cursor = index % new_len;
                    }
                }
            } else {
                return Err(QueueEnqueueError::PartitionLimit);
            }
        }
        let (capacity, source, initialized) = match attribution {
            QueueAttribution::Global => (GLOBAL_QUEUE_CAPACITY, QueueCapacitySource::Default, true),
            QueueAttribution::Location(_) => {
                (QueueCapacity::C32, QueueCapacitySource::Default, true)
            }
            QueueAttribution::Workspace(_) => {
                (QueueCapacity::C32, QueueCapacitySource::Default, false)
            }
        };
        self.partitions.push(QueuePartition {
            attribution,
            state: QueueState::new(capacity, source, initialized),
        });
        Ok(self.partitions.len() - 1)
    }
}

struct QueueInner<T> {
    state: Mutex<QueueManagerState<T>>,
    available: Condvar,
}

/// Cloneable bounded mailbox handle used by the control worker and producers.
pub(crate) struct QueueMailbox<T> {
    inner: Arc<QueueInner<T>>,
}

impl<T> std::fmt::Debug for QueueMailbox<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QueueMailbox")
            .finish_non_exhaustive()
    }
}

impl<T> Clone for QueueMailbox<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T> QueueMailbox<T> {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(QueueInner {
                state: Mutex::new(QueueManagerState::new()),
                available: Condvar::new(),
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn try_enqueue(
        &self,
        class: ServiceClass,
        item: T,
        enqueued_at: TimestampMicros,
    ) -> Result<(), QueueEnqueueError> {
        self.try_enqueue_attribution(QueueAttribution::Global, class, item, enqueued_at)
    }

    pub(crate) fn try_enqueue_attribution(
        &self,
        attribution: QueueAttribution,
        class: ServiceClass,
        item: T,
        enqueued_at: TimestampMicros,
    ) -> Result<(), QueueEnqueueError> {
        let Ok(mut state) = self.inner.state.lock() else {
            return Err(QueueEnqueueError::Poisoned);
        };
        if state.closed {
            return Err(QueueEnqueueError::Closed);
        }
        let partition_index = state.ensure_partition(attribution)?;
        let global_depth = state.total_depths().total();
        let global_input = QueueAdmissionInput::new(
            state.total_depths(),
            GLOBAL_QUEUE_CAPACITY,
            GLOBAL_QUEUE_CAPACITY.slots(),
        );
        let global_decision = evaluate_queue_admission(QUEUE_OPERATION, class, global_input)
            .map_err(|_| QueueEnqueueError::Policy)?;
        if !global_decision.admitted() {
            state.global_rejected_count = state
                .global_rejected_count
                .checked_add(1)
                .ok_or(QueueEnqueueError::CounterOverflow)?;
            state.partitions[partition_index].state.rejected_count = state.partitions
                [partition_index]
                .state
                .rejected_count
                .checked_add(1)
                .ok_or(QueueEnqueueError::CounterOverflow)?;
            return Err(QueueEnqueueError::Rejected);
        }
        let enqueued_at = state.last_observed_at.max(enqueued_at);
        state.last_observed_at = enqueued_at;
        let partition_decision = {
            let partition = &state.partitions[partition_index].state;
            let input = QueueAdmissionInput::new(
                partition.depths(),
                partition.target_capacity,
                partition.draining_ceiling,
            );
            evaluate_queue_admission(QUEUE_OPERATION, class, input)
        };
        let decision = match partition_decision {
            Ok(decision) => decision,
            Err(_error) => {
                return Err(QueueEnqueueError::Policy);
            }
        };
        if !decision.admitted() {
            state.global_rejected_count = match state.global_rejected_count.checked_add(1) {
                Some(value) => value,
                None => return Err(QueueEnqueueError::CounterOverflow),
            };
            let partition_rejected = &mut state.partitions[partition_index].state.rejected_count;
            *partition_rejected = match partition_rejected.checked_add(1) {
                Some(value) => value,
                None => return Err(QueueEnqueueError::CounterOverflow),
            };
            return Err(QueueEnqueueError::Rejected);
        }
        let partition = &mut state.partitions[partition_index].state;
        let index = class_index(class);
        partition.lanes[index].push_back(QueueEntry { item, enqueued_at });
        let total = partition.depths().total();
        let total = usize::try_from(total).unwrap_or(usize::MAX);
        partition.high_water = partition.high_water.max(bounded_depth(total));
        let global_total = global_depth
            .checked_add(1)
            .ok_or(QueueEnqueueError::CounterOverflow)?;
        state.global_high_water = state.global_high_water.max(bounded_depth(
            usize::try_from(global_total).unwrap_or(usize::MAX),
        ));
        drop(state);
        self.inner.available.notify_one();
        Ok(())
    }

    pub(crate) fn try_dequeue(
        &self,
        observed_at: TimestampMicros,
    ) -> Result<QueueDequeue<T>, QueueRuntimeError> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| QueueRuntimeError::Poisoned)?;
        let observed_at = state.last_observed_at.max(observed_at);
        state.last_observed_at = observed_at;
        dequeue_locked(&mut state, observed_at)
    }

    pub(crate) fn wait_dequeue(
        &self,
        observed_at: TimestampMicros,
    ) -> Result<QueueDequeue<T>, QueueRuntimeError> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| QueueRuntimeError::Poisoned)?;
        let observed_at = state.last_observed_at.max(observed_at);
        state.last_observed_at = observed_at;
        match dequeue_locked(&mut state, observed_at)? {
            QueueDequeue::Empty => {
                let _state = self
                    .inner
                    .available
                    .wait(state)
                    .map_err(|_| QueueRuntimeError::Poisoned)?;
                Ok(QueueDequeue::Empty)
            }
            result => Ok(result),
        }
    }

    #[cfg(test)]
    fn wait_dequeue_poison_probe(
        &self,
        barrier: &std::sync::Barrier,
    ) -> Result<QueueDequeue<T>, QueueRuntimeError> {
        let state = self
            .inner
            .state
            .lock()
            .map_err(|_| QueueRuntimeError::Poisoned)?;
        if state.total_depths().total() != 0 {
            drop(state);
            return self.try_dequeue(TimestampMicros(1));
        }
        barrier.wait();
        match self.inner.available.wait(state) {
            Ok(_) => Ok(QueueDequeue::Empty),
            Err(_) => Err(QueueRuntimeError::Poisoned),
        }
    }

    pub(crate) fn close(&self) -> Result<(), QueueRuntimeError> {
        let mut state = match self.inner.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.closed = true;
                drop(state);
                self.inner.available.notify_all();
                return Err(QueueRuntimeError::Poisoned);
            }
        };
        state.closed = true;
        drop(state);
        self.inner.available.notify_all();
        Ok(())
    }

    pub(crate) fn set_active_worker(&self, active: bool) -> Result<(), QueueRuntimeError> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| QueueRuntimeError::Poisoned)?;
        state.active_worker = active;
        Ok(())
    }

    pub(crate) fn finish_dispatch(&self) -> Result<(), QueueRuntimeError> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| QueueRuntimeError::Poisoned)?;
        state.inflight_partition = None;
        Ok(())
    }

    pub(crate) fn status(
        &self,
        observed_at: TimestampMicros,
    ) -> Result<QueueStatus, QueueRuntimeError> {
        self.status_for(QueueAttribution::Global, observed_at)
    }

    pub(crate) fn status_for(
        &self,
        attribution: QueueAttribution,
        observed_at: TimestampMicros,
    ) -> Result<QueueStatus, QueueRuntimeError> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| QueueRuntimeError::Poisoned)?;
        let index = state
            .ensure_partition(attribution)
            .map_err(|error| map_partition_enqueue_error(&error))?;
        let observed_at = state.last_observed_at.max(observed_at);
        state.last_observed_at = observed_at;
        status_locked(&state, index, observed_at)
    }

    pub(crate) fn apply_capacity(
        &self,
        capacity: QueueCapacity,
        expected_config_revision: u64,
    ) -> Result<QueueStatus, QueueConfigError> {
        self.apply_capacity_for(QueueAttribution::Global, capacity, expected_config_revision)
    }

    pub(crate) fn apply_workspace_capacity(
        &self,
        workspace_id: WorkspaceId,
        capacity: QueueCapacity,
        expected_config_revision: u64,
    ) -> Result<QueueStatus, QueueConfigError> {
        self.apply_capacity_for(
            QueueAttribution::Workspace(workspace_id),
            capacity,
            expected_config_revision,
        )
    }

    pub(crate) fn install_workspace_preference(
        &self,
        workspace_id: WorkspaceId,
        preference: Option<(QueueCapacity, u64)>,
    ) -> Result<QueueStatus, QueueConfigError> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| QueueConfigError::Poisoned)?;
        if state.closed {
            return Err(QueueConfigError::Closed);
        }
        let index = state
            .ensure_partition(QueueAttribution::Workspace(workspace_id))
            .map_err(|error| map_partition_config_error(&error))?;
        let partition = &mut state.partitions[index].state;
        let Some((capacity, persisted_revision)) = preference else {
            if partition.persisted_revision.is_some() {
                return Err(QueueConfigError::PersistedPreferenceConflict);
            }
            if partition.initialized {
                return status_locked(&state, index, state.last_observed_at)
                    .map_err(queue_config_error_from_runtime);
            }
            partition.target_capacity = QueueCapacity::default();
            partition.draining_ceiling = partition.target_capacity.slots();
            partition.source = QueueCapacitySource::Default;
            partition.initialized = true;
            partition.config_revision = partition
                .config_revision
                .checked_add(1)
                .ok_or(QueueConfigError::RevisionOverflow)?;
            return status_locked(&state, index, state.last_observed_at)
                .map_err(queue_config_error_from_runtime);
        };
        if let Some(current) = partition.persisted_revision {
            if persisted_revision < current {
                return Err(QueueConfigError::StalePersistedRevision {
                    incoming: persisted_revision,
                    current,
                });
            }
            if persisted_revision == current {
                if partition.target_capacity != capacity {
                    return Err(QueueConfigError::PersistedPreferenceConflict);
                }
                return status_locked(&state, index, state.last_observed_at)
                    .map_err(queue_config_error_from_runtime);
            }
        }
        let input = heterarchy_orchestration_policy::capture_draining_ceiling(
            QUEUE_OPERATION,
            capacity,
            partition.depths(),
        )
        .map_err(|error| QueueConfigError::Policy(error.code))?;
        partition.config_revision = partition
            .config_revision
            .checked_add(1)
            .ok_or(QueueConfigError::RevisionOverflow)?;
        partition.target_capacity = capacity;
        partition.draining_ceiling = input.draining_ceiling;
        partition.source = QueueCapacitySource::UserProvided;
        partition.initialized = true;
        partition.persisted_revision = Some(persisted_revision);
        status_locked(&state, index, state.last_observed_at)
            .map_err(queue_config_error_from_runtime)
    }

    fn apply_capacity_for(
        &self,
        attribution: QueueAttribution,
        capacity: QueueCapacity,
        expected_config_revision: u64,
    ) -> Result<QueueStatus, QueueConfigError> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| QueueConfigError::Poisoned)?;
        if state.closed {
            return Err(QueueConfigError::Closed);
        }
        let index = state
            .ensure_partition(attribution)
            .map_err(|error| map_partition_config_error(&error))?;
        let partition = &mut state.partitions[index].state;
        if partition.config_revision != expected_config_revision {
            return Err(QueueConfigError::StaleRevision {
                expected: expected_config_revision,
                actual: partition.config_revision,
            });
        }
        let input = heterarchy_orchestration_policy::capture_draining_ceiling(
            QUEUE_OPERATION,
            capacity,
            partition.depths(),
        )
        .map_err(|error| QueueConfigError::Policy(error.code))?;
        partition.config_revision = partition
            .config_revision
            .checked_add(1)
            .ok_or(QueueConfigError::RevisionOverflow)?;
        partition.target_capacity = capacity;
        partition.draining_ceiling = input.draining_ceiling;
        partition.source = QueueCapacitySource::UserProvided;
        partition.initialized = true;
        status_locked(&state, index, state.last_observed_at).map_err(|error| match error {
            QueueRuntimeError::Policy(code) => QueueConfigError::Policy(code),
            QueueRuntimeError::Closed => QueueConfigError::Closed,
            QueueRuntimeError::PartitionLimit => QueueConfigError::PartitionLimit,
            QueueRuntimeError::CounterOverflow => QueueConfigError::RevisionOverflow,
            QueueRuntimeError::Poisoned => QueueConfigError::Poisoned,
        })
    }
}

fn bounded_depth(length: usize) -> u16 {
    u16::try_from(length).unwrap_or(u16::MAX)
}

fn map_partition_enqueue_error(error: &QueueEnqueueError) -> QueueRuntimeError {
    match error {
        QueueEnqueueError::Closed => QueueRuntimeError::Closed,
        QueueEnqueueError::PartitionLimit => QueueRuntimeError::PartitionLimit,
        QueueEnqueueError::Rejected | QueueEnqueueError::Policy => QueueRuntimeError::Policy(
            heterarchy_orchestration_policy::ErrorCode::QueueInvalidSnapshot,
        ),
        QueueEnqueueError::CounterOverflow => QueueRuntimeError::CounterOverflow,
        QueueEnqueueError::Poisoned => QueueRuntimeError::Poisoned,
    }
}

fn map_partition_config_error(error: &QueueEnqueueError) -> QueueConfigError {
    match error {
        QueueEnqueueError::Closed => QueueConfigError::Closed,
        QueueEnqueueError::PartitionLimit => QueueConfigError::PartitionLimit,
        QueueEnqueueError::Policy | QueueEnqueueError::Rejected => QueueConfigError::Policy(
            heterarchy_orchestration_policy::ErrorCode::QueueInvalidSnapshot,
        ),
        QueueEnqueueError::CounterOverflow => QueueConfigError::RevisionOverflow,
        QueueEnqueueError::Poisoned => QueueConfigError::Poisoned,
    }
}

fn queue_config_error_from_runtime(error: QueueRuntimeError) -> QueueConfigError {
    match error {
        QueueRuntimeError::Closed => QueueConfigError::Closed,
        QueueRuntimeError::PartitionLimit => QueueConfigError::PartitionLimit,
        QueueRuntimeError::Policy(code) => QueueConfigError::Policy(code),
        QueueRuntimeError::CounterOverflow => QueueConfigError::RevisionOverflow,
        QueueRuntimeError::Poisoned => QueueConfigError::Poisoned,
    }
}

fn aggregate_heads<T>(state: &QueueManagerState<T>) -> QueueHeads {
    let mut heads = QueueHeads::default();
    for partition in &state.partitions {
        let current = partition.state.heads();
        for class in ServiceClass::ORDER {
            let candidate = current.get(class);
            let selected = heads.get(class);
            let Some(candidate) = candidate else {
                continue;
            };
            if selected.is_none_or(|selected| candidate.0 < selected.0) {
                match class {
                    ServiceClass::Liveness => heads.liveness = Some(candidate),
                    ServiceClass::AuthorityControl => heads.authority_control = Some(candidate),
                    ServiceClass::Interactive => heads.interactive = Some(candidate),
                    ServiceClass::Work => heads.work = Some(candidate),
                    ServiceClass::Background => heads.background = Some(candidate),
                }
            }
        }
    }
    heads
}

fn status_locked<T>(
    state: &QueueManagerState<T>,
    partition_index: usize,
    observed_at: TimestampMicros,
) -> Result<QueueStatus, QueueRuntimeError> {
    let global_depth = u16::try_from(state.total_depths().total()).unwrap_or(u16::MAX);
    let active_worker = state.active_worker
        && (state.inflight_partition == Some(partition_index)
            || state.partitions[partition_index].attribution == QueueAttribution::Global);
    let mut status = state.partitions[partition_index].state.status(
        observed_at,
        active_worker,
        global_depth,
        state.global_rejected_count,
        state.global_high_water,
    )?;
    if state.partitions[partition_index].attribution == QueueAttribution::Global {
        status.aging_count = state.global_aging_count;
    }
    Ok(status)
}

fn dequeue_locked<T>(
    state: &mut QueueManagerState<T>,
    observed_at: TimestampMicros,
) -> Result<QueueDequeue<T>, QueueRuntimeError> {
    if state.total_depths().total() == 0 {
        return if state.closed {
            Ok(QueueDequeue::Closed)
        } else {
            Ok(QueueDequeue::Empty)
        };
    }
    let decision = evaluate_queue_dispatch(
        QUEUE_OPERATION,
        QueueDispatchInput {
            heads: aggregate_heads(state),
            observed_at,
            schedule_cursor: state.schedule_cursor,
            dispatch_count: state.dispatch_count,
        },
    )
    .map_err(|error| QueueRuntimeError::Policy(error.code))?;
    let QueueDispatchOutcome::Selected { class } = decision.outcome else {
        return Err(QueueRuntimeError::Policy(
            heterarchy_orchestration_policy::ErrorCode::QueueInvalidSnapshot,
        ));
    };
    let class_index = class_index(class);
    let partition_index = if decision.aging_activated {
        state
            .partitions
            .iter()
            .enumerate()
            .filter_map(|(index, partition)| {
                partition.state.heads().get(class).map(|head| (index, head))
            })
            .min_by_key(|(_, head)| head.0)
            .map(|(index, _)| index)
    } else {
        let start = state.bucket_cursors[class_index] % state.partitions.len();
        (0..state.partitions.len())
            .map(|offset| (start + offset) % state.partitions.len())
            .find(|index| state.partitions[*index].state.heads().get(class).is_some())
    }
    .ok_or(QueueRuntimeError::Policy(
        heterarchy_orchestration_policy::ErrorCode::QueueInvalidSnapshot,
    ))?;
    state.schedule_cursor = decision.next_schedule_cursor;
    state.dispatch_count = decision.next_dispatch_count;
    if !decision.aging_activated {
        state.bucket_cursors[class_index] = (partition_index + 1) % state.partitions.len();
    }
    if decision.aging_activated {
        state.global_aging_count = state
            .global_aging_count
            .checked_add(1)
            .ok_or(QueueRuntimeError::CounterOverflow)?;
        state.partitions[partition_index].state.aging_count = state.partitions[partition_index]
            .state
            .aging_count
            .checked_add(1)
            .ok_or(QueueRuntimeError::CounterOverflow)?;
    }
    let lane = &mut state.partitions[partition_index].state.lanes[class_index];
    let entry = lane.pop_front().ok_or(QueueRuntimeError::Policy(
        heterarchy_orchestration_policy::ErrorCode::QueueInvalidSnapshot,
    ))?;
    if lane.is_empty() {
        *lane = VecDeque::new();
    }
    state.inflight_partition = Some(partition_index);
    Ok(QueueDequeue::Item { item: entry.item })
}

const fn class_index(class: ServiceClass) -> usize {
    match class {
        ServiceClass::Liveness => 0,
        ServiceClass::AuthorityControl => 1,
        ServiceClass::Interactive => 2,
        ServiceClass::Work => 3,
        ServiceClass::Background => 4,
    }
}

#[cfg(test)]
mod measurements;

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier, mpsc};
    use std::thread;

    use uuid::Uuid;

    use super::*;

    fn at(value: u64) -> TimestampMicros {
        TimestampMicros(value)
    }

    fn queue_result<T, E: std::fmt::Debug>(
        result: Result<T, E>,
        operation: &str,
    ) -> Result<T, String> {
        result.map_err(|error| format!("{operation}: {error:?}"))
    }

    fn joined<T>(result: thread::Result<T>, operation: &str) -> Result<T, String> {
        result.map_err(|_| operation.to_owned())
    }

    fn workspace(value: u128) -> WorkspaceId {
        WorkspaceId::from_uuid(Uuid::from_u128(value))
    }

    #[test]
    fn liveness_reservation_survives_noncritical_saturation() {
        let queue = QueueMailbox::<u64>::new();
        for index in 0..240 {
            assert!(
                queue
                    .try_enqueue(ServiceClass::Work, index, at(index))
                    .is_ok()
            );
        }
        for index in 240..248 {
            assert!(
                queue
                    .try_enqueue(ServiceClass::Background, index, at(index))
                    .is_ok()
            );
        }
        assert!(
            queue
                .try_enqueue(ServiceClass::Liveness, 248, at(248))
                .is_ok()
        );
        assert!(
            queue
                .try_enqueue(ServiceClass::AuthorityControl, 249, at(249))
                .is_ok()
        );
        assert!(matches!(
            queue.try_enqueue(ServiceClass::Work, 250, at(250)),
            Err(QueueEnqueueError::Rejected)
        ));
    }

    #[test]
    fn downsize_preserves_fifo_entries_and_drains_above_target() -> Result<(), String> {
        let queue = QueueMailbox::new();
        for index in 0..40 {
            assert!(
                queue
                    .try_enqueue(ServiceClass::Work, index, at(index))
                    .is_ok()
            );
        }
        let status = queue_result(
            queue.apply_capacity(QueueCapacity::C32, 0),
            "resize should capture the old depth",
        )?;
        assert!(status.draining());
        assert_eq!(status.depths().work, 40);
        assert!(matches!(
            queue.try_enqueue(ServiceClass::Background, 40, at(40)),
            Err(QueueEnqueueError::Rejected)
        ));
        for expected in 0..40 {
            let item = queue_result(queue.try_dequeue(at(1_000)), "dequeue")?;
            assert!(matches!(
                item,
                QueueDequeue::Item { item: value } if value == expected
            ));
        }
        Ok(())
    }

    #[test]
    fn shutdown_closes_admission_but_drains_admitted_items() -> Result<(), String> {
        let queue = QueueMailbox::new();
        assert!(queue.try_enqueue(ServiceClass::Liveness, 1, at(0)).is_ok());
        assert!(queue.close().is_ok());
        assert!(matches!(
            queue.try_enqueue(ServiceClass::Work, 2, at(1)),
            Err(QueueEnqueueError::Closed)
        ));
        assert!(matches!(
            queue_result(queue.try_dequeue(at(10)), "drain admitted item")?,
            QueueDequeue::Item { item: 1 }
        ));
        assert!(matches!(
            queue_result(queue.try_dequeue(at(10)), "closed queue")?,
            QueueDequeue::Closed
        ));
        Ok(())
    }

    #[test]
    fn stale_resize_revision_is_typed_and_non_mutating() -> Result<(), String> {
        let queue = QueueMailbox::<u8>::new();
        let Err(stale) = queue.apply_capacity(QueueCapacity::C64, 1) else {
            return Err("revision one unexpectedly succeeded".to_owned());
        };
        assert_eq!(
            stale,
            QueueConfigError::StaleRevision {
                expected: 1,
                actual: 0
            }
        );
        assert_eq!(
            queue_result(queue.status(at(0)), "status")?.target_capacity(),
            QueueCapacity::C256
        );
        Ok(())
    }

    #[test]
    fn aging_and_weighted_dispatch_metrics_are_observable() -> Result<(), String> {
        let queue = QueueMailbox::new();
        assert!(
            queue
                .try_enqueue(ServiceClass::Background, 1, at(0))
                .is_ok()
        );
        assert!(queue.try_enqueue(ServiceClass::Liveness, 2, at(1)).is_ok());
        assert!(
            queue
                .try_enqueue(ServiceClass::Interactive, 3, at(2))
                .is_ok()
        );
        let mut state = queue_result(queue.inner.state.lock(), "queue state")?;
        state.dispatch_count = 3;
        drop(state);
        let first = queue_result(queue.try_dequeue(at(1_000_001)), "dispatch")?;
        assert!(matches!(first, QueueDequeue::Item { item: 1 }));
        let status = queue_result(queue.status(at(1_000_001)), "status")?;
        assert_eq!(status.aging_count(), 1);
        assert!(status.oldest_age_micros().iter().any(Option::is_some));
        Ok(())
    }

    #[test]
    fn sustained_class_heads_follow_bounded_weighted_service() -> Result<(), String> {
        let queue = QueueMailbox::new();
        for class in ServiceClass::ORDER {
            assert!(queue.try_enqueue(class, class, at(10)).is_ok());
        }
        let mut counts = [0_u8; 5];
        for _ in 0..19 {
            let item = queue_result(queue.try_dequeue(at(10)), "dispatch")?;
            let QueueDequeue::Item { item: class } = item else {
                return Err("continuous workload unexpectedly became empty".to_owned());
            };
            counts[class_index(class)] += 1;
            assert!(queue.try_enqueue(class, class, at(10)).is_ok());
        }
        assert_eq!(counts, [8, 4, 4, 2, 1]);
        Ok(())
    }

    #[test]
    fn waiting_dispatch_resamples_after_a_later_timestamp_wakes_it() -> Result<(), String> {
        let queue = QueueMailbox::new();
        let barrier = Arc::new(Barrier::new(2));
        let (ready_sender, ready_receiver) = mpsc::sync_channel(0);
        let worker_queue = queue.clone();
        let worker_barrier = Arc::clone(&barrier);
        let worker = thread::spawn(move || -> Result<u8, String> {
            ready_sender
                .send(())
                .map_err(|_| "test worker ready send failed".to_owned())?;
            worker_barrier.wait();
            let first = queue_result(
                worker_queue.wait_dequeue(at(1)),
                "initial wait should not fail",
            )?;
            match first {
                QueueDequeue::Item { item } => Ok(item),
                QueueDequeue::Empty => {
                    let result = queue_result(
                        worker_queue.try_dequeue(at(10)),
                        "resampled dispatch should not fail",
                    )?;
                    match result {
                        QueueDequeue::Item { item } => Ok(item),
                        QueueDequeue::Empty => Err("queue remained empty after wake".to_owned()),
                        QueueDequeue::Closed => Err("queue closed after wake".to_owned()),
                    }
                }
                QueueDequeue::Closed => Err("queue closed before wake".to_owned()),
            }
        });
        ready_receiver
            .recv()
            .map_err(|_| "worker reached barrier".to_owned())?;
        barrier.wait();
        assert!(
            queue
                .try_enqueue(ServiceClass::Liveness, 42_u8, at(10))
                .is_ok()
        );
        let result = joined(worker.join(), "worker joined")??;
        assert_eq!(result, 42);
        Ok(())
    }

    #[test]
    fn poisoned_close_notifies_waiters_and_fails_closed() -> Result<(), String> {
        let queue = QueueMailbox::<u8>::new();
        let barrier = Arc::new(Barrier::new(2));
        let waiter_queue = queue.clone();
        let waiter_barrier = Arc::clone(&barrier);
        let waiter = thread::spawn(move || waiter_queue.wait_dequeue_poison_probe(&waiter_barrier));
        barrier.wait();

        let poison_queue = queue.clone();
        let poisoner = thread::spawn(move || {
            let Ok(_guard) = poison_queue.inner.state.lock() else {
                return;
            };
            std::panic::resume_unwind(Box::new("intentional queue poison"));
        });
        assert!(poisoner.join().is_err());
        assert_eq!(queue.close(), Err(QueueRuntimeError::Poisoned));
        assert!(matches!(
            joined(waiter.join(), "poison waiter joined")?,
            Err(QueueRuntimeError::Poisoned)
        ));
        Ok(())
    }

    #[test]
    fn uninitialized_workspace_is_conservatively_bounded_until_preference_install()
    -> Result<(), String> {
        let queue = QueueMailbox::new();
        let id = workspace(1);
        let status = queue_result(
            queue.status_for(QueueAttribution::Workspace(id), at(0)),
            "initial workspace status",
        )?;
        assert_eq!(status.target_capacity(), QueueCapacity::C32);
        assert!(!status.initialized());
        for index in 0..24 {
            assert!(
                queue
                    .try_enqueue_attribution(
                        QueueAttribution::Workspace(id),
                        ServiceClass::Work,
                        index,
                        at(index),
                    )
                    .is_ok()
            );
        }
        assert!(matches!(
            queue.try_enqueue_attribution(
                QueueAttribution::Workspace(id),
                ServiceClass::Work,
                24,
                at(24),
            ),
            Err(QueueEnqueueError::Rejected)
        ));
        let installed = queue_result(
            queue.install_workspace_preference(id, Some((QueueCapacity::C64, 7))),
            "install workspace preference",
        )?;
        assert_eq!(installed.target_capacity(), QueueCapacity::C64);
        assert!(installed.initialized());
        assert_eq!(installed.source(), QueueCapacitySource::UserProvided);
        assert_eq!(installed.depths().work, 24);
        assert!(matches!(
            queue.install_workspace_preference(id, Some((QueueCapacity::C32, 7))),
            Err(QueueConfigError::PersistedPreferenceConflict)
        ));
        assert!(matches!(
            queue.install_workspace_preference(id, None),
            Err(QueueConfigError::PersistedPreferenceConflict)
        ));
        Ok(())
    }

    #[test]
    fn global_c256_preserves_four_plus_four_critical_reservations() -> Result<(), String> {
        let queue = QueueMailbox::<u16>::new();
        for index in 0..240_u16 {
            queue_result(
                queue.try_enqueue(ServiceClass::Work, index, at(u64::from(index))),
                "global work enqueue",
            )?;
        }
        for index in 240..248_u16 {
            queue_result(
                queue.try_enqueue(ServiceClass::Background, index, at(u64::from(index))),
                "global background enqueue",
            )?;
        }
        for index in 0..4_u16 {
            queue_result(
                queue.try_enqueue(
                    ServiceClass::AuthorityControl,
                    index,
                    at(300 + u64::from(index)),
                ),
                "global authority enqueue",
            )?;
        }
        for index in 0..4_u16 {
            queue_result(
                queue.try_enqueue(ServiceClass::Liveness, index, at(400 + u64::from(index))),
                "global liveness enqueue",
            )?;
        }
        let status = queue_result(queue.status(at(1_000)), "global status")?;
        assert_eq!(status.target_capacity(), QueueCapacity::C256);
        assert_eq!(status.global_depth(), 256);
        assert!(matches!(
            queue.try_enqueue(ServiceClass::Work, 999, at(2_000)),
            Err(QueueEnqueueError::Rejected)
        ));
        Ok(())
    }

    #[test]
    fn location_bucket_is_fixed_c32_and_initialized_without_workspace_preference()
    -> Result<(), String> {
        let queue = QueueMailbox::<u8>::new();
        let location = LocationId::from_uuid(Uuid::from_u128(88));
        let status = queue_result(
            queue.status_for(QueueAttribution::Location(location), at(0)),
            "location status",
        )?;
        assert_eq!(status.target_capacity(), QueueCapacity::C32);
        assert!(status.initialized());
        assert_eq!(status.source(), QueueCapacitySource::Default);
        Ok(())
    }

    #[test]
    fn workspaces_have_independent_caps_but_share_the_global_hard_bound() -> Result<(), String> {
        let queue = QueueMailbox::new();
        let first = workspace(2);
        let second = workspace(3);
        queue_result(
            queue.apply_workspace_capacity(first, QueueCapacity::C256, 0),
            "first capacity",
        )?;
        queue_result(
            queue.apply_workspace_capacity(second, QueueCapacity::C256, 0),
            "second capacity",
        )?;
        for index in 0..124 {
            assert!(
                queue
                    .try_enqueue_attribution(
                        QueueAttribution::Workspace(first),
                        ServiceClass::Work,
                        index,
                        at(index),
                    )
                    .is_ok()
            );
            assert!(
                queue
                    .try_enqueue_attribution(
                        QueueAttribution::Workspace(second),
                        ServiceClass::Work,
                        index,
                        at(index),
                    )
                    .is_ok()
            );
        }
        assert_eq!(
            queue_result(
                queue.status_for(QueueAttribution::Workspace(first), at(1_000)),
                "first status",
            )?
            .global_depth(),
            248
        );
        assert!(matches!(
            queue.try_enqueue_attribution(
                QueueAttribution::Workspace(first),
                ServiceClass::Work,
                124,
                at(124),
            ),
            Err(QueueEnqueueError::Rejected)
        ));
        assert_eq!(
            queue_result(
                queue.status_for(QueueAttribution::Workspace(second), at(1_000)),
                "second status",
            )?
            .depths()
            .work,
            124
        );
        Ok(())
    }

    #[test]
    fn same_class_workspace_buckets_round_robin_and_preserve_fifo() -> Result<(), String> {
        let queue = QueueMailbox::new();
        let first = workspace(4);
        let second = workspace(5);
        queue_result(
            queue.apply_workspace_capacity(first, QueueCapacity::C32, 0),
            "first capacity",
        )?;
        queue_result(
            queue.apply_workspace_capacity(second, QueueCapacity::C32, 0),
            "second capacity",
        )?;
        for index in 0..3 {
            queue_result(
                queue.try_enqueue_attribution(
                    QueueAttribution::Workspace(first),
                    ServiceClass::Liveness,
                    (first, index),
                    at(index),
                ),
                "first enqueue",
            )?;
            queue_result(
                queue.try_enqueue_attribution(
                    QueueAttribution::Workspace(second),
                    ServiceClass::Liveness,
                    (second, index),
                    at(index),
                ),
                "second enqueue",
            )?;
        }
        for index in 0..3 {
            let first_item = queue_result(queue.try_dequeue(at(100)), "first dequeue")?;
            let second_item = queue_result(queue.try_dequeue(at(100)), "second dequeue")?;
            assert!(
                matches!(first_item, QueueDequeue::Item { item: (id, value) } if id == first && value == index)
            );
            assert!(
                matches!(second_item, QueueDequeue::Item { item: (id, value) } if id == second && value == index)
            );
        }
        Ok(())
    }

    #[test]
    fn global_and_location_buckets_are_explicitly_separate() -> Result<(), String> {
        let queue = QueueMailbox::new();
        let location = LocationId::from_uuid(Uuid::from_u128(77));
        queue_result(
            queue.try_enqueue_attribution(
                QueueAttribution::Global,
                ServiceClass::Interactive,
                1_u8,
                at(1),
            ),
            "global enqueue",
        )?;
        queue_result(
            queue.try_enqueue_attribution(
                QueueAttribution::Location(location),
                ServiceClass::Interactive,
                2_u8,
                at(2),
            ),
            "location enqueue",
        )?;
        assert!(matches!(
            queue_result(queue.try_dequeue(at(100)), "global dequeue")?,
            QueueDequeue::Item { item: 1 }
        ));
        assert!(matches!(
            queue_result(queue.try_dequeue(at(100)), "location dequeue")?,
            QueueDequeue::Item { item: 2 }
        ));
        Ok(())
    }

    #[test]
    fn sixty_four_partition_interleaving_and_swap_remove_remap_are_bounded() -> Result<(), String> {
        let queue = QueueMailbox::<(WorkspaceId, u8)>::new();
        for value in 0..60_u128 {
            let id = workspace(10_000 + value);
            let timestamp = u64::try_from(value).map_err(|_| "timestamp overflow".to_owned())?;
            queue_result(
                queue.apply_workspace_capacity(id, QueueCapacity::C32, 0),
                "partition capacity",
            )?;
            queue_result(
                queue.try_enqueue_attribution(
                    QueueAttribution::Workspace(id),
                    ServiceClass::Interactive,
                    (
                        id,
                        u8::try_from(value).map_err(|_| "value overflow".to_owned())?,
                    ),
                    at(timestamp),
                ),
                "partition enqueue",
            )?;
        }
        let uninitialized_a = workspace(20_000);
        let uninitialized_b = workspace(20_001);
        let uninitialized_c = workspace(20_002);
        queue_result(
            queue.status_for(QueueAttribution::Workspace(uninitialized_a), at(0)),
            "uninitialized partition A",
        )?;
        queue_result(
            queue.status_for(QueueAttribution::Workspace(uninitialized_b), at(0)),
            "uninitialized partition B",
        )?;
        queue_result(
            queue.status_for(QueueAttribution::Workspace(uninitialized_c), at(0)),
            "uninitialized partition C",
        )?;

        {
            let mut state = queue_result(queue.inner.state.lock(), "queue manager state")?;
            assert_eq!(state.partitions.len(), MAX_QUEUE_PARTITIONS);
            state.inflight_partition = Some(MAX_QUEUE_PARTITIONS - 1);
            state.bucket_cursors[class_index(ServiceClass::Interactive)] = MAX_QUEUE_PARTITIONS - 1;
        }
        let replacement = workspace(20_003);
        let replacement_status = queue_result(
            queue.status_for(QueueAttribution::Workspace(replacement), at(0)),
            "replacement status",
        )?;
        assert!(!replacement_status.initialized());
        {
            let state = queue_result(queue.inner.state.lock(), "queue manager state")?;
            assert!(
                state
                    .inflight_partition
                    .is_some_and(|index| index < state.partitions.len())
            );
            assert!(
                state.bucket_cursors[class_index(ServiceClass::Interactive)]
                    < state.partitions.len()
            );
        }

        let mut observed = Vec::new();
        for _ in 0..60 {
            let QueueDequeue::Item { item: (_, value) } =
                queue_result(queue.try_dequeue(at(10_000)), "partition dequeue")?
            else {
                return Err("partition queue became empty".to_owned());
            };
            observed.push(value);
        }
        observed.sort_unstable();
        assert_eq!(observed, (0_u8..60).collect::<Vec<_>>());
        Ok(())
    }

    #[test]
    fn workspace_downsize_drains_without_dropping_admitted_items() -> Result<(), String> {
        let queue = QueueMailbox::new();
        let id = workspace(6);
        queue_result(
            queue.apply_workspace_capacity(id, QueueCapacity::C64, 0),
            "initial capacity",
        )?;
        for index in 0..40 {
            queue_result(
                queue.try_enqueue_attribution(
                    QueueAttribution::Workspace(id),
                    ServiceClass::Work,
                    index,
                    at(index),
                ),
                "enqueue",
            )?;
        }
        let status = queue_result(
            queue.apply_workspace_capacity(id, QueueCapacity::C32, 1),
            "downsize",
        )?;
        assert!(status.draining());
        assert_eq!(status.depths().work, 40);
        for expected in 0..40 {
            assert!(matches!(
                queue_result(queue.try_dequeue(at(1_000)), "dequeue")?,
                QueueDequeue::Item { item } if item == expected
            ));
        }
        assert!(matches!(
            queue_result(queue.try_dequeue(at(1_000)), "empty dequeue")?,
            QueueDequeue::Empty
        ));
        Ok(())
    }

    #[test]
    fn partition_limit_rejects_without_unbounded_scope_allocation() {
        let queue = QueueMailbox::<u8>::new();
        for value in 0..63_u128 {
            assert!(
                queue
                    .apply_workspace_capacity(workspace(100 + value), QueueCapacity::C32, 0)
                    .is_ok()
            );
        }
        assert!(matches!(
            queue.status_for(QueueAttribution::Workspace(workspace(999)), at(0)),
            Err(QueueRuntimeError::PartitionLimit)
        ));
    }
}
