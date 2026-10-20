//! Deterministic bounded queue admission and dispatch policy.
//!
//! The policy owns neither requests nor queue storage. The owning adapter
//! retains the five FIFO lanes, request classification, enqueue/dequeue
//! effects, and the monotonic observation clock. This module receives only
//! bounded counts and class-head timestamps, then returns typed decisions.

use serde::{Deserialize, Serialize};

use crate::{DomainError, ErrorCode, TimestampMicros};

/// The closed set of queue lanes owned by the Orchestration policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceClass {
    Liveness,
    AuthorityControl,
    Interactive,
    Work,
    Background,
}

impl ServiceClass {
    /// Fixed class order used for schedule ties and deterministic scans.
    pub const ORDER: [Self; 5] = [
        Self::Liveness,
        Self::AuthorityControl,
        Self::Interactive,
        Self::Work,
        Self::Background,
    ];

    #[must_use]
    pub const fn is_critical(self) -> bool {
        matches!(self, Self::Liveness | Self::AuthorityControl)
    }

    #[must_use]
    pub const fn weight(self) -> u8 {
        match self {
            Self::Liveness => 8,
            Self::AuthorityControl | Self::Interactive => 4,
            Self::Work => 2,
            Self::Background => 1,
        }
    }
}

/// Supported queue capacity presets. The default is `C128`.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueCapacity {
    C32,
    C64,
    #[default]
    C128,
    C256,
}

impl QueueCapacity {
    pub const ALL: [Self; 4] = [Self::C32, Self::C64, Self::C128, Self::C256];

    #[must_use]
    pub const fn slots(self) -> u16 {
        match self {
            Self::C32 => 32,
            Self::C64 => 64,
            Self::C128 => 128,
            Self::C256 => 256,
        }
    }
}

pub const DEFAULT_QUEUE_CAPACITY: QueueCapacity = QueueCapacity::C128;
pub const MAX_PHYSICAL_QUEUE_DEPTH: u16 = 256;
pub const LIVENESS_RESERVED_SLOTS: u16 = 4;
pub const AUTHORITY_CONTROL_RESERVED_SLOTS: u16 = 4;
pub const NONCRITICAL_RESERVED_SLOTS: u16 =
    LIVENESS_RESERVED_SLOTS + AUTHORITY_CONTROL_RESERVED_SLOTS;
pub const AGING_THRESHOLD_MICROS: u64 = 1_000_000;
pub const WEIGHTED_ROUND_ROBIN_SCHEDULE: [ServiceClass; 19] = [
    ServiceClass::Liveness,
    ServiceClass::AuthorityControl,
    ServiceClass::Interactive,
    ServiceClass::Liveness,
    ServiceClass::Work,
    ServiceClass::Liveness,
    ServiceClass::AuthorityControl,
    ServiceClass::Interactive,
    ServiceClass::Liveness,
    ServiceClass::Background,
    ServiceClass::Liveness,
    ServiceClass::AuthorityControl,
    ServiceClass::Interactive,
    ServiceClass::Liveness,
    ServiceClass::Work,
    ServiceClass::Liveness,
    ServiceClass::AuthorityControl,
    ServiceClass::Interactive,
    ServiceClass::Liveness,
];

/// Explicit per-class queue depths observed by the owning queue adapter.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueueDepths {
    pub liveness: u16,
    pub authority_control: u16,
    pub interactive: u16,
    pub work: u16,
    pub background: u16,
}

impl QueueDepths {
    #[must_use]
    pub const fn new(
        liveness: u16,
        authority_control: u16,
        interactive: u16,
        work: u16,
        background: u16,
    ) -> Self {
        Self {
            liveness,
            authority_control,
            interactive,
            work,
            background,
        }
    }

    #[must_use]
    pub const fn get(self, class: ServiceClass) -> u16 {
        match class {
            ServiceClass::Liveness => self.liveness,
            ServiceClass::AuthorityControl => self.authority_control,
            ServiceClass::Interactive => self.interactive,
            ServiceClass::Work => self.work,
            ServiceClass::Background => self.background,
        }
    }

    #[must_use]
    pub const fn total(self) -> u32 {
        self.liveness as u32
            + self.authority_control as u32
            + self.interactive as u32
            + self.work as u32
            + self.background as u32
    }
}

/// Admission state supplied for one bounded decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueueAdmissionInput {
    pub depths: QueueDepths,
    pub target_capacity: QueueCapacity,
    /// A captured upper bound for an in-progress downsize. When no downsize
    /// is active, this should equal the target capacity.
    pub draining_ceiling: u16,
}

impl QueueAdmissionInput {
    #[must_use]
    pub const fn new(
        depths: QueueDepths,
        target_capacity: QueueCapacity,
        draining_ceiling: u16,
    ) -> Self {
        Self {
            depths,
            target_capacity,
            draining_ceiling,
        }
    }
}

/// Capture the bounded ceiling that preserves admitted work during a resize.
///
/// # Errors
///
/// Returns a typed error when the observed depth exceeds the physical bound.
pub fn capture_draining_ceiling(
    operation: &str,
    target_capacity: QueueCapacity,
    depths: QueueDepths,
) -> Result<QueueAdmissionInput, DomainError> {
    let total = validate_depths(operation, depths)?;
    let target = u32::from(target_capacity.slots());
    let ceiling = total.max(target);
    let draining_ceiling = u16::try_from(ceiling).map_err(|_| {
        queue_error(
            ErrorCode::QueueArithmeticOverflow,
            operation,
            "draining_ceiling",
            "Queue draining ceiling exceeded the representable bound.",
        )
    })?;
    Ok(QueueAdmissionInput::new(
        depths,
        target_capacity,
        draining_ceiling,
    ))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueAdmissionRejection {
    CapacityFull,
    ReservedCapacity,
    DrainingNonCritical,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum QueueAdmissionOutcome {
    Admitted,
    Rejected { reason: QueueAdmissionRejection },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueueAdmissionDecision {
    pub class: ServiceClass,
    pub outcome: QueueAdmissionOutcome,
    pub effective_limit: u16,
    pub total_depth: u16,
    pub draining: bool,
}

impl QueueAdmissionDecision {
    #[must_use]
    pub const fn admitted(self) -> bool {
        matches!(self.outcome, QueueAdmissionOutcome::Admitted)
    }
}

/// Evaluate whether one class may reserve one additional queue slot.
///
/// # Errors
///
/// Returns a typed error when the supplied queue snapshot is invalid.
pub fn evaluate_queue_admission(
    operation: &str,
    class: ServiceClass,
    input: QueueAdmissionInput,
) -> Result<QueueAdmissionDecision, DomainError> {
    let total = validate_admission_input(operation, input)?;
    let target = input.target_capacity.slots();
    let ceiling = input.draining_ceiling;
    let draining = total > u32::from(target);
    let effective_limit = match class {
        ServiceClass::Liveness => {
            if draining {
                ceiling
            } else {
                target
            }
        }
        ServiceClass::AuthorityControl => {
            if draining {
                ceiling - AUTHORITY_CONTROL_RESERVED_SLOTS
            } else {
                target - AUTHORITY_CONTROL_RESERVED_SLOTS
            }
        }
        ServiceClass::Interactive | ServiceClass::Work | ServiceClass::Background => {
            target - NONCRITICAL_RESERVED_SLOTS
        }
    };
    let total_depth = u16::try_from(total).map_err(|_| {
        queue_error(
            ErrorCode::QueueArithmeticOverflow,
            operation,
            "depths",
            "Queue depth could not be represented as a bounded count.",
        )
    })?;
    let outcome = if total < u32::from(effective_limit) {
        QueueAdmissionOutcome::Admitted
    } else {
        let reason = if total >= u32::from(MAX_PHYSICAL_QUEUE_DEPTH)
            || (class.is_critical() && total >= u32::from(ceiling))
        {
            QueueAdmissionRejection::CapacityFull
        } else if draining && !class.is_critical() && total >= u32::from(target) {
            QueueAdmissionRejection::DrainingNonCritical
        } else {
            QueueAdmissionRejection::ReservedCapacity
        };
        QueueAdmissionOutcome::Rejected { reason }
    };
    Ok(QueueAdmissionDecision {
        class,
        outcome,
        effective_limit,
        total_depth,
        draining,
    })
}

/// One class-head observation. Forge retains the actual FIFO request.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueueHeads {
    pub liveness: Option<TimestampMicros>,
    pub authority_control: Option<TimestampMicros>,
    pub interactive: Option<TimestampMicros>,
    pub work: Option<TimestampMicros>,
    pub background: Option<TimestampMicros>,
}

impl QueueHeads {
    #[must_use]
    pub const fn new(
        liveness: Option<TimestampMicros>,
        authority_control: Option<TimestampMicros>,
        interactive: Option<TimestampMicros>,
        work: Option<TimestampMicros>,
        background: Option<TimestampMicros>,
    ) -> Self {
        Self {
            liveness,
            authority_control,
            interactive,
            work,
            background,
        }
    }

    #[must_use]
    pub const fn get(self, class: ServiceClass) -> Option<TimestampMicros> {
        match class {
            ServiceClass::Liveness => self.liveness,
            ServiceClass::AuthorityControl => self.authority_control,
            ServiceClass::Interactive => self.interactive,
            ServiceClass::Work => self.work,
            ServiceClass::Background => self.background,
        }
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.liveness.is_none()
            && self.authority_control.is_none()
            && self.interactive.is_none()
            && self.work.is_none()
            && self.background.is_none()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueueDispatchInput {
    pub heads: QueueHeads,
    pub observed_at: TimestampMicros,
    /// Current slot in the fixed 19-slot weighted schedule.
    pub schedule_cursor: u8,
    /// Number of successful dispatches before this decision. The fourth,
    /// eighth, and subsequent fourth dispatches are aging opportunities.
    pub dispatch_count: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum QueueDispatchOutcome {
    Empty,
    Selected { class: ServiceClass },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueueDispatchDecision {
    pub outcome: QueueDispatchOutcome,
    pub aging_activated: bool,
    pub next_schedule_cursor: u8,
    pub next_dispatch_count: u64,
}

impl QueueDispatchDecision {
    #[must_use]
    pub const fn selected_class(self) -> Option<ServiceClass> {
        match self.outcome {
            QueueDispatchOutcome::Empty => None,
            QueueDispatchOutcome::Selected { class } => Some(class),
        }
    }
}

/// Select one class head using bounded weighted round robin and explicit aging.
///
/// # Errors
///
/// Returns a typed error for future-dated heads, an invalid schedule cursor,
/// or dispatch-counter overflow.
pub fn evaluate_queue_dispatch(
    operation: &str,
    input: QueueDispatchInput,
) -> Result<QueueDispatchDecision, DomainError> {
    validate_heads(operation, input.heads, input.observed_at)?;
    if usize::from(input.schedule_cursor) >= WEIGHTED_ROUND_ROBIN_SCHEDULE.len() {
        return Err(queue_error(
            ErrorCode::QueueInvalidSnapshot,
            operation,
            "schedule_cursor",
            "Weighted schedule cursor is outside the fixed schedule.",
        ));
    }
    if input.heads.is_empty() {
        return Ok(QueueDispatchDecision {
            outcome: QueueDispatchOutcome::Empty,
            aging_activated: false,
            next_schedule_cursor: input.schedule_cursor,
            next_dispatch_count: input.dispatch_count,
        });
    }

    let next_dispatch_count = input.dispatch_count.checked_add(1).ok_or_else(|| {
        queue_error(
            ErrorCode::QueueArithmeticOverflow,
            operation,
            "dispatch_count",
            "Queue dispatch counter overflowed.",
        )
    })?;
    let aging_turn = next_dispatch_count % 4 == 0;
    if aging_turn && let Some(class) = oldest_aged_class(input.heads, input.observed_at) {
        return Ok(QueueDispatchDecision {
            outcome: QueueDispatchOutcome::Selected { class },
            aging_activated: true,
            next_schedule_cursor: input.schedule_cursor,
            next_dispatch_count,
        });
    }

    let schedule_start = usize::from(input.schedule_cursor);
    for offset in 0..WEIGHTED_ROUND_ROBIN_SCHEDULE.len() {
        let index = (schedule_start + offset) % WEIGHTED_ROUND_ROBIN_SCHEDULE.len();
        let class = WEIGHTED_ROUND_ROBIN_SCHEDULE[index];
        if input.heads.get(class).is_some() {
            return Ok(QueueDispatchDecision {
                outcome: QueueDispatchOutcome::Selected { class },
                aging_activated: false,
                next_schedule_cursor: u8::try_from(
                    (index + 1) % WEIGHTED_ROUND_ROBIN_SCHEDULE.len(),
                )
                .unwrap_or(0),
                next_dispatch_count,
            });
        }
    }

    Err(queue_error(
        ErrorCode::QueueInvalidSnapshot,
        operation,
        "heads",
        "Queue heads were non-empty but no weighted schedule class was available.",
    ))
}

fn oldest_aged_class(heads: QueueHeads, observed_at: TimestampMicros) -> Option<ServiceClass> {
    let mut oldest: Option<(ServiceClass, TimestampMicros)> = None;
    for class in ServiceClass::ORDER {
        let Some(enqueued_at) = heads.get(class) else {
            continue;
        };
        if observed_at.0 - enqueued_at.0 < AGING_THRESHOLD_MICROS {
            continue;
        }
        let is_older = match oldest {
            None => true,
            Some((_, oldest_at)) => enqueued_at.0 < oldest_at.0,
        };
        if is_older {
            oldest = Some((class, enqueued_at));
        }
    }
    oldest.map(|(class, _)| class)
}

fn validate_admission_input(
    operation: &str,
    input: QueueAdmissionInput,
) -> Result<u32, DomainError> {
    let total = validate_depths(operation, input.depths)?;
    let target = u32::from(input.target_capacity.slots());
    let ceiling = u32::from(input.draining_ceiling);
    if ceiling > u32::from(MAX_PHYSICAL_QUEUE_DEPTH) || ceiling < target || ceiling < total {
        return Err(queue_error(
            ErrorCode::QueueInvalidSnapshot,
            operation,
            "draining_ceiling",
            "Queue draining ceiling must cover the target and observed depth within the physical bound.",
        ));
    }
    Ok(total)
}

fn validate_depths(operation: &str, depths: QueueDepths) -> Result<u32, DomainError> {
    let total = depths.total();
    if total > u32::from(MAX_PHYSICAL_QUEUE_DEPTH) {
        return Err(queue_error(
            ErrorCode::QueueInvalidSnapshot,
            operation,
            "depths",
            "Queue depth exceeds the physical maximum.",
        ));
    }
    Ok(total)
}

fn validate_heads(
    operation: &str,
    heads: QueueHeads,
    observed_at: TimestampMicros,
) -> Result<(), DomainError> {
    for class in ServiceClass::ORDER {
        if let Some(enqueued_at) = heads.get(class)
            && enqueued_at.0 > observed_at.0
        {
            return Err(queue_error(
                ErrorCode::QueueInvalidSnapshot,
                operation,
                "heads",
                "Queue head timestamp is newer than the monotonic observation.",
            ));
        }
    }
    Ok(())
}

fn queue_error(code: ErrorCode, operation: &str, resource_id: &str, message: &str) -> DomainError {
    DomainError {
        code,
        operation: operation.to_owned(),
        resource_id: resource_id.to_owned(),
        message: message.to_owned(),
        current_revision: None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn class_index(class: ServiceClass) -> usize {
        ServiceClass::ORDER
            .iter()
            .position(|candidate| *candidate == class)
            .expect("class is in fixed order")
    }

    fn depths(total: u16) -> QueueDepths {
        QueueDepths::new(total, 0, 0, 0, 0)
    }

    fn admission(
        class: ServiceClass,
        target_capacity: QueueCapacity,
        depths: QueueDepths,
        draining_ceiling: u16,
    ) -> QueueAdmissionDecision {
        evaluate_queue_admission(
            "queue_test",
            class,
            QueueAdmissionInput::new(depths, target_capacity, draining_ceiling),
        )
        .expect("valid queue admission snapshot")
    }

    fn heads(all: Option<TimestampMicros>) -> QueueHeads {
        QueueHeads::new(all, all, all, all, all)
    }

    #[test]
    fn presets_are_closed_and_default_to_128() {
        assert_eq!(QueueCapacity::default(), QueueCapacity::C128);
        assert_eq!(
            QueueCapacity::ALL.map(QueueCapacity::slots),
            [32, 64, 128, 256]
        );
        assert_eq!(ServiceClass::Liveness.weight(), 8);
        assert_eq!(ServiceClass::AuthorityControl.weight(), 4);
        assert_eq!(ServiceClass::Interactive.weight(), 4);
        assert_eq!(ServiceClass::Work.weight(), 2);
        assert_eq!(ServiceClass::Background.weight(), 1);
    }

    #[test]
    fn normal_admission_reserves_authority_and_noncritical_slots() {
        for capacity in QueueCapacity::ALL {
            let slots = capacity.slots();
            assert!(
                admission(ServiceClass::Liveness, capacity, depths(slots - 1), slots).admitted()
            );
            assert!(!admission(ServiceClass::Liveness, capacity, depths(slots), slots).admitted());
            assert!(
                admission(
                    ServiceClass::AuthorityControl,
                    capacity,
                    depths(slots - AUTHORITY_CONTROL_RESERVED_SLOTS - 1),
                    slots,
                )
                .admitted()
            );
            assert!(
                !admission(
                    ServiceClass::AuthorityControl,
                    capacity,
                    depths(slots - AUTHORITY_CONTROL_RESERVED_SLOTS),
                    slots,
                )
                .admitted()
            );
            assert!(
                !admission(
                    ServiceClass::Background,
                    capacity,
                    depths(slots - NONCRITICAL_RESERVED_SLOTS),
                    slots,
                )
                .admitted()
            );
        }
    }

    #[test]
    fn downsizing_lets_only_critical_classes_use_the_captured_ceiling() {
        let input = capture_draining_ceiling("queue_test", QueueCapacity::C32, depths(40))
            .expect("valid downsize");
        assert_eq!(input.draining_ceiling, 40);
        let draining = QueueAdmissionInput::new(depths(33), QueueCapacity::C32, 40);
        assert!(
            evaluate_queue_admission("queue_test", ServiceClass::Liveness, draining)
                .expect("valid admission")
                .admitted()
        );
        assert!(
            evaluate_queue_admission("queue_test", ServiceClass::AuthorityControl, draining)
                .expect("valid admission")
                .admitted()
        );
        assert!(
            !evaluate_queue_admission("queue_test", ServiceClass::Background, draining)
                .expect("valid admission")
                .admitted()
        );
        assert!(!admission(ServiceClass::Liveness, QueueCapacity::C32, depths(40), 40,).admitted());
    }

    #[test]
    fn invalid_snapshots_fail_closed() {
        let too_deep = QueueAdmissionInput::new(depths(257), QueueCapacity::C256, 257);
        assert_eq!(
            evaluate_queue_admission("queue_test", ServiceClass::Liveness, too_deep)
                .expect_err("physical maximum must reject")
                .code,
            ErrorCode::QueueInvalidSnapshot
        );
        let below_observed = QueueAdmissionInput::new(depths(40), QueueCapacity::C32, 32);
        assert_eq!(
            evaluate_queue_admission("queue_test", ServiceClass::Liveness, below_observed)
                .expect_err("ceiling must cover depth")
                .code,
            ErrorCode::QueueInvalidSnapshot
        );
    }

    #[test]
    fn weighted_schedule_is_interleaved_and_exactly_weighted() {
        let mut counts = [0_u8; 5];
        for class in WEIGHTED_ROUND_ROBIN_SCHEDULE {
            counts[ServiceClass::ORDER
                .iter()
                .position(|candidate| *candidate == class)
                .expect("schedule class is in fixed order")] += 1;
        }
        assert_eq!(counts, [8, 4, 4, 2, 1]);
        let input = QueueDispatchInput {
            heads: heads(Some(TimestampMicros(0))),
            observed_at: TimestampMicros(1),
            schedule_cursor: 0,
            dispatch_count: 0,
        };
        for (index, expected) in WEIGHTED_ROUND_ROBIN_SCHEDULE.iter().enumerate() {
            let mut next = input;
            next.schedule_cursor = u8::try_from(index).expect("schedule index fits in cursor");
            assert_eq!(
                evaluate_queue_dispatch("queue_test", next)
                    .expect("weighted dispatch")
                    .selected_class(),
                Some(*expected)
            );
            assert_eq!(
                evaluate_queue_dispatch("queue_test", next)
                    .expect("weighted cursor")
                    .next_schedule_cursor,
                u8::try_from((index + 1) % WEIGHTED_ROUND_ROBIN_SCHEDULE.len())
                    .expect("schedule index fits in cursor")
            );
        }

        let mut dispatch = input;
        let mut dispatched_counts = [0_u8; 5];
        for _ in 0..WEIGHTED_ROUND_ROBIN_SCHEDULE.len() {
            let decision = evaluate_queue_dispatch("queue_test", dispatch)
                .expect("weighted dispatch sequence");
            let class = decision
                .selected_class()
                .expect("non-empty weighted dispatch sequence");
            dispatched_counts[class_index(class)] += 1;
            dispatch.schedule_cursor = decision.next_schedule_cursor;
            dispatch.dispatch_count = decision.next_dispatch_count;
        }
        assert_eq!(dispatched_counts, [8, 4, 4, 2, 1]);
    }

    #[test]
    fn sparse_lanes_preserve_weights_by_advancing_past_the_selected_slot() {
        let mut input = QueueDispatchInput {
            heads: QueueHeads::new(
                Some(TimestampMicros(0)),
                None,
                None,
                None,
                Some(TimestampMicros(0)),
            ),
            observed_at: TimestampMicros(1),
            schedule_cursor: 0,
            dispatch_count: 0,
        };
        let mut counts = [0_u8; 5];
        for _ in 0..9 {
            let decision = evaluate_queue_dispatch("queue_test", input).expect("sparse dispatch");
            let class = decision
                .selected_class()
                .expect("sparse heads should select a class");
            counts[class_index(class)] += 1;
            input.schedule_cursor = decision.next_schedule_cursor;
            input.dispatch_count = decision.next_dispatch_count;
        }
        assert_eq!(counts[class_index(ServiceClass::Liveness)], 8);
        assert_eq!(counts[class_index(ServiceClass::Background)], 1);
    }

    #[test]
    fn work_and_background_sparse_lanes_preserve_two_to_one_weight() {
        let mut input = QueueDispatchInput {
            heads: QueueHeads::new(
                None,
                None,
                None,
                Some(TimestampMicros(0)),
                Some(TimestampMicros(0)),
            ),
            observed_at: TimestampMicros(1),
            schedule_cursor: 0,
            dispatch_count: 0,
        };
        let mut work = 0;
        let mut background = 0;
        for _ in 0..3 {
            let decision = evaluate_queue_dispatch("queue_test", input).expect("sparse dispatch");
            let class = decision
                .selected_class()
                .expect("sparse heads should select a class");
            assert!(
                matches!(class, ServiceClass::Work | ServiceClass::Background),
                "unexpected sparse class {class:?}"
            );
            if class == ServiceClass::Work {
                work += 1;
            } else {
                background += 1;
            }
            input.schedule_cursor = decision.next_schedule_cursor;
            input.dispatch_count = decision.next_dispatch_count;
        }
        assert_eq!((work, background), (2, 1));
    }

    #[test]
    fn aging_runs_every_fourth_dispatch_and_ties_by_class_order() {
        let input = QueueDispatchInput {
            heads: QueueHeads::new(
                Some(TimestampMicros(0)),
                Some(TimestampMicros(0)),
                None,
                None,
                Some(TimestampMicros(1)),
            ),
            observed_at: TimestampMicros(AGING_THRESHOLD_MICROS + 1),
            schedule_cursor: 7,
            dispatch_count: 3,
        };
        let decision = evaluate_queue_dispatch("queue_test", input).expect("aging dispatch");
        assert_eq!(decision.selected_class(), Some(ServiceClass::Liveness));
        assert!(decision.aging_activated);
        assert_eq!(decision.next_schedule_cursor, 7);
        assert_eq!(decision.next_dispatch_count, 4);

        let background_oldest = QueueDispatchInput {
            heads: QueueHeads::new(
                Some(TimestampMicros(1)),
                Some(TimestampMicros(2)),
                None,
                None,
                Some(TimestampMicros(0)),
            ),
            observed_at: TimestampMicros(AGING_THRESHOLD_MICROS + 2),
            schedule_cursor: 0,
            dispatch_count: 7,
        };
        let decision = evaluate_queue_dispatch("queue_test", background_oldest)
            .expect("oldest aging dispatch");
        assert_eq!(decision.selected_class(), Some(ServiceClass::Background));
        assert!(decision.aging_activated);
    }

    #[test]
    fn dispatch_validates_monotonic_time_and_counter_overflow() {
        let future = QueueDispatchInput {
            heads: QueueHeads::new(Some(TimestampMicros(2)), None, None, None, None),
            observed_at: TimestampMicros(1),
            schedule_cursor: 0,
            dispatch_count: 0,
        };
        assert_eq!(
            evaluate_queue_dispatch("queue_test", future)
                .expect_err("future head must reject")
                .code,
            ErrorCode::QueueInvalidSnapshot
        );
        let invalid_cursor = QueueDispatchInput {
            heads: QueueHeads::new(Some(TimestampMicros(0)), None, None, None, None),
            observed_at: TimestampMicros(1),
            schedule_cursor: 19,
            dispatch_count: 0,
        };
        assert_eq!(
            evaluate_queue_dispatch("queue_test", invalid_cursor)
                .expect_err("cursor outside the fixed schedule must reject")
                .code,
            ErrorCode::QueueInvalidSnapshot
        );
        let overflow = QueueDispatchInput {
            heads: QueueHeads::new(Some(TimestampMicros(0)), None, None, None, None),
            observed_at: TimestampMicros(1),
            schedule_cursor: 0,
            dispatch_count: u64::MAX,
        };
        assert_eq!(
            evaluate_queue_dispatch("queue_test", overflow)
                .expect_err("counter overflow must reject")
                .code,
            ErrorCode::QueueArithmeticOverflow
        );
        let empty = evaluate_queue_dispatch(
            "queue_test",
            QueueDispatchInput {
                heads: QueueHeads::default(),
                observed_at: TimestampMicros(1),
                schedule_cursor: 0,
                dispatch_count: u64::MAX,
            },
        )
        .expect("empty queue is a valid no-work observation");
        assert_eq!(empty.outcome, QueueDispatchOutcome::Empty);
        assert_eq!(empty.next_dispatch_count, u64::MAX);
    }
}
