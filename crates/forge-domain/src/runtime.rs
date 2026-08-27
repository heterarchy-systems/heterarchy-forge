use thiserror::Error;

/// Monotonic generation assigned to a started runtime instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuntimeGeneration(u64);

impl RuntimeGeneration {
    pub const INITIAL: Self = Self(1);

    pub const fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> Result<Self, RuntimeTransitionError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(RuntimeTransitionError::GenerationOverflow)
    }
}

/// Commands accepted by the live runtime coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeCommand {
    Start,
    Stop,
    EmergencyStop,
    Restart,
    Shutdown,
}

/// Internal, deterministic lifecycle events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeEvent {
    BootCompleted,
    Tick,
    StartRequested,
    StartCompleted,
    StopRequested,
    EmergencyStopRequested,
    StopCompleted,
    RestartRequested,
    RestartCompleted,
    ShutdownRequested,
    Failed(RuntimeFailureCode),
}

/// Stable high-level phase exposed to application projections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimePhase {
    Starting,
    Running,
    Restarting,
    Stopping,
    Stopped,
    Failed,
}

impl RuntimePhase {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Starting => "Starting",
            Self::Running => "Running",
            Self::Restarting => "Restarting",
            Self::Stopping => "Stopping",
            Self::Stopped => "Stopped",
            Self::Failed => "Failed",
        }
    }
}

/// Coarse failure code suitable for durable state and UI projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeFailureCode {
    RuntimeBuild,
    RuntimeThread,
    Internal,
}

impl RuntimeFailureCode {
    pub const fn label(self) -> &'static str {
        match self {
            Self::RuntimeBuild => "runtime-build",
            Self::RuntimeThread => "runtime-thread",
            Self::Internal => "internal",
        }
    }
}

/// Read-only semantic projection of the runtime lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeProjection {
    Starting {
        generation: RuntimeGeneration,
    },
    Running {
        generation: RuntimeGeneration,
        uptime_seconds: u64,
    },
    Restarting {
        generation: RuntimeGeneration,
    },
    Stopping {
        generation: RuntimeGeneration,
    },
    Stopped {
        generation: RuntimeGeneration,
    },
    Failed {
        generation: RuntimeGeneration,
        code: RuntimeFailureCode,
    },
}

impl RuntimeProjection {
    pub const fn phase(&self) -> RuntimePhase {
        match self {
            Self::Starting { .. } => RuntimePhase::Starting,
            Self::Running { .. } => RuntimePhase::Running,
            Self::Restarting { .. } => RuntimePhase::Restarting,
            Self::Stopping { .. } => RuntimePhase::Stopping,
            Self::Stopped { .. } => RuntimePhase::Stopped,
            Self::Failed { .. } => RuntimePhase::Failed,
        }
    }

    pub const fn generation(&self) -> RuntimeGeneration {
        match self {
            Self::Starting { generation }
            | Self::Running { generation, .. }
            | Self::Restarting { generation }
            | Self::Stopping { generation }
            | Self::Stopped { generation }
            | Self::Failed { generation, .. } => *generation,
        }
    }

    pub const fn uptime_seconds(&self) -> u64 {
        match self {
            Self::Running { uptime_seconds, .. } => *uptime_seconds,
            _ => 0,
        }
    }

    pub const fn failure_code(&self) -> Option<RuntimeFailureCode> {
        match self {
            Self::Failed { code, .. } => Some(*code),
            _ => None,
        }
    }
}

/// Pure lifecycle state machine. It does not perform I/O or read hidden runtime state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeLifecycle {
    projection: RuntimeProjection,
}

impl RuntimeLifecycle {
    pub const fn booting() -> Self {
        Self {
            projection: RuntimeProjection::Starting {
                generation: RuntimeGeneration::INITIAL,
            },
        }
    }

    pub const fn projection(&self) -> &RuntimeProjection {
        &self.projection
    }

    pub fn apply(&mut self, event: RuntimeEvent) -> Result<(), RuntimeTransitionError> {
        let current = self.projection.clone();
        self.projection = match (current, event) {
            (
                RuntimeProjection::Starting { generation },
                RuntimeEvent::BootCompleted | RuntimeEvent::StartCompleted,
            ) => RuntimeProjection::Running {
                generation,
                uptime_seconds: 0,
            },
            (
                RuntimeProjection::Running {
                    generation,
                    uptime_seconds,
                },
                RuntimeEvent::Tick,
            ) => RuntimeProjection::Running {
                generation,
                uptime_seconds: uptime_seconds
                    .checked_add(1)
                    .ok_or(RuntimeTransitionError::UptimeOverflow)?,
            },
            (
                RuntimeProjection::Running { generation, .. },
                RuntimeEvent::StopRequested | RuntimeEvent::EmergencyStopRequested,
            ) => RuntimeProjection::Stopping { generation },
            (RuntimeProjection::Stopping { generation }, RuntimeEvent::StopCompleted) => {
                RuntimeProjection::Stopped { generation }
            }
            (RuntimeProjection::Stopped { generation }, RuntimeEvent::StartRequested) => {
                RuntimeProjection::Starting {
                    generation: generation.next()?,
                }
            }
            (RuntimeProjection::Running { generation, .. }, RuntimeEvent::RestartRequested) => {
                RuntimeProjection::Restarting { generation }
            }
            (RuntimeProjection::Restarting { generation }, RuntimeEvent::RestartCompleted) => {
                RuntimeProjection::Running {
                    generation: generation.next()?,
                    uptime_seconds: 0,
                }
            }
            (projection, RuntimeEvent::ShutdownRequested) => RuntimeProjection::Stopping {
                generation: projection.generation(),
            },
            (projection, RuntimeEvent::Failed(code)) => RuntimeProjection::Failed {
                generation: projection.generation(),
                code,
            },
            (projection, invalid_event) => {
                return Err(RuntimeTransitionError::InvalidTransition {
                    phase: projection.phase(),
                    event: invalid_event,
                });
            }
        };
        Ok(())
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeTransitionError {
    #[error("invalid runtime transition from {phase:?} using {event:?}")]
    InvalidTransition {
        phase: RuntimePhase,
        event: RuntimeEvent,
    },
    #[error("runtime generation overflow")]
    GenerationOverflow,
    #[error("runtime uptime overflow")]
    UptimeOverflow,
}

#[cfg(test)]
mod tests {
    use super::{
        RuntimeEvent, RuntimeGeneration, RuntimeLifecycle, RuntimePhase, RuntimeProjection,
    };

    #[test]
    fn lifecycle_supports_boot_stop_start_and_restart() -> Result<(), Box<dyn std::error::Error>> {
        let mut lifecycle = RuntimeLifecycle::booting();
        assert_eq!(lifecycle.projection().phase(), RuntimePhase::Starting);

        lifecycle.apply(RuntimeEvent::BootCompleted)?;
        assert_eq!(
            lifecycle.projection(),
            &RuntimeProjection::Running {
                generation: RuntimeGeneration::INITIAL,
                uptime_seconds: 0,
            }
        );

        lifecycle.apply(RuntimeEvent::Tick)?;
        assert_eq!(lifecycle.projection().uptime_seconds(), 1);

        lifecycle.apply(RuntimeEvent::StopRequested)?;
        lifecycle.apply(RuntimeEvent::StopCompleted)?;
        assert_eq!(lifecycle.projection().phase(), RuntimePhase::Stopped);

        lifecycle.apply(RuntimeEvent::StartRequested)?;
        lifecycle.apply(RuntimeEvent::StartCompleted)?;
        assert_eq!(lifecycle.projection().generation().get(), 2);

        lifecycle.apply(RuntimeEvent::RestartRequested)?;
        lifecycle.apply(RuntimeEvent::RestartCompleted)?;
        assert_eq!(lifecycle.projection().generation().get(), 3);
        assert_eq!(lifecycle.projection().phase(), RuntimePhase::Running);
        Ok(())
    }

    #[test]
    fn lifecycle_rejects_invalid_transitions() {
        let mut lifecycle = RuntimeLifecycle::booting();
        let error = lifecycle.apply(RuntimeEvent::Tick);
        assert!(error.is_err());
        assert_eq!(lifecycle.projection().phase(), RuntimePhase::Starting);
    }
}
