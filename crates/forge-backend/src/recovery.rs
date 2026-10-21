//! Bounded startup recovery pass over every registered, enabled Location.
//!
//! After a crash, executions left in Starting/Running and leases left live are
//! unproven: recovery maintenance must classify them before the standalone
//! backend admits new work. This pass mirrors the desktop startup
//! maintenance: one bounded recovery-maintenance claim per Workspace under
//! the process boot identity. A failing or busy Workspace never blocks the
//! others — each outcome is reported, and the report is the operator-visible
//! startup evidence.

use std::time::{SystemTime, UNIX_EPOCH};

use forge_control::{ForgeControlClient, RecoveryMaintenanceOutcome, RecoveryMaintenanceRequest};
use forge_domain::{
    ActivityListLimit, ExecutionListLimit, LocationState, RecoveryLeaseDurationMillis,
    RuntimeInstanceId, TimestampMillis,
};

/// One-shot maintenance lease duration, mirroring the desktop startup pass.
const STARTUP_RECOVERY_LEASE_DURATION_MILLIS: i64 = 30_000;

/// Bounded startup evidence. Failures carry a redacted, stable reason only —
/// never adapter or SQL detail.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupRecoveryReport {
    pub locations_scanned: usize,
    pub workspaces_scanned: usize,
    pub classified_activities: usize,
    pub classified_executions: usize,
    pub busy_workspaces: usize,
    pub conflicts: usize,
    pub failures: Vec<String>,
}

impl StartupRecoveryReport {
    pub fn is_clean(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Run the pass synchronously on the caller (a startup blocking context).
/// Control-client-level failures land in `failures` too: the backend must not
/// refuse to serve unrelated Workspaces because one scope cannot be recovered.
pub fn run_startup_recovery(
    client: &ForgeControlClient,
    owner: RuntimeInstanceId,
) -> StartupRecoveryReport {
    let mut report = StartupRecoveryReport {
        locations_scanned: 0,
        workspaces_scanned: 0,
        classified_activities: 0,
        classified_executions: 0,
        busy_workspaces: 0,
        conflicts: 0,
        failures: Vec::new(),
    };
    let Some(duration) =
        RecoveryLeaseDurationMillis::new(STARTUP_RECOVERY_LEASE_DURATION_MILLIS).ok()
    else {
        report
            .failures
            .push("the recovery lease duration is invalid".to_owned());
        return report;
    };
    let Some(observed_at) = observed_millis(SystemTime::now()) else {
        report
            .failures
            .push("the system clock is out of range".to_owned());
        return report;
    };
    let locations = match client.location_list() {
        Ok(locations) => locations,
        Err(error) => {
            report
                .failures
                .push(redacted_failure("location listing", &error));
            return report;
        }
    };
    for location in &locations {
        if location.state() != LocationState::Enabled {
            continue;
        }
        report.locations_scanned += 1;
        let workspaces =
            match client.registered_workspace_inventory(location.id(), location.revision()) {
                Ok(workspaces) => workspaces,
                Err(error) => {
                    report
                        .failures
                        .push(redacted_failure("workspace listing", &error));
                    continue;
                }
            };
        for entry in workspaces.entries() {
            report.workspaces_scanned += 1;
            let scope = match entry {
                forge_control::WorkspaceInventoryEntry::Registered { scope, .. } => scope.clone(),
                forge_control::WorkspaceInventoryEntry::Unavailable { code, .. } => {
                    report
                        .failures
                        .push(format!("workspace inventory: {}", code.as_str()));
                    continue;
                }
            };
            let request = match RecoveryMaintenanceRequest::native(
                scope,
                uuid::Uuid::now_v7(),
                owner,
                duration,
                observed_at,
                (ActivityListLimit::DEFAULT, ExecutionListLimit::DEFAULT),
            ) {
                Ok(request) => request,
                Err(error) => {
                    report
                        .failures
                        .push(format!("recovery intent: {}", error.code().as_str()));
                    continue;
                }
            };
            match client.run_recovery_maintenance(request) {
                Ok(maintenance) => match maintenance.outcome() {
                    RecoveryMaintenanceOutcome::Completed => {
                        report.classified_activities += maintenance.activity_count();
                        report.classified_executions += maintenance.execution_count();
                    }
                    RecoveryMaintenanceOutcome::Busy => report.busy_workspaces += 1,
                    RecoveryMaintenanceOutcome::ClaimConflict => report.conflicts += 1,
                },
                Err(error) => {
                    report
                        .failures
                        .push(redacted_failure("recovery maintenance", &error));
                }
            }
        }
    }
    report
}

fn observed_millis(now: SystemTime) -> Option<TimestampMillis> {
    let millis = now.duration_since(UNIX_EPOCH).ok()?.as_millis();
    i64::try_from(millis)
        .ok()
        .and_then(|value| TimestampMillis::new(value).ok())
}

/// Control errors are already redacted; keep only the stable wire label.
fn redacted_failure(stage: &'static str, error: &forge_control::ControlClientError) -> String {
    let label = match error {
        forge_control::ControlClientError::QueueFull => "CONTROL_QUEUE_FULL".to_owned(),
        forge_control::ControlClientError::WorkerShuttingDown => {
            "CONTROL_WORKER_SHUTTING_DOWN".to_owned()
        }
        forge_control::ControlClientError::WorkerClosed => "CONTROL_WORKER_CLOSED".to_owned(),
        forge_control::ControlClientError::ResponseDropped => "CONTROL_RESPONSE_DROPPED".to_owned(),
        forge_control::ControlClientError::Service(service) => service.code().to_string(),
    };
    format!("{stage}: {label}")
}

#[cfg(test)]
mod tests {
    use super::run_startup_recovery;
    use forge_control::{ForgeControl, ForgeControlWorker};
    use forge_domain::RuntimeInstanceId;
    use forge_persistence::GlobalRegistry;
    use uuid::Uuid;

    #[test]
    fn recovery_clock_rejects_pre_epoch_time_without_reinterpreting_it_as_zero()
    -> Result<(), Box<dyn std::error::Error>> {
        let epoch = std::time::UNIX_EPOCH;
        let before = epoch
            .checked_sub(std::time::Duration::from_millis(1))
            .ok_or("pre-epoch fixture is not representable")?;
        assert_eq!(
            super::observed_millis(epoch),
            Some(forge_domain::TimestampMillis::new(0)?)
        );
        assert_eq!(super::observed_millis(before), None);
        Ok(())
    }

    #[test]
    fn startup_recovery_visits_registered_children_and_classifies_expired_activity()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!("forge-child-recovery-{}", Uuid::now_v7()));
        let location_root = root.join("location");
        let child = location_root.join("child");
        std::fs::create_dir_all(&child)?;
        let mut registry = forge_workspace::LocationService::new(GlobalRegistry::open(
            root.join("registry.sqlite3"),
        )?);
        let location = registry.register_selected_path(
            forge_domain::LocationId::from_uuid(Uuid::now_v7()),
            "child recovery",
            &location_root,
            forge_domain::TimestampMillis::new(1)?,
        )?;
        let (client, mut worker) = ForgeControlWorker::start(ForgeControl::from_location_service(
            registry,
            root.join("agent-sessions.sqlite3"),
        ))?;
        let locator =
            forge_control::WorkspaceLocator::new(location.id(), location.revision(), "child")?;
        let probe = client.probe_workspace_registration(locator.clone())?;
        let _registration =
            client.register_workspace(forge_control::WorkspaceRegistrationRequest::new(
                locator.clone(),
                forge_domain::WorkspaceId::from_uuid(Uuid::now_v7()),
                probe.root_fingerprint,
                forge_domain::TimestampMillis::new(1)?,
            )?)?;
        let scope = client.resolve_workspace(location.id(), location.revision(), locator)?;
        let _activity = client.bootstrap_activity(
            scope,
            forge_domain::ActivityId::from_uuid(Uuid::now_v7()),
            RuntimeInstanceId::from_uuid(Uuid::now_v7()),
            forge_domain::TimestampMillis::new(2)?,
            forge_domain::TimestampMillis::new(3)?,
        )?;
        let report = run_startup_recovery(&client, RuntimeInstanceId::from_uuid(Uuid::now_v7()));
        worker.shutdown()?;
        std::fs::remove_dir_all(root)?;
        assert_eq!(
            report.workspaces_scanned, 1,
            "registered child was omitted: {report:?}"
        );
        assert_eq!(
            report.classified_activities, 1,
            "expired child activity was not classified"
        );
        assert!(report.is_clean(), "{report:?}");
        Ok(())
    }

    #[test]
    fn empty_registry_scans_nothing_and_reports_clean() -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-startup-recovery-{}",
            Uuid::now_v7()
        ));
        std::fs::create_dir_all(&root)?;
        let registry_path = root.join("registry.sqlite3");
        drop(GlobalRegistry::open(&registry_path)?);
        let (client, mut worker) = ForgeControlWorker::start(ForgeControl::new(
            GlobalRegistry::open_existing(&registry_path)?,
        ))?;
        let report = run_startup_recovery(&client, RuntimeInstanceId::from_uuid(Uuid::now_v7()));
        worker.shutdown()?;
        assert_eq!(report.locations_scanned, 0);
        assert_eq!(report.workspaces_scanned, 0);
        assert!(report.is_clean());
        std::fs::remove_dir_all(&root)?;
        Ok(())
    }
}
