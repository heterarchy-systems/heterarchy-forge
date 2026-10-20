#![allow(clippy::wildcard_imports)]

use super::*;

const CURRENT_SCHEMA_VERSION: u32 = 2;

#[allow(clippy::too_many_lines)]
pub(super) fn validate_snapshot(
    snapshot: &ProvisioningSnapshot,
    operation: &str,
) -> Result<(), DomainError> {
    if snapshot.schema_version != CURRENT_SCHEMA_VERSION {
        return Err(snapshot_error(
            operation,
            "snapshot",
            "Unsupported provisioning snapshot schema version.",
        ));
    }
    if snapshot.demands.len() > MAX_PROVISIONING_DEMANDS {
        return Err(snapshot_error(
            operation,
            "demands",
            "Provisioning snapshot exceeds the bounded demand limit.",
        ));
    }
    if snapshot.requests.len() > MAX_PROVISIONING_REQUESTS {
        return Err(snapshot_error(
            operation,
            "requests",
            "Provisioning snapshot exceeds the bounded request limit.",
        ));
    }

    let mut projects = HashSet::new();
    for demand in &snapshot.demands {
        validate_snapshot_id(operation, "demands", &demand.project_id, "project_id")?;
        if demand.schema_version != CURRENT_SCHEMA_VERSION {
            return Err(snapshot_error(
                operation,
                &demand.project_id,
                "Unsupported provisioning demand schema version.",
            ));
        }
        if !projects.insert(demand.project_id.as_str()) {
            return Err(snapshot_error(
                operation,
                &demand.project_id,
                "Provisioning demand project IDs must be unique.",
            ));
        }
        if demand.spawn_needed > demand.desired_capacity {
            return Err(snapshot_error(
                operation,
                &demand.project_id,
                "spawn_needed cannot exceed desired_capacity.",
            ));
        }
        if demand.created_at_micros > demand.updated_at_micros
            || demand.updated_at_micros > snapshot.updated_at_micros
        {
            return Err(snapshot_error(
                operation,
                &demand.project_id,
                "Provisioning demand timestamps are inverted.",
            ));
        }
    }

    if snapshot.admission.schema_version != CURRENT_SCHEMA_VERSION {
        return Err(snapshot_error(
            operation,
            "admission",
            "Unsupported provisioning admission schema version.",
        ));
    }
    if let (Some(last), Some(next)) = (
        snapshot.admission.last_admitted_at_micros,
        snapshot.admission.next_admission_at_micros,
    ) && next < last
    {
        return Err(snapshot_error(
            operation,
            "admission",
            "next_admission_at_micros precedes last_admitted_at_micros.",
        ));
    }
    if let (Some(last), Some(backoff)) = (
        snapshot.admission.last_admitted_at_micros,
        snapshot.admission.backoff_until_micros,
    ) && backoff < last
    {
        return Err(snapshot_error(
            operation,
            "admission",
            "backoff_until_micros precedes last_admitted_at_micros.",
        ));
    }
    if snapshot.admission.backoff_attempt == 0 && snapshot.admission.backoff_until_micros.is_some()
    {
        return Err(snapshot_error(
            operation,
            "admission",
            "A backoff timestamp requires a positive backoff attempt.",
        ));
    }
    if snapshot.admission.backoff_attempt > 0 && snapshot.admission.backoff_until_micros.is_none() {
        return Err(snapshot_error(
            operation,
            "admission",
            "A positive backoff attempt requires a backoff timestamp.",
        ));
    }

    let mut request_ids = HashSet::new();
    let mut wake_ids = HashSet::new();
    let mut transient_ids = Vec::new();
    for request in &snapshot.requests {
        validate_snapshot_id(operation, "requests", &request.request_id, "request_id")?;
        validate_snapshot_id(
            operation,
            &request.request_id,
            &request.project_id,
            "project_id",
        )?;
        validate_snapshot_provider_binding(
            operation,
            &request.request_id,
            request.provider_binding.as_ref(),
            &request.project_id,
        )?;
        validate_snapshot_optional_text(
            operation,
            &request.request_id,
            request.failure_reason.as_deref(),
            "failure_reason",
            MAX_PROVISIONING_FAILURE_REASON_BYTES,
        )?;
        if request.schema_version != CURRENT_SCHEMA_VERSION {
            return Err(snapshot_error(
                operation,
                &request.request_id,
                "Unsupported provisioning request schema version.",
            ));
        }
        if !projects.contains(request.project_id.as_str()) {
            return Err(snapshot_error(
                operation,
                &request.request_id,
                "Provisioning request references a project without demand.",
            ));
        }
        if !request_ids.insert(request.request_id.as_str()) {
            return Err(snapshot_error(
                operation,
                &request.request_id,
                "Provisioning request IDs must be unique.",
            ));
        }
        if let Some(wake_target_id) = &request.wake_target_id {
            validate_snapshot_id(
                operation,
                &request.request_id,
                wake_target_id,
                "wake_target_id",
            )?;
            if !wake_ids.insert(wake_target_id.as_str()) {
                return Err(snapshot_error(
                    operation,
                    wake_target_id,
                    "Provisioning wake target IDs must be unique.",
                ));
            }
        }
        if request.created_at_micros > request.updated_at_micros
            || request.updated_at_micros > snapshot.updated_at_micros
        {
            return Err(snapshot_error(
                operation,
                &request.request_id,
                "Provisioning request timestamps are inverted.",
            ));
        }
        if let Some(admission_revision) = request.admission_revision
            && admission_revision > snapshot.admission.revision
        {
            return Err(snapshot_error(
                operation,
                &request.request_id,
                "Request admission revision exceeds the admission revision.",
            ));
        }
        if request.status == ProvisioningRequestStatus::Active {
            validate_snapshot_id(
                operation,
                &request.request_id,
                request.provider_runtime_id.as_deref().unwrap_or_default(),
                "provider_runtime_id",
            )?;
            validate_snapshot_id(
                operation,
                &request.request_id,
                request.wake_target_id.as_deref().unwrap_or_default(),
                "wake_target_id",
            )?;
            if request.admission_revision.is_none() {
                return Err(snapshot_error(
                    operation,
                    &request.request_id,
                    "An active request must retain its admission identity.",
                ));
            }
        } else if request.status.transient() {
            validate_snapshot_id(
                operation,
                &request.request_id,
                request.wake_target_id.as_deref().unwrap_or_default(),
                "wake_target_id",
            )?;
            if request.admission_revision.is_none() {
                return Err(snapshot_error(
                    operation,
                    &request.request_id,
                    "A transient request must retain its admission revision.",
                ));
            }
            transient_ids.push(request.request_id.as_str());
        } else if request.status == ProvisioningRequestStatus::WaitingAdmission
            && request.admission_revision.is_some()
        {
            return Err(snapshot_error(
                operation,
                &request.request_id,
                "A waiting-admission request must not retain an admission revision.",
            ));
        }
    }

    if transient_ids.len() > 1 {
        return Err(snapshot_error(
            operation,
            "requests",
            "At most one transient provisioning request may exist.",
        ));
    }
    if let Some(in_flight_id) = &snapshot.admission.in_flight_request_id {
        validate_snapshot_id(operation, "admission", in_flight_id, "in_flight_request_id")?;
        let Some(request) = snapshot
            .requests
            .iter()
            .find(|item| &item.request_id == in_flight_id)
        else {
            return Err(snapshot_error(
                operation,
                in_flight_id,
                "Admission in-flight request does not exist.",
            ));
        };
        if !request.status.transient()
            || request.admission_revision.is_none()
            || transient_ids.as_slice() != [in_flight_id.as_str()]
        {
            return Err(snapshot_error(
                operation,
                in_flight_id,
                "Admission in-flight request must be the only transient request and retain its admission identity.",
            ));
        }
    } else if !transient_ids.is_empty() {
        return Err(snapshot_error(
            operation,
            transient_ids[0],
            "A transient request must be referenced by admission.in_flight_request_id.",
        ));
    }
    Ok(())
}

fn validate_snapshot_id(
    operation: &str,
    resource_id: &str,
    value: &str,
    label: &str,
) -> Result<(), DomainError> {
    if value.trim().is_empty() {
        return Err(snapshot_error(
            operation,
            resource_id,
            &format!("{label} cannot be empty."),
        ));
    }
    if value.len() > MAX_PROVISIONING_ID_BYTES {
        return Err(snapshot_error(
            operation,
            resource_id,
            &format!("{label} exceeds the bounded identifier size."),
        ));
    }
    Ok(())
}

fn validate_snapshot_provider_binding(
    operation: &str,
    resource_id: &str,
    binding: Option<&ProviderBindingObservation>,
    project_id: &str,
) -> Result<(), DomainError> {
    let Some(binding) = binding else {
        return Ok(());
    };
    if binding.project_id != project_id {
        return Err(snapshot_error(
            operation,
            resource_id,
            "Provider binding observation belongs to a different project.",
        ));
    }
    validate_snapshot_id(operation, resource_id, &binding.binding_id, "binding_id")?;
    if let Some(fingerprint) = binding.metadata_fingerprint.as_deref()
        && (fingerprint.trim().is_empty()
            || fingerprint.len() > MAX_PROVISIONING_BINDING_FINGERPRINT_BYTES)
    {
        return Err(snapshot_error(
            operation,
            resource_id,
            "metadata_fingerprint is malformed or exceeds the bounded size.",
        ));
    }
    Ok(())
}

fn validate_snapshot_optional_text(
    operation: &str,
    resource_id: &str,
    value: Option<&str>,
    label: &str,
    maximum_bytes: usize,
) -> Result<(), DomainError> {
    if value.is_some_and(|text| text.len() > maximum_bytes) {
        return Err(snapshot_error(
            operation,
            resource_id,
            &format!("{label} exceeds the bounded size."),
        ));
    }
    Ok(())
}
