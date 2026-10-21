#![allow(clippy::wildcard_imports)]

use super::*;

#[allow(clippy::too_many_lines)]
pub(super) fn admit_next(
    operation: &str,
    state: &mut ProvisioningSnapshot,
    command: AdmitNextCommand,
) -> Result<(ProvisioningSnapshot, ProvisioningOutcome), DomainError> {
    validate_retention(
        operation,
        "terminal_request_retention",
        command.terminal_request_retention,
    )?;
    if command.admission_lease_micros == 0 {
        return Err(error(
            operation,
            "admission_lease_micros",
            "admission_lease_micros must be positive.",
        ));
    }
    let mut binding_projects = HashSet::new();
    for binding in &command.bindings {
        validate_id(operation, "bindings", &binding.project_id, "project_id")?;
        if !binding_projects.insert(binding.project_id.as_str()) {
            return Err(error(
                operation,
                &binding.project_id,
                "Provisioning binding project IDs must be unique.",
            ));
        }
    }
    if let Some(seed) = &command.new_request_seed {
        validate_id(
            operation,
            "new_request_seed",
            &seed.request_id,
            "request_id",
        )?;
        validate_id(
            operation,
            &seed.request_id,
            &seed.wake_target_id,
            "wake_target_id",
        )?;
    }

    let now = command.now_micros;
    let mut changed = false;
    if let Some(in_flight_id) = state.admission.in_flight_request_id.clone() {
        let in_flight = state
            .requests
            .iter_mut()
            .find(|item| item.request_id == in_flight_id);
        match in_flight {
            Some(request) if request.status.transient() => {
                let elapsed = checked_elapsed(
                    now,
                    request.updated_at_micros,
                    operation,
                    &request.request_id,
                )?;
                if elapsed < command.admission_lease_micros {
                    return Ok((state.clone(), ProvisioningOutcome::Noop));
                }
                request.status = ProvisioningRequestStatus::WaitingAdmission;
                request.admission_revision = None;
                request.failure_reason = Some("admission_lease_expired".to_owned());
                request.revision = next_revision(request.revision, operation, &request.request_id)?;
                request.updated_at_micros = now;
                state.admission.in_flight_request_id = None;
                state.admission.revision =
                    next_revision(state.admission.revision, operation, "admission")?;
                changed = true;
            }
            _ => {
                state.admission.in_flight_request_id = None;
                state.admission.revision =
                    next_revision(state.admission.revision, operation, "admission")?;
                changed = true;
            }
        }
    }
    if state.admission.in_flight_request_id.is_none()
        && (state
            .admission
            .next_admission_at_micros
            .is_some_and(|value| value.0 > now.0)
            || state
                .admission
                .backoff_until_micros
                .is_some_and(|value| value.0 > now.0))
    {
        if changed {
            commit_root(state, now, operation)?;
        }
        return Ok((state.clone(), ProvisioningOutcome::Noop));
    }
    let bindings: HashMap<&str, &ProviderBindingObservation> = command
        .bindings
        .iter()
        .map(|binding| (binding.project_id.as_str(), binding))
        .collect();
    let blocked_projects = operator_blocked_projects(state, &bindings, command.binding_required);
    let mut candidates: Vec<(usize, String)> = state
        .requests
        .iter()
        .enumerate()
        .filter(|(_, request)| request.status.queued())
        .filter(|(_, request)| demand_positive(state, &request.project_id))
        .filter(|(_, request)| !blocked_projects.contains(request.project_id.as_str()))
        .filter(|(_, request)| {
            binding_admissible(
                bindings.get(request.project_id.as_str()),
                command.binding_required,
            )
        })
        .map(|(index, request)| (index, request.request_id.clone()))
        .collect();
    candidates.sort_by_key(|(index, _)| {
        let request = &state.requests[*index];
        (request.created_at_micros.0, request.request_id.clone())
    });
    let candidate_index = if let Some((index, _)) = candidates.first() {
        *index
    } else {
        let demand_index = state.demands.iter().position(|demand| {
            demand.spawn_needed > 0
                && !blocked_projects.contains(demand.project_id.as_str())
                && binding_admissible(
                    bindings.get(demand.project_id.as_str()),
                    command.binding_required,
                )
        });
        let Some(demand_index) = demand_index else {
            if changed {
                commit_root(state, now, operation)?;
            }
            return Ok((state.clone(), ProvisioningOutcome::Noop));
        };
        let Some(seed) = command.new_request_seed else {
            return Err(error(
                operation,
                &state.demands[demand_index].project_id,
                "A prepared request seed is required for admission.",
            ));
        };
        let demand = &state.demands[demand_index];
        if state.requests.iter().any(|item| {
            item.request_id == seed.request_id
                || item.wake_target_id.as_deref() == Some(seed.wake_target_id.as_str())
        }) {
            return Err(error(
                operation,
                &seed.request_id,
                "Prepared provisioning request or wake target ID collides with durable state.",
            ));
        }
        if state.requests.len() >= MAX_PROVISIONING_REQUESTS {
            return Err(error(
                operation,
                &state.demands[demand_index].project_id,
                "Provisioning admission would exceed the bounded request limit.",
            ));
        }
        state.requests.push(ProvisioningRequest {
            schema_version: 2,
            request_id: seed.request_id,
            project_id: demand.project_id.clone(),
            provider_binding: None,
            status: ProvisioningRequestStatus::WaitingAdmission,
            admission_revision: None,
            revision: Revision(0),
            provider_runtime_id: None,
            wake_target_id: Some(seed.wake_target_id),
            failure_reason: None,
            created_at_micros: now,
            updated_at_micros: now,
        });
        state.requests.len() - 1
    };
    let request_project_id = state.requests[candidate_index].project_id.clone();
    let binding = bindings.get(request_project_id.as_str()).copied();
    let admission_revision = next_revision(state.admission.revision, operation, "admission")?;
    let request_id;
    {
        let request = &mut state.requests[candidate_index];
        request.status = ProvisioningRequestStatus::OpeningProject;
        if let Some(binding) = binding {
            request.provider_binding = Some(binding.clone());
        }
        request.admission_revision = Some(admission_revision);
        request.revision = next_revision(request.revision, operation, &request.request_id)?;
        request.updated_at_micros = now;
        request_id = request.request_id.clone();
    }
    state.admission.in_flight_request_id = Some(request_id.clone());
    state.admission.last_admitted_at_micros = Some(now);
    state.admission.next_admission_at_micros = Some(checked_timestamp_add(
        now,
        command.minimum_admission_interval_micros,
        operation,
        "admission",
        "Provisioning admission interval overflowed.",
    )?);
    state.admission.revision = admission_revision;
    commit_root(state, now, operation)?;
    let protected = HashSet::new();
    prune_terminal(
        state,
        command.terminal_request_retention,
        operation,
        &protected,
    )?;
    Ok((
        state.clone(),
        ProvisioningOutcome::Admitted {
            request_id,
            admission_revision,
        },
    ))
}

fn operator_blocked_projects(
    state: &ProvisioningSnapshot,
    bindings: &HashMap<&str, &ProviderBindingObservation>,
    binding_required: bool,
) -> HashSet<String> {
    state
        .requests
        .iter()
        .filter(|request| request.status == ProvisioningRequestStatus::OperatorBlocked)
        .filter(|request| {
            if !binding_required {
                return true;
            }
            let Some(binding) = bindings.get(request.project_id.as_str()) else {
                return true;
            };
            request.provider_binding.as_ref() == Some(*binding)
        })
        .map(|request| request.project_id.clone())
        .collect()
}
