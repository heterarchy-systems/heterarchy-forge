use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::{DomainError, ErrorCode};

pub const MAX_DEPENDENCY_TASKS: usize = 512;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyTask {
    pub key: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyPlan {
    pub tasks: Vec<DependencyTask>,
    pub requested_parallelism: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DependencyDecision {
    pub ordered_keys: Vec<String>,
    pub root_keys: Vec<String>,
    pub requested_parallelism: u16,
}

/// Validate a bounded dependency projection supplied by Forge and derive stable runnable ordering.
/// This does not create, revise, or own Forge Goal/DAG state.
///
/// # Errors
///
/// Returns a typed error when task bounds, dependency identities, or graph
/// acyclicity are invalid.
pub fn validate_dependencies(
    operation: &str,
    plan: DependencyPlan,
) -> Result<DependencyDecision, DomainError> {
    let DependencyPlan {
        tasks,
        requested_parallelism,
    } = plan;
    validate_bounds(operation, &tasks, requested_parallelism)?;
    let by_key = index_tasks(operation, &tasks)?;
    let (roots, ordered) = topological_order(operation, &tasks, &by_key)?;
    let requested_parallelism = match requested_parallelism {
        Some(value) => value,
        None => u16::try_from(roots.len()).unwrap_or(u16::MAX).max(1),
    };
    Ok(DependencyDecision {
        ordered_keys: ordered
            .into_iter()
            .map(|index| tasks[index].key.clone())
            .collect(),
        root_keys: roots
            .into_iter()
            .map(|index| tasks[index].key.clone())
            .collect(),
        requested_parallelism,
    })
}

fn validate_bounds(
    operation: &str,
    tasks: &[DependencyTask],
    requested_parallelism: Option<u16>,
) -> Result<(), DomainError> {
    if tasks.is_empty() {
        return Err(error(
            ErrorCode::EmptyTasks,
            operation,
            "tasks",
            "At least one dependency task is required.",
        ));
    }
    if tasks.len() > MAX_DEPENDENCY_TASKS {
        return Err(error(
            ErrorCode::InvalidInput,
            operation,
            "tasks",
            "Dependency task count exceeds the bounded policy limit.",
        ));
    }
    if matches!(requested_parallelism, Some(0)) {
        return Err(error(
            ErrorCode::InvalidParallelism,
            operation,
            "requested_parallelism",
            "requested_parallelism must be at least one.",
        ));
    }
    Ok(())
}

fn index_tasks(
    operation: &str,
    tasks: &[DependencyTask],
) -> Result<HashMap<String, usize>, DomainError> {
    let mut by_key = HashMap::with_capacity(tasks.len());
    for (index, task) in tasks.iter().enumerate() {
        if by_key.insert(task.key.clone(), index).is_some() {
            return Err(error(
                ErrorCode::DuplicateTaskKey,
                operation,
                &task.key,
                "Dependency task key is duplicated.",
            ));
        }
    }
    Ok(by_key)
}

fn topological_order(
    operation: &str,
    tasks: &[DependencyTask],
    by_key: &HashMap<String, usize>,
) -> Result<(Vec<usize>, Vec<usize>), DomainError> {
    let task_count = tasks.len();
    let mut indegree = vec![0_usize; task_count];
    let mut dependents = vec![Vec::<usize>::new(); task_count];
    for (index, task) in tasks.iter().enumerate() {
        let mut seen = HashSet::with_capacity(task.depends_on.len());
        for dependency in &task.depends_on {
            if dependency == &task.key {
                return Err(error(
                    ErrorCode::SelfDependency,
                    operation,
                    &task.key,
                    "A dependency task cannot depend on itself.",
                ));
            }
            let Some(&dependency_index) = by_key.get(dependency) else {
                return Err(error(
                    ErrorCode::UnknownDependency,
                    operation,
                    dependency,
                    "Dependency task refers to an unknown prerequisite.",
                ));
            };
            if seen.insert(dependency) {
                indegree[index] += 1;
                dependents[dependency_index].push(index);
            }
        }
    }

    let roots: Vec<usize> = (0..task_count)
        .filter(|&index| indegree[index] == 0)
        .collect();
    let mut ready = VecDeque::from(roots.clone());
    let mut ordered = Vec::with_capacity(task_count);
    while let Some(index) = ready.pop_front() {
        ordered.push(index);
        let mut newly_ready = Vec::new();
        for &dependent in &dependents[index] {
            indegree[dependent] -= 1;
            if indegree[dependent] == 0 {
                newly_ready.push(dependent);
            }
        }
        newly_ready.sort_unstable();
        ready.extend(newly_ready);
    }
    if ordered.len() != task_count {
        return Err(error(
            ErrorCode::Cycle,
            operation,
            "tasks",
            "Dependency projection contains a cycle.",
        ));
    }
    Ok((roots, ordered))
}

fn error(code: ErrorCode, operation: &str, resource_id: &str, message: &str) -> DomainError {
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

    #[test]
    fn derives_stable_topological_order() {
        let decision = validate_dependencies(
            "test",
            DependencyPlan {
                tasks: vec![
                    DependencyTask {
                        key: "a".into(),
                        depends_on: vec![],
                    },
                    DependencyTask {
                        key: "b".into(),
                        depends_on: vec!["a".into()],
                    },
                    DependencyTask {
                        key: "c".into(),
                        depends_on: vec!["a".into()],
                    },
                ],
                requested_parallelism: None,
            },
        )
        .expect("valid dependency plan");
        assert_eq!(decision.ordered_keys, ["a", "b", "c"]);
        assert_eq!(decision.root_keys, ["a"]);
        assert_eq!(decision.requested_parallelism, 1);
    }
}
