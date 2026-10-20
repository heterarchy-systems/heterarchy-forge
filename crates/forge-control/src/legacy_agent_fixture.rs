//! Historical fixture rows for tests of retained work authority.
//! No production attachment API or session authority is provided here.

use std::path::Path;

use forge_domain::{AgentEventId, RegisteredAgentInstance};
use rusqlite::Connection;

use crate::{ForgeControl, ForgeControlClient, ResolvedWorkspaceScope};

#[path = "../../forge-persistence/src/legacy_agent_seed.rs"]
mod rows;

pub(crate) fn seed_agent_in_database(
    database: &Path,
    agent: &RegisteredAgentInstance,
    event_id: AgentEventId,
) -> Result<RegisteredAgentInstance, Box<dyn std::error::Error>> {
    let connection = Connection::open(database)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    rows::seed_agent(&connection, agent, Some(event_id))?;
    Ok(agent.clone())
}

pub(crate) fn seed_agent(
    control: &ForgeControl,
    scope: &ResolvedWorkspaceScope,
    agent: &RegisteredAgentInstance,
    event_id: AgentEventId,
) -> Result<RegisteredAgentInstance, Box<dyn std::error::Error>> {
    let (resolved, layout, store) = control.open_resolved_workspace_with_layout(
        scope.locator().location_id(),
        scope.locator().expected_revision(),
        scope.locator(),
    )?;
    if resolved != *scope || agent.workspace_id() != scope.workspace_id() {
        return Err("historical fixture Workspace mismatch".into());
    }
    drop(store);
    let _ = seed_agent_in_database(&layout.database_path(), agent, event_id)?;
    let (_, store) = control.open_agent_workspace(scope)?;
    store
        .get_agent(agent.id())?
        .ok_or_else(|| "historical fixture Agent missing after seed".into())
}

/// Resolve the test's explicit registered location before inserting fixture
/// rows. This is test setup, not a replacement control-worker mutation.
pub(crate) fn seed_client_agent(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    agent: &RegisteredAgentInstance,
    event_id: AgentEventId,
) -> Result<RegisteredAgentInstance, Box<dyn std::error::Error>> {
    let locator = scope.locator();
    let current = client.resolve_workspace(
        locator.location_id(),
        locator.expected_revision(),
        locator.clone(),
    )?;
    if current != *scope || agent.workspace_id() != scope.workspace_id() {
        return Err("historical fixture Workspace mismatch".into());
    }
    let location = client
        .location_list()?
        .into_iter()
        .find(|location| {
            location.id() == locator.location_id()
                && location.revision() == locator.expected_revision()
        })
        .ok_or("historical fixture Location missing")?;
    let root = location.root().as_path().join(locator.relative_root());
    let layout = forge_workspace::WorkspaceStateLayout::inspect_existing(&root)?
        .ok_or("historical fixture Workspace layout missing")?;
    seed_agent_in_database(&layout.database_path(), agent, event_id)
}
