//! Historical Coordinator DAG plan readback.

use forge_domain::AgentDagPlanRequestId;
use rusqlite::TransactionBehavior;

use super::{WorkspaceStore, WorkspaceStoreError};
use crate::workspace_agent_dag::{self, AgentDagPlanRecord};

impl WorkspaceStore {
    /// Read one historical Coordinator DAG plan receipt without requiring any
    /// live session, Coordinator, or Goal authority.
    ///
    /// Ledger and session provenance are decoded from one deferred `SQLite`
    /// transaction.  A missing session identity is returned as an explicit
    /// persistence error by the shared ledger decoder; it is never inferred.
    pub fn agent_dag_plan_readback(
        &mut self,
        request_id: AgentDagPlanRequestId,
    ) -> Result<Option<AgentDagPlanRecord>, WorkspaceStoreError> {
        self.ensure_live_binding()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let record = workspace_agent_dag::read_plan_record(&transaction, request_id)?;
        transaction.commit()?;
        self.ensure_live_binding()?;
        Ok(record)
    }
}
