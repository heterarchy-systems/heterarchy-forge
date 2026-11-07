//! Terminal cancellation before recipient admission is complete.
//!
//! Aborting cannot require the admission it is intended to recover. It does
//! require an authenticated configured issuer and the exact historical request.

use forge_domain::{
    ForgeBackendId, HomeHandoffTakeRequest, OrchestrationIssuerId, TimestampMillis,
};
use rusqlite::{Connection, TransactionBehavior};
use uuid::Uuid;

use super::{
    HomeHandoffAcceptanceOutcomeRecord, HomeHandoffAcceptanceOutcomeRecordParts,
    HomeHandoffAcceptanceTerminal, HomeHandoffApplicationStoreError as Error, get_in_transaction,
    get_outcome, insert_outcome_in_transaction,
};

/// Persist Aborted or return an already terminal exact acceptance. No assignment,
/// current proposal head, organizational membership or effect fact is changed.
pub(crate) fn abort_unstarted<C>(
    connection: &mut Connection,
    request: &HomeHandoffTakeRequest,
    issuer: OrchestrationIssuerId,
    backend: ForgeBackendId,
    destination: Uuid,
    sample_clock: C,
) -> Result<HomeHandoffAcceptanceOutcomeRecord, Error>
where
    C: FnOnce() -> Result<TimestampMillis, Error>,
{
    validate_service_scope(request, backend, destination)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(existing) = get_outcome(&transaction, request.acceptance_id())? {
        require_exact_replay(&existing, request, issuer)?;
        transaction.commit()?;
        return Ok(existing);
    }

    let proposal = get_in_transaction(&transaction, request.handoff_id(), request.proposal_id())?
        .ok_or(Error::Conflict("abort proposal does not exist"))?;
    let preparation_id = proposal.request().preparation_id();
    let (preparation, _) =
        super::super::repository::read_record_with_inventory(&transaction, preparation_id)
            .map_err(|source| Error::HomeTransfer(Box::new(source)))?
            .ok_or(Error::Corrupt("abort proposal Prepared parent is missing"))?;
    let source_at = sample_clock()?;
    let record =
        HomeHandoffAcceptanceOutcomeRecord::from_parts(HomeHandoffAcceptanceOutcomeRecordParts {
            request: *request,
            authenticated_issuer: issuer,
            proposal,
            preparation,
            source_at,
            terminal: HomeHandoffAcceptanceTerminal::Aborted,
        })?;
    let _write = insert_outcome_in_transaction(&transaction, &record)?;
    transaction
        .commit()
        .map_err(|source| Error::CommitUnconfirmed {
            acceptance_id: request.acceptance_id(),
            source: Box::new(source),
        })?;

    let readback = get_terminal(
        connection,
        request.acceptance_id(),
        issuer,
        backend,
        destination,
    )
    .and_then(|outcome| outcome.ok_or(Error::Corrupt("committed abort is missing")))
    .and_then(|outcome| {
        if outcome == record {
            Ok(outcome)
        } else {
            Err(Error::Corrupt("committed abort differs from its readback"))
        }
    });
    readback.map_err(|source| Error::ReadbackRequired {
        acceptance_id: request.acceptance_id(),
        source: Box::new(source),
    })
}

/// Exact terminal read under the configured private service identity. Missing
/// history is neither an abort nor proof that a delayed Apply cannot arrive.
pub(crate) fn get_terminal(
    connection: &Connection,
    acceptance_id: Uuid,
    issuer: OrchestrationIssuerId,
    backend: ForgeBackendId,
    destination: Uuid,
) -> Result<Option<HomeHandoffAcceptanceOutcomeRecord>, Error> {
    let transaction = connection.unchecked_transaction()?;
    let outcome = get_outcome(&transaction, acceptance_id)?;
    if let Some(record) = &outcome {
        validate_service_scope(&record.request(), backend, destination)?;
        if record.issuer() != issuer {
            return Err(Error::Conflict("acceptance terminal issuer"));
        }
    }
    transaction.commit()?;
    Ok(outcome)
}

fn validate_service_scope(
    request: &HomeHandoffTakeRequest,
    backend: ForgeBackendId,
    destination: Uuid,
) -> Result<(), Error> {
    if request.scope().backend_id() != backend || request.scope().destination_id() != destination {
        return Err(Error::Conflict("acceptance terminal service scope"));
    }
    Ok(())
}

fn require_exact_replay(
    record: &HomeHandoffAcceptanceOutcomeRecord,
    request: &HomeHandoffTakeRequest,
    issuer: OrchestrationIssuerId,
) -> Result<(), Error> {
    if record.request() != *request || record.issuer() != issuer {
        return Err(Error::Conflict(
            "acceptance identity has different intent or issuer",
        ));
    }
    Ok(())
}
