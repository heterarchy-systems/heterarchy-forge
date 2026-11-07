use std::error::Error;

use super::*;
use crate::{
    ActivityCoordinatorRevision, ActivityId, AgentInstanceId, AgentInstanceRevision,
    AgentSessionId, DirectTokenId, ForgeBackendId, OAuthGrantId, WorkspaceId, WorkspaceRevision,
};

type TestResult<T> = Result<T, Box<dyn Error>>;

fn id(seed: u128) -> Uuid {
    Uuid::from_u128(seed)
}

fn timestamp(value: i64) -> TestResult<TimestampMillis> {
    Ok(TimestampMillis::new(value)?)
}

#[derive(Clone, Copy)]
struct CoordinatorInput {
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    agent_id: AgentInstanceId,
    expected_revision: ActivityCoordinatorRevision,
    principal: AuthenticatedPrincipal,
    session_id: AgentSessionId,
}

fn coordinator(input: CoordinatorInput) -> ActivityCoordinatorActor {
    ActivityCoordinatorActor::new(
        input.workspace_id,
        input.activity_id,
        input.agent_id,
        input.expected_revision,
        input.principal,
        input.session_id,
    )
}

fn coordinator_input(seed: u128) -> TestResult<CoordinatorInput> {
    Ok(CoordinatorInput {
        workspace_id: WorkspaceId::from_uuid(id(seed)),
        activity_id: ActivityId::from_uuid(id(seed + 1)),
        agent_id: AgentInstanceId::from_uuid(id(seed + 2)),
        expected_revision: ActivityCoordinatorRevision::new(3)?,
        principal: AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(id(seed + 3))),
        session_id: AgentSessionId::from_uuid(id(seed + 4)),
    })
}

#[derive(Clone, Copy)]
struct RecipientInput {
    agent_id: AgentInstanceId,
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    agent_revision: AgentInstanceRevision,
}

fn recipient(input: RecipientInput) -> AgentAssignmentTarget {
    AgentAssignmentTarget::new(
        input.agent_id,
        input.session_id,
        input.principal,
        input.agent_revision,
    )
}

fn recipient_input(seed: u128) -> TestResult<RecipientInput> {
    Ok(RecipientInput {
        agent_id: AgentInstanceId::from_uuid(id(seed)),
        session_id: AgentSessionId::from_uuid(id(seed + 1)),
        principal: AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(id(seed + 2))),
        agent_revision: AgentInstanceRevision::new(4)?,
    })
}

#[derive(Clone, Copy)]
struct ProposalInput {
    proposal_id: Uuid,
    handoff_id: Uuid,
    preparation_id: Uuid,
    predecessor_id: AgentAssignmentId,
    predecessor_revision: AgentAssignmentRevision,
    successor_id: AgentAssignmentId,
    coordinator: CoordinatorInput,
    recipient: RecipientInput,
    artifact_id: Option<HomeArtifactId>,
    expected_case_revision: Option<i64>,
}

fn base_proposal_input() -> TestResult<ProposalInput> {
    Ok(ProposalInput {
        proposal_id: id(1),
        handoff_id: id(2),
        preparation_id: id(3),
        predecessor_id: AgentAssignmentId::from_uuid(id(4)),
        predecessor_revision: AgentAssignmentRevision::new(5)?,
        successor_id: AgentAssignmentId::from_uuid(id(6)),
        coordinator: coordinator_input(10)?,
        recipient: recipient_input(20)?,
        artifact_id: Some(HomeArtifactId::new(id(30))?),
        expected_case_revision: Some(7),
    })
}

fn build_proposal(
    input: &ProposalInput,
) -> Result<HomeHandoffProposalRequest, HomeHandoffDomainError> {
    HomeHandoffProposalRequest::new(
        input.proposal_id,
        input.handoff_id,
        input.preparation_id,
        input.predecessor_id,
        input.predecessor_revision,
        input.successor_id,
        coordinator(input.coordinator),
        recipient(input.recipient),
        input.artifact_id,
        input.expected_case_revision,
    )
}

#[derive(Clone, Copy)]
struct ScopeInput {
    workspace_id: Uuid,
    workspace_revision: i64,
    backend_id: Uuid,
    destination_id: Uuid,
}

fn base_scope_input() -> ScopeInput {
    ScopeInput {
        workspace_id: id(40),
        workspace_revision: 8,
        backend_id: id(41),
        destination_id: id(42),
    }
}

fn build_scope(input: ScopeInput) -> TestResult<HomeTransferSourceScope> {
    Ok(HomeTransferSourceScope::new(
        WorkspaceId::from_uuid(input.workspace_id),
        WorkspaceRevision::new(input.workspace_revision)?,
        ForgeBackendId::from_uuid(input.backend_id),
        input.destination_id,
    )?)
}

#[derive(Clone, Copy)]
struct TakeInput {
    acceptance_id: Uuid,
    handoff_id: Uuid,
    proposal_id: Uuid,
    expected_case_revision: i64,
    proposal_digest: HomeHandoffProposalRequestDigest,
    scope: HomeTransferSourceScope,
    recipient: RecipientInput,
}

fn base_take_input() -> TestResult<TakeInput> {
    Ok(TakeInput {
        acceptance_id: id(50),
        handoff_id: id(2),
        proposal_id: id(1),
        expected_case_revision: 7,
        proposal_digest: HomeHandoffProposalRequestDigest::from_bytes([0x71; DIGEST_BYTES])?,
        scope: build_scope(base_scope_input())?,
        recipient: recipient_input(60)?,
    })
}

fn build_take(input: TakeInput) -> Result<HomeHandoffTakeRequest, HomeHandoffDomainError> {
    HomeHandoffTakeRequest::new(
        input.acceptance_id,
        input.handoff_id,
        input.proposal_id,
        input.expected_case_revision,
        input.proposal_digest,
        input.scope,
        recipient(input.recipient),
    )
}

fn affinity_digest(value: u8) -> TestResult<HomeHandoffAffinityAdmissionReferenceDigest> {
    Ok(HomeHandoffAffinityAdmissionReferenceDigest::from_bytes(
        [value; DIGEST_BYTES],
    )?)
}

fn node_digest(value: u8) -> TestResult<HomeHandoffNodeBindingDigest> {
    Ok(HomeHandoffNodeBindingDigest::from_bytes(
        [value; DIGEST_BYTES],
    )?)
}

fn receipt_digest(value: u8) -> TestResult<HomeHandoffAcceptanceReceiptDigest> {
    Ok(HomeHandoffAcceptanceReceiptDigest::from_bytes(
        [value; DIGEST_BYTES],
    )?)
}

fn temporary_dispatch_authority(
    end_at: TimestampMillis,
) -> TestResult<HomeHandoffTemporaryDispatchAuthority> {
    Ok(HomeHandoffTemporaryDispatchAuthority::new(
        affinity_digest(1)?,
        id(71),
        id(72),
        2,
        3,
        node_digest(4)?,
        end_at,
    )?)
}

#[derive(Clone, Copy)]
struct GrantInput {
    issuer: OrchestrationIssuerId,
    take_request_digest: HomeHandoffTakeRequestDigest,
    acceptance_receipt_id: Uuid,
    acceptance_receipt_digest: HomeHandoffAcceptanceReceiptDigest,
    moving_profile_id: Uuid,
    recipient_profile_id: Uuid,
    recipient_participation: HomeHandoffRecipientParticipation,
    work_authority: HomeHandoffWorkAuthority,
    issued_at: TimestampMillis,
    expires_at: TimestampMillis,
}

fn build_grant(input: &GrantInput) -> Result<HomeHandoffAcceptanceGrant, HomeHandoffDomainError> {
    HomeHandoffAcceptanceGrant::new(
        input.issuer,
        input.take_request_digest,
        input.acceptance_receipt_id,
        input.acceptance_receipt_digest,
        input.moving_profile_id,
        input.recipient_profile_id,
        input.recipient_participation,
        input.work_authority,
        input.issued_at,
        input.expires_at,
    )
}

fn base_grant_input(
    request: &HomeHandoffTakeRequest,
    work_authority: HomeHandoffWorkAuthority,
) -> TestResult<GrantInput> {
    Ok(GrantInput {
        issuer: OrchestrationIssuerId::from_uuid(id(80)),
        take_request_digest: request.request_digest(),
        acceptance_receipt_id: id(81),
        acceptance_receipt_digest: receipt_digest(8)?,
        moving_profile_id: id(82),
        recipient_profile_id: id(83),
        recipient_participation: HomeHandoffRecipientParticipation::new(id(84), 5)?,
        work_authority,
        issued_at: timestamp(10)?,
        expires_at: timestamp(20)?,
    })
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "every immutable proposal input must remain digest-bound"
)]
fn proposal_snapshot_is_bounded_deterministic_and_binds_every_field() -> TestResult<()> {
    let base = base_proposal_input()?;
    let proposal = build_proposal(&base)?;
    let replay = build_proposal(&base)?;
    assert_eq!(proposal.canonical_snapshot().len(), PROPOSAL_SNAPSHOT_BYTES);
    assert!(proposal.canonical_snapshot().len() <= MAX_HOME_HANDOFF_REQUEST_SNAPSHOT_BYTES);
    assert_eq!(proposal.canonical_snapshot(), replay.canonical_snapshot());
    assert_eq!(proposal.request_digest(), replay.request_digest());

    let variants = [
        (
            "proposal id",
            ProposalInput {
                proposal_id: id(101),
                ..base
            },
        ),
        (
            "handoff id",
            ProposalInput {
                handoff_id: id(102),
                ..base
            },
        ),
        (
            "preparation id",
            ProposalInput {
                preparation_id: id(103),
                ..base
            },
        ),
        (
            "predecessor id",
            ProposalInput {
                predecessor_id: AgentAssignmentId::from_uuid(id(104)),
                ..base
            },
        ),
        (
            "predecessor revision",
            ProposalInput {
                predecessor_revision: AgentAssignmentRevision::new(6)?,
                ..base
            },
        ),
        (
            "successor id",
            ProposalInput {
                successor_id: AgentAssignmentId::from_uuid(id(105)),
                ..base
            },
        ),
        (
            "Coordinator Workspace",
            ProposalInput {
                coordinator: CoordinatorInput {
                    workspace_id: WorkspaceId::from_uuid(id(106)),
                    ..base.coordinator
                },
                ..base
            },
        ),
        (
            "Coordinator Activity",
            ProposalInput {
                coordinator: CoordinatorInput {
                    activity_id: ActivityId::from_uuid(id(107)),
                    ..base.coordinator
                },
                ..base
            },
        ),
        (
            "Coordinator Agent",
            ProposalInput {
                coordinator: CoordinatorInput {
                    agent_id: AgentInstanceId::from_uuid(id(108)),
                    ..base.coordinator
                },
                ..base
            },
        ),
        (
            "Coordinator Session",
            ProposalInput {
                coordinator: CoordinatorInput {
                    session_id: AgentSessionId::from_uuid(id(109)),
                    ..base.coordinator
                },
                ..base
            },
        ),
        (
            "Coordinator principal kind",
            ProposalInput {
                coordinator: CoordinatorInput {
                    principal: AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(id(
                        13,
                    ))),
                    ..base.coordinator
                },
                ..base
            },
        ),
        (
            "Coordinator principal identity",
            ProposalInput {
                coordinator: CoordinatorInput {
                    principal: AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(id(110))),
                    ..base.coordinator
                },
                ..base
            },
        ),
        (
            "Coordinator revision",
            ProposalInput {
                coordinator: CoordinatorInput {
                    expected_revision: ActivityCoordinatorRevision::new(4)?,
                    ..base.coordinator
                },
                ..base
            },
        ),
        (
            "recipient Agent",
            ProposalInput {
                recipient: RecipientInput {
                    agent_id: AgentInstanceId::from_uuid(id(111)),
                    ..base.recipient
                },
                ..base
            },
        ),
        (
            "recipient Session",
            ProposalInput {
                recipient: RecipientInput {
                    session_id: AgentSessionId::from_uuid(id(112)),
                    ..base.recipient
                },
                ..base
            },
        ),
        (
            "recipient principal kind",
            ProposalInput {
                recipient: RecipientInput {
                    principal: AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(id(
                        22,
                    ))),
                    ..base.recipient
                },
                ..base
            },
        ),
        (
            "recipient principal identity",
            ProposalInput {
                recipient: RecipientInput {
                    principal: AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(id(113))),
                    ..base.recipient
                },
                ..base
            },
        ),
        (
            "recipient Agent revision",
            ProposalInput {
                recipient: RecipientInput {
                    agent_revision: AgentInstanceRevision::new(5)?,
                    ..base.recipient
                },
                ..base
            },
        ),
        (
            "artifact identity",
            ProposalInput {
                artifact_id: Some(HomeArtifactId::new(id(31))?),
                ..base
            },
        ),
        (
            "artifact presence",
            ProposalInput {
                artifact_id: None,
                ..base
            },
        ),
        (
            "case-head revision value",
            ProposalInput {
                expected_case_revision: Some(8),
                ..base
            },
        ),
        (
            "case-head revision presence",
            ProposalInput {
                expected_case_revision: None,
                ..base
            },
        ),
    ];
    for (field, input) in variants {
        let changed = build_proposal(&input)?;
        assert_ne!(
            changed.request_digest(),
            proposal.request_digest(),
            "{field} substitution escaped the proposal digest"
        );
        assert_ne!(changed.canonical_snapshot(), proposal.canonical_snapshot());
    }
    Ok(())
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "every immutable take input must remain digest-bound"
)]
fn take_snapshot_is_bounded_deterministic_and_binds_every_field() -> TestResult<()> {
    let base = base_take_input()?;
    let request = build_take(base)?;
    let replay = build_take(base)?;
    assert_eq!(request.canonical_snapshot().len(), TAKE_SNAPSHOT_BYTES);
    assert!(request.canonical_snapshot().len() <= MAX_HOME_HANDOFF_REQUEST_SNAPSHOT_BYTES);
    assert_eq!(request.canonical_snapshot(), replay.canonical_snapshot());
    assert_eq!(request.request_digest(), replay.request_digest());

    let variants = [
        (
            "acceptance id",
            TakeInput {
                acceptance_id: id(201),
                ..base
            },
        ),
        (
            "handoff id",
            TakeInput {
                handoff_id: id(202),
                ..base
            },
        ),
        (
            "proposal id",
            TakeInput {
                proposal_id: id(203),
                ..base
            },
        ),
        (
            "case-head revision",
            TakeInput {
                expected_case_revision: 8,
                ..base
            },
        ),
        (
            "proposal digest",
            TakeInput {
                proposal_digest: HomeHandoffProposalRequestDigest::from_bytes(
                    [0x72; DIGEST_BYTES],
                )?,
                ..base
            },
        ),
        (
            "Workspace identity",
            TakeInput {
                scope: build_scope(ScopeInput {
                    workspace_id: id(204),
                    ..base_scope_input()
                })?,
                ..base
            },
        ),
        (
            "Workspace revision",
            TakeInput {
                scope: build_scope(ScopeInput {
                    workspace_revision: 9,
                    ..base_scope_input()
                })?,
                ..base
            },
        ),
        (
            "Forge backend",
            TakeInput {
                scope: build_scope(ScopeInput {
                    backend_id: id(205),
                    ..base_scope_input()
                })?,
                ..base
            },
        ),
        (
            "Orchestration destination",
            TakeInput {
                scope: build_scope(ScopeInput {
                    destination_id: id(206),
                    ..base_scope_input()
                })?,
                ..base
            },
        ),
        (
            "recipient Agent",
            TakeInput {
                recipient: RecipientInput {
                    agent_id: AgentInstanceId::from_uuid(id(207)),
                    ..base.recipient
                },
                ..base
            },
        ),
        (
            "recipient Session",
            TakeInput {
                recipient: RecipientInput {
                    session_id: AgentSessionId::from_uuid(id(208)),
                    ..base.recipient
                },
                ..base
            },
        ),
        (
            "recipient principal kind",
            TakeInput {
                recipient: RecipientInput {
                    principal: AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(id(
                        62,
                    ))),
                    ..base.recipient
                },
                ..base
            },
        ),
        (
            "recipient principal identity",
            TakeInput {
                recipient: RecipientInput {
                    principal: AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(id(209))),
                    ..base.recipient
                },
                ..base
            },
        ),
        (
            "recipient Agent revision",
            TakeInput {
                recipient: RecipientInput {
                    agent_revision: AgentInstanceRevision::new(5)?,
                    ..base.recipient
                },
                ..base
            },
        ),
    ];
    for (field, input) in variants {
        let changed = build_take(input)?;
        assert_ne!(
            changed.request_digest(),
            request.request_digest(),
            "{field} substitution escaped the take digest"
        );
        assert_ne!(changed.canonical_snapshot(), request.canonical_snapshot());
    }
    Ok(())
}

#[test]
fn take_request_snapshot_round_trips_each_principal_kind() -> TestResult<()> {
    let base = base_take_input()?;
    for principal in [
        AuthenticatedPrincipal::TrustedStdio,
        AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(id(220))),
        AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(id(221))),
    ] {
        let request = build_take(TakeInput {
            recipient: RecipientInput {
                principal,
                ..base.recipient
            },
            ..base
        })?;
        let snapshot = request.canonical_snapshot();
        let decoded = HomeHandoffTakeRequest::from_canonical_snapshot(&snapshot)?;
        assert_eq!(decoded, request);
        assert_eq!(decoded.request_digest(), request.request_digest());
        assert_eq!(decoded.canonical_snapshot(), snapshot);
    }
    Ok(())
}

#[test]
fn take_request_snapshot_rejects_bad_framing_padding_ids_and_revisions() -> TestResult<()> {
    let base = base_take_input()?;
    let trusted = build_take(TakeInput {
        recipient: RecipientInput {
            principal: AuthenticatedPrincipal::TrustedStdio,
            ..base.recipient
        },
        ..base
    })?;
    let snapshot = trusted.canonical_snapshot();

    assert_eq!(
        HomeHandoffTakeRequest::from_canonical_snapshot(&snapshot[..snapshot.len() - 1]),
        Err(HomeHandoffTakeRequestSnapshotError::InvalidSnapshot)
    );
    let mut extra_byte = snapshot.clone();
    extra_byte.push(0);
    assert_eq!(
        HomeHandoffTakeRequest::from_canonical_snapshot(&extra_byte),
        Err(HomeHandoffTakeRequestSnapshotError::TooLarge)
    );

    let mut wrong_version = snapshot.clone();
    wrong_version[4] = 2;
    assert_eq!(
        HomeHandoffTakeRequest::from_canonical_snapshot(&wrong_version),
        Err(HomeHandoffTakeRequestSnapshotError::InvalidSnapshot)
    );
    let mut wrong_principal_tag = snapshot.clone();
    wrong_principal_tag[181] = 3;
    assert_eq!(
        HomeHandoffTakeRequest::from_canonical_snapshot(&wrong_principal_tag),
        Err(HomeHandoffTakeRequestSnapshotError::InvalidSnapshot)
    );
    let mut noncanonical_padding = snapshot.clone();
    noncanonical_padding[182] = 1;
    assert_eq!(
        HomeHandoffTakeRequest::from_canonical_snapshot(&noncanonical_padding),
        Err(HomeHandoffTakeRequestSnapshotError::NonCanonical)
    );

    let mut nil_acceptance_id = snapshot.clone();
    nil_acceptance_id[5..21].copy_from_slice(Uuid::nil().as_bytes());
    assert_eq!(
        HomeHandoffTakeRequest::from_canonical_snapshot(&nil_acceptance_id),
        Err(HomeHandoffTakeRequestSnapshotError::InvalidRequest(
            HomeHandoffDomainError::NilIdentity("acceptance")
        ))
    );
    let mut nil_recipient_agent_id = snapshot.clone();
    nil_recipient_agent_id[149..165].copy_from_slice(Uuid::nil().as_bytes());
    assert_eq!(
        HomeHandoffTakeRequest::from_canonical_snapshot(&nil_recipient_agent_id),
        Err(HomeHandoffTakeRequestSnapshotError::InvalidRequest(
            HomeHandoffDomainError::NilIdentity("recipient Agent")
        ))
    );

    let mut invalid_case_revision = snapshot.clone();
    invalid_case_revision[53..61].copy_from_slice(&0_i64.to_be_bytes());
    assert_eq!(
        HomeHandoffTakeRequest::from_canonical_snapshot(&invalid_case_revision),
        Err(HomeHandoffTakeRequestSnapshotError::InvalidRequest(
            HomeHandoffDomainError::InvalidRevision("proposal case head")
        ))
    );
    let mut invalid_agent_revision = snapshot;
    invalid_agent_revision[198..206].copy_from_slice(&0_i64.to_be_bytes());
    assert_eq!(
        HomeHandoffTakeRequest::from_canonical_snapshot(&invalid_agent_revision),
        Err(HomeHandoffTakeRequestSnapshotError::InvalidRecipientAgentRevision)
    );
    Ok(())
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "identity and revision rejection must cover both request boundaries"
)]
fn proposal_and_take_constructors_reject_nil_identities_and_nonpositive_case_revisions()
-> TestResult<()> {
    let base = base_proposal_input()?;
    for input in [
        ProposalInput {
            proposal_id: Uuid::nil(),
            ..base
        },
        ProposalInput {
            handoff_id: Uuid::nil(),
            ..base
        },
        ProposalInput {
            preparation_id: Uuid::nil(),
            ..base
        },
        ProposalInput {
            predecessor_id: AgentAssignmentId::from_uuid(Uuid::nil()),
            ..base
        },
        ProposalInput {
            successor_id: AgentAssignmentId::from_uuid(Uuid::nil()),
            ..base
        },
        ProposalInput {
            coordinator: CoordinatorInput {
                workspace_id: WorkspaceId::from_uuid(Uuid::nil()),
                ..base.coordinator
            },
            ..base
        },
        ProposalInput {
            coordinator: CoordinatorInput {
                activity_id: ActivityId::from_uuid(Uuid::nil()),
                ..base.coordinator
            },
            ..base
        },
        ProposalInput {
            coordinator: CoordinatorInput {
                agent_id: AgentInstanceId::from_uuid(Uuid::nil()),
                ..base.coordinator
            },
            ..base
        },
        ProposalInput {
            coordinator: CoordinatorInput {
                session_id: AgentSessionId::from_uuid(Uuid::nil()),
                ..base.coordinator
            },
            ..base
        },
        ProposalInput {
            coordinator: CoordinatorInput {
                principal: AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(
                    Uuid::nil(),
                )),
                ..base.coordinator
            },
            ..base
        },
        ProposalInput {
            recipient: RecipientInput {
                agent_id: AgentInstanceId::from_uuid(Uuid::nil()),
                ..base.recipient
            },
            ..base
        },
        ProposalInput {
            recipient: RecipientInput {
                session_id: AgentSessionId::from_uuid(Uuid::nil()),
                ..base.recipient
            },
            ..base
        },
        ProposalInput {
            recipient: RecipientInput {
                principal: AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(Uuid::nil())),
                ..base.recipient
            },
            ..base
        },
    ] {
        assert!(matches!(
            build_proposal(&input),
            Err(HomeHandoffDomainError::NilIdentity(_))
        ));
    }
    assert_eq!(
        build_proposal(&ProposalInput {
            successor_id: base.predecessor_id,
            ..base
        }),
        Err(HomeHandoffDomainError::SuccessorEqualsPredecessor)
    );
    for expected_case_revision in [Some(0), Some(-1)] {
        assert!(matches!(
            build_proposal(&ProposalInput {
                expected_case_revision,
                ..base
            }),
            Err(HomeHandoffDomainError::InvalidRevision(
                "proposal case head"
            ))
        ));
    }

    let take = base_take_input()?;
    for input in [
        TakeInput {
            acceptance_id: Uuid::nil(),
            ..take
        },
        TakeInput {
            handoff_id: Uuid::nil(),
            ..take
        },
        TakeInput {
            proposal_id: Uuid::nil(),
            ..take
        },
        TakeInput {
            recipient: RecipientInput {
                agent_id: AgentInstanceId::from_uuid(Uuid::nil()),
                ..take.recipient
            },
            ..take
        },
        TakeInput {
            recipient: RecipientInput {
                session_id: AgentSessionId::from_uuid(Uuid::nil()),
                ..take.recipient
            },
            ..take
        },
        TakeInput {
            recipient: RecipientInput {
                principal: AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(Uuid::nil())),
                ..take.recipient
            },
            ..take
        },
    ] {
        assert!(matches!(
            build_take(input),
            Err(HomeHandoffDomainError::NilIdentity(_))
        ));
    }
    for expected_case_revision in [0, -1] {
        assert!(matches!(
            build_take(TakeInput {
                expected_case_revision,
                ..take
            }),
            Err(HomeHandoffDomainError::InvalidRevision(
                "proposal case head"
            ))
        ));
    }
    assert!(matches!(
        HomeHandoffProposalRequestDigest::from_bytes([0; DIGEST_BYTES]),
        Err(HomeHandoffDomainError::EmptyDigest("proposal request"))
    ));
    assert!(matches!(
        HomeHandoffTakeRequestDigest::from_bytes([0; DIGEST_BYTES]),
        Err(HomeHandoffDomainError::EmptyDigest("take request"))
    ));
    Ok(())
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "each typed organizational authority has independent identity and revision guards"
)]
fn work_authority_and_receipt_inputs_reject_nil_ids_zero_revisions_and_empty_digests()
-> TestResult<()> {
    assert!(matches!(
        HomeHandoffAffinityAdmissionReferenceDigest::from_bytes([0; DIGEST_BYTES]),
        Err(HomeHandoffDomainError::EmptyDigest(
            "affinity/admission reference"
        ))
    ));
    assert!(matches!(
        HomeHandoffNodeBindingDigest::from_bytes([0; DIGEST_BYTES]),
        Err(HomeHandoffDomainError::EmptyDigest("Node binding"))
    ));
    assert!(matches!(
        HomeHandoffAcceptanceReceiptDigest::from_bytes([0; DIGEST_BYTES]),
        Err(HomeHandoffDomainError::EmptyDigest("acceptance receipt"))
    ));
    assert!(matches!(
        HomeHandoffRecipientParticipation::new(Uuid::nil(), 1),
        Err(HomeHandoffDomainError::NilIdentity(
            "recipient participation"
        ))
    ));
    assert!(matches!(
        HomeHandoffRecipientParticipation::new(id(1), 0),
        Err(HomeHandoffDomainError::InvalidRevision(
            "recipient participation"
        ))
    ));

    let affinity = affinity_digest(1)?;
    let node = node_digest(2)?;
    assert!(matches!(
        HomeHandoffHomeTeamAuthority::new(affinity, Uuid::nil(), 1, 1, node),
        Err(HomeHandoffDomainError::NilIdentity("Home Team"))
    ));
    assert!(matches!(
        HomeHandoffHomeTeamAuthority::new(affinity, id(3), 0, 1, node),
        Err(HomeHandoffDomainError::InvalidRevision(
            "Home Team membership"
        ))
    ));
    assert!(matches!(
        HomeHandoffHomeTeamAuthority::new(affinity, id(3), 1, 0, node),
        Err(HomeHandoffDomainError::InvalidRevision(
            "Home Team Node binding"
        ))
    ));

    assert!(matches!(
        HomeHandoffTemporaryDispatchAuthority::new(
            affinity,
            Uuid::nil(),
            id(4),
            1,
            1,
            node,
            timestamp(20)?,
        ),
        Err(HomeHandoffDomainError::NilIdentity("Temporary Dispatch"))
    ));
    assert!(matches!(
        HomeHandoffTemporaryDispatchAuthority::new(
            affinity,
            id(4),
            Uuid::nil(),
            1,
            1,
            node,
            timestamp(20)?,
        ),
        Err(HomeHandoffDomainError::NilIdentity(
            "Temporary Dispatch destination Team"
        ))
    ));
    assert!(matches!(
        HomeHandoffTemporaryDispatchAuthority::new(
            affinity,
            id(4),
            id(5),
            0,
            1,
            node,
            timestamp(20)?,
        ),
        Err(HomeHandoffDomainError::InvalidRevision(
            "Temporary Dispatch reservation/authority"
        ))
    ));
    assert!(matches!(
        HomeHandoffTemporaryDispatchAuthority::new(
            affinity,
            id(4),
            id(5),
            1,
            0,
            node,
            timestamp(20)?,
        ),
        Err(HomeHandoffDomainError::InvalidRevision(
            "Temporary Dispatch Node binding"
        ))
    ));
    Ok(())
}

#[test]
fn acceptance_grant_checks_issuer_request_profiles_participation_and_window() -> TestResult<()> {
    let request = build_take(base_take_input()?)?;
    let affinity = affinity_digest(3)?;
    let work_authority = HomeHandoffWorkAuthority::WorkspaceWork {
        affinity_admission_reference_digest: affinity,
    };
    let base = base_grant_input(&request, work_authority)?;
    let grant = build_grant(&base)?;
    assert_eq!(
        grant.validate_for(base.issuer, &request, base.issued_at),
        Ok(())
    );
    let home_team = HomeHandoffWorkAuthority::HomeTeam(HomeHandoffHomeTeamAuthority::new(
        affinity_digest(3)?,
        id(85),
        6,
        7,
        node_digest(4)?,
    )?);
    let home_team_grant_input = base_grant_input(&request, home_team)?;
    let home_team_grant = build_grant(&home_team_grant_input)?;
    assert_eq!(
        home_team_grant.validate_for(base.issuer, &request, base.issued_at),
        Ok(())
    );
    assert_eq!(
        grant.validate_for(
            OrchestrationIssuerId::from_uuid(id(99)),
            &request,
            base.issued_at
        ),
        Err(HomeHandoffDomainError::IssuerMismatch)
    );
    let changed_request = build_take(TakeInput {
        acceptance_id: id(51),
        ..base_take_input()?
    })?;
    assert_eq!(
        grant.validate_for(base.issuer, &changed_request, base.issued_at),
        Err(HomeHandoffDomainError::RequestDigestMismatch)
    );
    assert_eq!(
        grant.validate_for(base.issuer, &request, timestamp(9)?),
        Err(HomeHandoffDomainError::NotYetValid)
    );
    assert_eq!(
        grant.validate_for(base.issuer, &request, base.expires_at),
        Err(HomeHandoffDomainError::Expired)
    );
    Ok(())
}

#[test]
fn acceptance_grant_rejects_invalid_identity_and_window() -> TestResult<()> {
    let request = build_take(base_take_input()?)?;
    let work_authority = HomeHandoffWorkAuthority::WorkspaceWork {
        affinity_admission_reference_digest: affinity_digest(3)?,
    };
    let base = base_grant_input(&request, work_authority)?;
    assert_eq!(
        build_grant(&GrantInput {
            issuer: OrchestrationIssuerId::from_uuid(Uuid::nil()),
            ..base
        }),
        Err(HomeHandoffDomainError::NilIdentity("Orchestration issuer"))
    );
    assert_eq!(
        build_grant(&GrantInput {
            acceptance_receipt_id: Uuid::nil(),
            ..base
        }),
        Err(HomeHandoffDomainError::NilIdentity("acceptance receipt"))
    );
    assert_eq!(
        build_grant(&GrantInput {
            moving_profile_id: Uuid::nil(),
            ..base
        }),
        Err(HomeHandoffDomainError::NilIdentity("moving Profile"))
    );
    assert_eq!(
        build_grant(&GrantInput {
            recipient_profile_id: Uuid::nil(),
            ..base
        }),
        Err(HomeHandoffDomainError::NilIdentity("recipient Profile"))
    );
    assert_eq!(
        build_grant(&GrantInput {
            recipient_profile_id: base.moving_profile_id,
            ..base
        }),
        Err(HomeHandoffDomainError::ProfilesMustDiffer)
    );
    assert_eq!(
        build_grant(&GrantInput {
            issued_at: base.expires_at,
            ..base
        }),
        Err(HomeHandoffDomainError::InvalidGrantWindow)
    );
    let longer_workspace_work_window = build_grant(&GrantInput {
        expires_at: timestamp(21)?,
        ..base
    })?;
    assert_eq!(
        longer_workspace_work_window.validate_for(base.issuer, &request, timestamp(20)?),
        Ok(())
    );
    assert_eq!(
        longer_workspace_work_window.validate_for(base.issuer, &request, timestamp(21)?),
        Err(HomeHandoffDomainError::Expired)
    );
    assert_eq!(
        build_grant(&GrantInput {
            issued_at: timestamp(21)?,
            expires_at: timestamp(20)?,
            ..base
        }),
        Err(HomeHandoffDomainError::InvalidGrantWindow)
    );
    Ok(())
}

#[test]
fn temporary_dispatch_is_valid_before_end_and_rejected_at_or_after_end() -> TestResult<()> {
    let request = build_take(base_take_input()?)?;
    let authority =
        HomeHandoffWorkAuthority::TemporaryDispatch(temporary_dispatch_authority(timestamp(20)?)?);
    let input = base_grant_input(&request, authority)?;
    let grant = build_grant(&input)?;
    assert_eq!(grant.expires_at(), timestamp(20)?);
    assert_eq!(
        grant.validate_for(input.issuer, &request, timestamp(19)?),
        Ok(())
    );
    assert_eq!(
        grant.validate_for(input.issuer, &request, timestamp(20)?),
        Err(HomeHandoffDomainError::TemporaryDispatchEnded)
    );
    assert_eq!(
        grant.validate_for(input.issuer, &request, timestamp(21)?),
        Err(HomeHandoffDomainError::TemporaryDispatchEnded)
    );
    assert!(matches!(
        build_grant(&GrantInput {
            expires_at: timestamp(21)?,
            ..input
        }),
        Err(HomeHandoffDomainError::GrantExceedsTemporaryDispatchEnd)
    ));
    Ok(())
}
