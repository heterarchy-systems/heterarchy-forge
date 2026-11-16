//! Typed, deterministic Swarm run, member, workspace-mode, and settlement-target models.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;
use uuid::Uuid;

use crate::{DagNodeId, DagRevisionNumber, GoalId};

macro_rules! uuid_identity {
    ($name:ident, $error:ident, $message:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Uuid);

        impl $name {
            /// Wrap a validated UUID value as a typed identity.
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            /// Return the underlying UUID value.
            pub const fn into_uuid(self) -> Uuid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = $error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value)
                    .map(Self)
                    .map_err($error::InvalidUuid)
            }
        }

        #[derive(Debug, Error)]
        pub enum $error {
            #[error($message)]
            InvalidUuid(#[source] uuid::Error),
        }
    };
}

uuid_identity!(SwarmRunId, SwarmRunIdParseError, "invalid Swarm run UUID");
uuid_identity!(
    SwarmMemberId,
    SwarmMemberIdParseError,
    "invalid Swarm member UUID"
);

/// Workspace isolation mode assigned to a Swarm member.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SwarmWorkspaceMode {
    /// Read/verify-only view pinned to a baseline or converged candidate tree.
    Inherit,
    /// Isolated external worktree backed by `dag-store.git`.
    Share,
    /// Isolated standalone Git clone outside `<workspace_root>` with independent `.git` metadata.
    Branch,
}

impl SwarmWorkspaceMode {
    /// Return the canonical lowercase storage/wire tag for this mode.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inherit => "inherit",
            Self::Share => "share",
            Self::Branch => "branch",
        }
    }
}

impl fmt::Display for SwarmWorkspaceMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for SwarmWorkspaceMode {
    type Err = SwarmWorkspaceModeParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "inherit" => Ok(Self::Inherit),
            "share" => Ok(Self::Share),
            "branch" => Ok(Self::Branch),
            _ => Err(SwarmWorkspaceModeParseError {
                value: value.to_owned(),
            }),
        }
    }
}

/// Invalid Swarm workspace mode tag encountered while parsing.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("invalid Swarm workspace mode {value:?}")]
pub struct SwarmWorkspaceModeParseError {
    value: String,
}

/// Target authority boundary for Swarm convergence settlement.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwarmSettlementTarget {
    /// Standalone Swarm settles directly into `<workspace_root>` under Preimage CAS.
    StandaloneSwarm,
    /// Hybrid micro-swarm materializes into the owning DAG node's external worktree without mutating `<workspace_root>`.
    DagNodeHybrid {
        goal_id: GoalId,
        dag_revision: DagRevisionNumber,
        node_id: DagNodeId,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_mode_round_trips_and_rejects_unknown_tags() {
        for mode in [
            SwarmWorkspaceMode::Inherit,
            SwarmWorkspaceMode::Share,
            SwarmWorkspaceMode::Branch,
        ] {
            assert_eq!(SwarmWorkspaceMode::from_str(mode.as_str()), Ok(mode));
            assert_eq!(mode.to_string(), mode.as_str());
        }
        assert!(SwarmWorkspaceMode::from_str("unknown").is_err());
    }
}
