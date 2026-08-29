//! Bounded single-owner worker for the app-global Harness Library.
//!
//! The Slint thread never opens the Catalog database or inspects Bundle files.
//! It submits typed actions here and polls one-shot replies from the UI pump.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use forge_control::{HarnessCompositionRequest, HarnessLibrary, HarnessLibraryError};
use forge_domain::{
    HarnessBundleId, HarnessRevision, HarnessSkillId, HarnessSkillRevision, TimestampMillis,
};
use forge_persistence::{HarnessCatalogEntry, HarnessSkillCatalogEntry};
use thiserror::Error;

const REQUEST_QUEUE_CAPACITY: usize = 8;
const THREAD_NAME: &str = "heterarchy-forge-harness-library";
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(50);

type Reply = Result<HarnessWorkerOutcome, HarnessWorkerError>;

#[derive(Debug)]
pub(crate) enum HarnessWorkerAction {
    List,
    Register {
        source_root: PathBuf,
        observed_at: TimestampMillis,
    },
    Refresh {
        id: HarnessBundleId,
        expected_revision: HarnessRevision,
        observed_at: TimestampMillis,
    },
    ListSkills,
    RegisterSkill {
        source_root: PathBuf,
        observed_at: TimestampMillis,
    },
    RefreshSkill {
        id: HarnessSkillId,
        expected_revision: HarnessSkillRevision,
        observed_at: TimestampMillis,
    },
    SaveComposition {
        request: HarnessCompositionRequest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HarnessWorkerOutcome {
    Listed(Vec<HarnessCatalogEntry>),
    Registered(HarnessCatalogEntry),
    Refreshed(HarnessCatalogEntry),
    SkillsListed(Vec<HarnessSkillCatalogEntry>),
    SkillRegistered(HarnessSkillCatalogEntry),
    SkillRefreshed(HarnessSkillCatalogEntry),
    CompositionSaved(HarnessCatalogEntry),
}

#[derive(Debug, Error)]
pub(crate) enum HarnessWorkerError {
    #[error(transparent)]
    Library(#[from] HarnessLibraryError),
    #[error("Harness Library worker queue is full")]
    QueueFull,
    #[error("Harness Library worker is unavailable")]
    Unavailable,
    #[error("Harness Library worker is shutting down")]
    ShuttingDown,
    #[error("failed to spawn Harness Library worker")]
    ThreadSpawn(#[source] io::Error),
    #[error("Harness Library worker thread panicked")]
    ThreadPanicked,
}

#[derive(Debug)]
pub(crate) struct PendingHarnessRequest {
    receiver: Receiver<Reply>,
}

impl PendingHarnessRequest {
    pub(crate) fn try_recv(&self) -> Result<Option<Reply>, HarnessWorkerError> {
        match self.receiver.try_recv() {
            Ok(reply) => Ok(Some(reply)),
            Err(std::sync::mpsc::TryRecvError::Empty) => Ok(None),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                Err(HarnessWorkerError::Unavailable)
            }
        }
    }
}

#[derive(Debug)]
struct WorkRequest {
    action: HarnessWorkerAction,
    response: SyncSender<Reply>,
}

#[derive(Debug, Clone)]
pub(crate) struct HarnessLibraryClient {
    sender: SyncSender<WorkRequest>,
    accepting: Arc<AtomicBool>,
}

impl HarnessLibraryClient {
    pub(crate) fn submit(
        &self,
        action: HarnessWorkerAction,
    ) -> Result<PendingHarnessRequest, HarnessWorkerError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(HarnessWorkerError::ShuttingDown);
        }
        let (response, receiver) = mpsc::sync_channel(1);
        match self.sender.try_send(WorkRequest { action, response }) {
            Ok(()) => Ok(PendingHarnessRequest { receiver }),
            Err(TrySendError::Full(_)) => Err(HarnessWorkerError::QueueFull),
            Err(TrySendError::Disconnected(_)) => Err(HarnessWorkerError::Unavailable),
        }
    }
}

#[derive(Debug)]
pub(crate) struct HarnessLibraryWorker {
    client: HarnessLibraryClient,
    sender_guard: Option<SyncSender<WorkRequest>>,
    thread: Option<JoinHandle<()>>,
}

impl HarnessLibraryWorker {
    pub(crate) fn start(library: HarnessLibrary) -> Result<Self, HarnessWorkerError> {
        let (sender, receiver) = mpsc::sync_channel(REQUEST_QUEUE_CAPACITY);
        let accepting = Arc::new(AtomicBool::new(true));
        let runtime_accepting = Arc::clone(&accepting);
        let thread = thread::Builder::new()
            .name(THREAD_NAME.to_owned())
            .spawn(move || run_worker(library, &receiver, &runtime_accepting))
            .map_err(HarnessWorkerError::ThreadSpawn)?;
        Ok(Self {
            client: HarnessLibraryClient {
                sender: sender.clone(),
                accepting,
            },
            sender_guard: Some(sender),
            thread: Some(thread),
        })
    }

    pub(crate) fn client(&self) -> HarnessLibraryClient {
        self.client.clone()
    }

    pub(crate) fn shutdown(&mut self) -> Result<(), HarnessWorkerError> {
        self.client.accepting.store(false, Ordering::Release);
        self.sender_guard.take();
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        thread
            .join()
            .map_err(|_| HarnessWorkerError::ThreadPanicked)
    }
}

impl Drop for HarnessLibraryWorker {
    fn drop(&mut self) {
        self.client.accepting.store(false, Ordering::Release);
        self.sender_guard.take();
        if let Some(thread) = self.thread.take() {
            let _ignored = thread.join();
        }
    }
}

fn run_worker(
    mut library: HarnessLibrary,
    receiver: &Receiver<WorkRequest>,
    accepting: &Arc<AtomicBool>,
) {
    while accepting.load(Ordering::Acquire) {
        let request = match receiver.recv_timeout(SHUTDOWN_POLL_INTERVAL) {
            Ok(request) => request,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        let result = run_action(&mut library, request.action);
        let _ignored = request.response.send(result);
    }
    accepting.store(false, Ordering::Release);
    while let Ok(request) = receiver.try_recv() {
        let _ignored = request.response.send(Err(HarnessWorkerError::ShuttingDown));
    }
}

fn run_action(library: &mut HarnessLibrary, action: HarnessWorkerAction) -> Reply {
    match action {
        HarnessWorkerAction::List => library
            .list()
            .map(HarnessWorkerOutcome::Listed)
            .map_err(HarnessWorkerError::from),
        HarnessWorkerAction::Register {
            source_root,
            observed_at,
        } => library
            .register_path(&source_root, observed_at)
            .map(HarnessWorkerOutcome::Registered)
            .map_err(HarnessWorkerError::from),
        HarnessWorkerAction::Refresh {
            id,
            expected_revision,
            observed_at,
        } => library
            .refresh_bundle(id, expected_revision, observed_at)
            .map(HarnessWorkerOutcome::Refreshed)
            .map_err(HarnessWorkerError::from),
        HarnessWorkerAction::ListSkills => library
            .list_skills()
            .map(HarnessWorkerOutcome::SkillsListed)
            .map_err(HarnessWorkerError::from),
        HarnessWorkerAction::RegisterSkill {
            source_root,
            observed_at,
        } => library
            .register_skill_path(&source_root, observed_at)
            .map(HarnessWorkerOutcome::SkillRegistered)
            .map_err(HarnessWorkerError::from),
        HarnessWorkerAction::RefreshSkill {
            id,
            expected_revision,
            observed_at,
        } => library
            .refresh_skill(id, expected_revision, observed_at)
            .map(HarnessWorkerOutcome::SkillRefreshed)
            .map_err(HarnessWorkerError::from),
        HarnessWorkerAction::SaveComposition { request } => library
            .save_composition(&request)
            .map(HarnessWorkerOutcome::CompositionSaved)
            .map_err(HarnessWorkerError::from),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use forge_control::{HarnessCompositionRequest, HarnessCompositionSkillSelection};
    use forge_domain::{HarnessBundleId, HarnessName, HarnessVersion};
    use forge_persistence::HarnessCatalog;
    use forge_workspace::{HARNESS_SKILL_ENTRY_FILE, HarnessCompositionIdentity};
    use uuid::Uuid;

    use super::*;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    fn source_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-harness-worker-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("rules"))?;
        fs::write(root.join("rules/base.md"), b"# Rules\n")?;
        fs::write(
            root.join(forge_workspace::HARNESS_MANIFEST_FILE_NAME),
            format!(
                "[harness]\nid = \"{}\"\nname = \"Worker Harness\"\nversion = \"1.0.0\"\ninstall_root = \".agents/worker_harness\"\nmanaged_files = [\"rules/base.md\"]\nskills = []\n",
                Uuid::from_u128(0x4200 + u128::from(serial))
            ),
        )?;
        Ok(root)
    }

    fn skill_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-harness-worker-skill-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("references"))?;
        fs::write(root.join(HARNESS_SKILL_ENTRY_FILE), b"# Optional Skill\n")?;
        fs::write(root.join("references/guide.md"), b"# Guide\n")?;
        Ok(root)
    }

    fn recv(pending: &PendingHarnessRequest) -> Result<Reply, HarnessWorkerError> {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(reply) = pending.try_recv()? {
                return Ok(reply);
            }
            if std::time::Instant::now() >= deadline {
                return Err(HarnessWorkerError::Unavailable);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn bounded_worker_registers_and_lists_without_detached_work()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = source_root()?;
        let database = source
            .parent()
            .ok_or("fixture parent missing")?
            .join(format!(
                "harness-worker-{}-{}.sqlite3",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
        let library = HarnessLibrary::new(HarnessCatalog::open(&database)?);
        let mut worker = HarnessLibraryWorker::start(library)?;
        let client = worker.client();
        let registered = recv(&client.submit(HarnessWorkerAction::Register {
            source_root: source.clone(),
            observed_at: TimestampMillis::new(10)?,
        })?)??;
        let HarnessWorkerOutcome::Registered(registered) = registered else {
            return Err("unexpected registration outcome".into());
        };
        let listed = recv(&client.submit(HarnessWorkerAction::List)?)??;
        assert_eq!(
            listed,
            HarnessWorkerOutcome::Listed(vec![registered.clone()])
        );
        fs::write(source.join("rules/base.md"), b"# Updated rules\n")?;
        let refreshed = recv(&client.submit(HarnessWorkerAction::Refresh {
            id: registered.bundle().descriptor().id(),
            expected_revision: registered.bundle().revision(),
            observed_at: TimestampMillis::new(11)?,
        })?)??;
        let HarnessWorkerOutcome::Refreshed(refreshed) = refreshed else {
            return Err("unexpected refresh outcome".into());
        };
        assert_eq!(refreshed.bundle().revision().get(), 2);
        assert_ne!(
            refreshed.bundle().descriptor().content_hash(),
            registered.bundle().descriptor().content_hash()
        );
        let shutdown_started = Instant::now();
        worker.shutdown()?;
        assert!(shutdown_started.elapsed() < Duration::from_secs(1));
        assert!(matches!(
            client.submit(HarnessWorkerAction::List),
            Err(HarnessWorkerError::ShuttingDown)
        ));
        drop(worker);
        fs::remove_dir_all(source)?;
        fs::remove_file(database)?;
        Ok(())
    }

    #[test]
    fn bounded_worker_handles_skill_composition_and_rejects_after_shutdown()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = source_root()?;
        let skill_source = skill_root()?;
        let saved_root = std::env::temp_dir().join(format!(
            "heterarchy-forge-harness-worker-saved-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        let database = source
            .parent()
            .ok_or("fixture parent missing")?
            .join(format!(
                "harness-worker-composition-{}-{}.sqlite3",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
        let library = HarnessLibrary::with_saved_harness_bundles_root(
            HarnessCatalog::open(&database)?,
            saved_root.clone(),
        );
        let mut worker = HarnessLibraryWorker::start(library)?;
        let client = worker.client();

        let registered = recv(&client.submit(HarnessWorkerAction::Register {
            source_root: source.clone(),
            observed_at: TimestampMillis::new(10)?,
        })?)??;
        let HarnessWorkerOutcome::Registered(base) = registered else {
            return Err("unexpected base registration outcome".into());
        };
        let initial_skills = recv(&client.submit(HarnessWorkerAction::ListSkills)?)??;
        assert_eq!(
            initial_skills,
            HarnessWorkerOutcome::SkillsListed(Vec::new())
        );

        let registered_skill = recv(&client.submit(HarnessWorkerAction::RegisterSkill {
            source_root: skill_source.clone(),
            observed_at: TimestampMillis::new(10)?,
        })?)??;
        let HarnessWorkerOutcome::SkillRegistered(skill) = registered_skill else {
            return Err("unexpected Skill registration outcome".into());
        };
        let listed_skills = recv(&client.submit(HarnessWorkerAction::ListSkills)?)??;
        assert_eq!(
            listed_skills,
            HarnessWorkerOutcome::SkillsListed(vec![skill.clone()])
        );
        fs::write(skill_source.join("references/guide.md"), b"# Changed\n")?;
        let refreshed_skill = recv(&client.submit(HarnessWorkerAction::RefreshSkill {
            id: skill.skill().descriptor().id(),
            expected_revision: skill.skill().revision(),
            observed_at: TimestampMillis::new(11)?,
        })?)??;
        let HarnessWorkerOutcome::SkillRefreshed(skill) = refreshed_skill else {
            return Err("unexpected Skill refresh outcome".into());
        };
        assert_eq!(skill.skill().revision().get(), 2);

        let request = HarnessCompositionRequest::new(
            base.bundle().descriptor().id(),
            base.bundle().revision(),
            vec![HarnessCompositionSkillSelection::new(
                skill.skill().descriptor().id(),
                skill.skill().revision(),
                skill.skill().descriptor().content_hash(),
            )],
            HarnessCompositionIdentity::new(
                HarnessBundleId::from_uuid(Uuid::from_u128(0x4270)),
                HarnessName::new("Worker Composition".to_owned())?,
                HarnessVersion::new("1.0.0".to_owned())?,
            ),
            TimestampMillis::new(12)?,
        )?;
        let saved = recv(&client.submit(HarnessWorkerAction::SaveComposition {
            request: request.clone(),
        })?)??;
        let HarnessWorkerOutcome::CompositionSaved(saved) = saved else {
            return Err("unexpected composition outcome".into());
        };
        assert_eq!(
            saved.bundle().descriptor().name().as_str(),
            "Worker Composition"
        );

        worker.shutdown()?;
        assert!(matches!(
            client.submit(HarnessWorkerAction::SaveComposition { request }),
            Err(HarnessWorkerError::ShuttingDown)
        ));
        fs::remove_dir_all(source)?;
        fs::remove_dir_all(skill_source)?;
        fs::remove_dir_all(saved_root)?;
        fs::remove_file(database)?;
        Ok(())
    }
}
