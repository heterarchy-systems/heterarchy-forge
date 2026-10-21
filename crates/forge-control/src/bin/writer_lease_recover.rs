use std::env;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use forge_domain::TimestampMillis;
use forge_persistence::WorkspaceStore;
use forge_workspace::WorkspaceStateLayout;

fn main() {
    if let Err(error) = run() {
        eprintln!("Heterarchy Forge writer lease recovery failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let workspace_root = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("usage: writer_lease_recover <workspace-root>")?;
    if arguments.next().is_some() {
        return Err("usage: writer_lease_recover <workspace-root>".into());
    }

    let canonical_root = std::fs::canonicalize(workspace_root)?;
    let layout = WorkspaceStateLayout::inspect_existing(&canonical_root)?
        .ok_or("Workspace state layout is not initialized")?;
    if layout.workspace_root() != canonical_root.as_path() {
        return Err("Workspace state layout root does not match the requested root".into());
    }
    let mut store = WorkspaceStore::open_existing(&layout)?;

    let now_ms = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let observed_at = TimestampMillis::new(now_ms)?;
    let active = store.list_active_writer_leases()?;
    let mut released = 0usize;

    for lease in active {
        if lease.lease_until().get() > observed_at.get() {
            continue;
        }
        let recovered =
            store.release_writer_lease_for_recovery(lease.id(), lease.revision(), observed_at)?;
        println!(
            "released_writer_lease={} revision={} activity={} agent={}",
            recovered.id(),
            recovered.revision().get(),
            recovered.activity_id(),
            recovered.agent_id()
        );
        released = released.saturating_add(1);
    }

    println!("expired_writer_leases_released={released}");
    Ok(())
}
