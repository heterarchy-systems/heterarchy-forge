use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use uuid::Uuid;

#[test]
fn binary_stdio_emits_only_json_rpc_and_exits_on_eof() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!("heterarchy-forge-mcp-bin-{}", Uuid::now_v7()));
    let home = root.join("home");
    let registry = root.join("support").join("registry.sqlite3");
    std::fs::create_dir_all(&home)?;

    let mut child = Command::new(env!("CARGO_BIN_EXE_forge-mcp"))
        .env("HOME", &home)
        .env("HETERARCHY_FORGE_REGISTRY_PATH", &registry)
        .env("RUST_LOG", "off")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"binary-test","version":"0.1"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        "\n"
    );
    child
        .stdin
        .as_mut()
        .ok_or("child stdin missing")?
        .write_all(input.as_bytes())?;
    drop(child.stdin.take());

    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .ok_or("child stdout missing")?
        .read_to_end(&mut stdout)?;
    let status = child.wait()?;
    assert!(status.success());

    let lines: Vec<Value> = std::str::from_utf8(&stdout)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["id"], json!(1));
    let names: Vec<&str> = lines[1]["result"]["tools"]
        .as_array()
        .ok_or("tools list missing")?
        .iter()
        .map(|tool| tool["name"].as_str().ok_or("tool name missing"))
        .collect::<Result<_, _>>()?;
    assert_eq!(
        names,
        vec![
            "workspace_list",
            "workspace_resolve",
            "activity_bootstrap",
            "file_read",
            "file_create",
            "file_replace",
            "file_delete",
            "diff_list",
            "diff_read",
            "diff_doctor",
            "diff_retention_plan",
            "diff_artifact_doctor",
            "agent_attach",
            "agent_set_focus",
            "agent_publish_work",
            "agent_get_context",
            "agent_detach",
            "goal_list",
            "goal_get",
            "dag_get_current",
            "dag_authoring_grant_discover",
            "dag_replan_commit",
        ]
    );
    assert!(registry.is_file());
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn binary_doctor_missing_registry_is_read_only_and_reports_warning()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "heterarchy-forge-mcp-doctor-bin-{}",
        Uuid::now_v7()
    ));
    let home = root.join("home");
    let registry = root.join("support").join("registry.sqlite3");
    std::fs::create_dir_all(&home)?;

    let output = Command::new(env!("CARGO_BIN_EXE_forge-mcp"))
        .arg("--doctor")
        .env("HOME", &home)
        .env("HETERARCHY_FORGE_REGISTRY_PATH", &registry)
        .env("RUST_LOG", "off")
        .stdin(Stdio::null())
        .output()?;
    assert!(output.status.success());
    let stdout = std::str::from_utf8(&output.stdout)?;
    for marker in [
        "mcp_doctor=PASS_WITH_WARNINGS",
        "registry_health=NOT_INITIALIZED",
        "runtime_ownership=PASS",
        "tool_names=PASS",
        "shutdown=PASS",
    ] {
        assert!(stdout.lines().any(|line| line == marker));
    }
    assert!(!registry.exists());
    assert!(!registry.parent().ok_or("registry parent missing")?.exists());
    assert!(
        !home
            .join("Library/Application Support/Heterarchy Forge/mcp-tokens.sqlite3")
            .exists()
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn binary_doctor_keeps_existing_registry_and_sidecars_byte_identical()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "heterarchy-forge-mcp-doctor-existing-{}",
        Uuid::now_v7()
    ));
    let home = root.join("home");
    let registry = root.join("support").join("registry.sqlite3");
    std::fs::create_dir_all(&home)?;

    let mut child = Command::new(env!("CARGO_BIN_EXE_forge-mcp"))
        .env("HOME", &home)
        .env("HETERARCHY_FORGE_REGISTRY_PATH", &registry)
        .env("RUST_LOG", "off")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    assert!(child.wait()?.success());
    assert!(registry.is_file());

    let sidecars = [
        registry.with_file_name("registry.sqlite3-wal"),
        registry.with_file_name("registry.sqlite3-shm"),
    ];
    let before_database = std::fs::read(&registry)?;
    let before_database_metadata = metadata_signature(&registry)?;
    let before_sidecars = sidecars
        .iter()
        .map(|path| {
            let bytes = path.exists().then(|| std::fs::read(path)).transpose()?;
            let metadata = metadata_signature(path)?;
            Ok::<_, Box<dyn std::error::Error>>((bytes, metadata))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let output = Command::new(env!("CARGO_BIN_EXE_forge-mcp"))
        .arg("--doctor")
        .env("HOME", &home)
        .env("HETERARCHY_FORGE_REGISTRY_PATH", &registry)
        .env("RUST_LOG", "off")
        .stdin(Stdio::null())
        .output()?;
    assert!(output.status.success());
    let stdout = std::str::from_utf8(&output.stdout)?;
    for marker in [
        "mcp_doctor=PASS",
        "registry_health=PASS",
        "runtime_ownership=PASS",
        "tool_names=PASS",
        "shutdown=PASS",
    ] {
        assert!(stdout.lines().any(|line| line == marker));
    }
    assert_eq!(std::fs::read(&registry)?, before_database);
    assert_eq!(metadata_signature(&registry)?, before_database_metadata);
    for (path, (before_bytes, before_metadata)) in sidecars.iter().zip(before_sidecars) {
        let after_bytes = path.exists().then(|| std::fs::read(path)).transpose()?;
        let after_metadata = metadata_signature(path)?;
        assert_eq!(after_bytes, before_bytes);
        assert_eq!(after_metadata, before_metadata);
    }
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct MetadataSignature {
    device: u64,
    inode: u64,
    links: u64,
    mode: u32,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

fn metadata_signature(path: &Path) -> Result<Option<MetadataSignature>, std::io::Error> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    Ok(Some(MetadataSignature {
        device: metadata.dev(),
        inode: metadata.ino(),
        links: metadata.nlink(),
        mode: metadata.mode(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
    }))
}

#[test]
fn binary_rejects_real_100kb_json_rpc_line_and_exits_cleanly()
-> Result<(), Box<dyn std::error::Error>> {
    let root =
        std::env::temp_dir().join(format!("heterarchy-forge-mcp-oversized-{}", Uuid::now_v7()));
    let home = root.join("home");
    let registry = root.join("support").join("registry.sqlite3");
    std::fs::create_dir_all(&home)?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_forge-mcp"))
        .env("HOME", &home)
        .env("HETERARCHY_FORGE_REGISTRY_PATH", &registry)
        .env("RUST_LOG", "off")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut oversized = vec![b'{'; 100 * 1024];
    oversized.push(b'\n');
    child
        .stdin
        .as_mut()
        .ok_or("child stdin missing")?
        .write_all(&oversized)?;
    drop(child.stdin.take());
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .ok_or("child stdout missing")?
        .read_to_end(&mut stdout)?;
    assert!(child.wait()?.success());
    assert!(stdout.is_empty());
    std::fs::remove_dir_all(root)?;
    Ok(())
}
