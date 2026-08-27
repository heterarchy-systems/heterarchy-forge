use std::os::unix::ffi::OsStrExt;

use forge_domain::{ExecutionKind, ExecutionRequest, ExecutionRequestDigest};

const DIGEST_DOMAIN: &[u8] = b"heterarchy-forge.execution-request.v1";

/// Hash the exact request with typed, length-delimited fields. Raw arguments
/// and shell text never need to enter durable semantic state.
pub fn execution_request_digest(request: &ExecutionRequest) -> ExecutionRequestDigest {
    let mut hasher = blake3::Hasher::new();
    write_field(&mut hasher, b"domain", DIGEST_DOMAIN);
    match request.kind() {
        ExecutionKind::Structured { program, arguments } => {
            write_field(&mut hasher, b"mode", b"structured");
            write_field(
                &mut hasher,
                b"program",
                program.as_path().as_os_str().as_bytes(),
            );
            write_u64(
                &mut hasher,
                b"argument-count",
                u64::try_from(arguments.len()).unwrap_or(u64::MAX),
            );
            for argument in arguments {
                write_field(&mut hasher, b"argument", argument.as_os_str().as_bytes());
            }
        }
        ExecutionKind::Shell { script } => {
            write_field(&mut hasher, b"mode", b"shell");
            write_field(&mut hasher, b"script", script.as_str().as_bytes());
        }
    }
    match request.cwd() {
        Some(cwd) => write_field(&mut hasher, b"cwd", cwd.as_path().as_os_str().as_bytes()),
        None => write_field(&mut hasher, b"cwd", &[]),
    }
    write_u64(&mut hasher, b"timeout-ms", request.timeout().get());
    write_u64(&mut hasher, b"output-limit", request.output_limit().get());
    write_bool(
        &mut hasher,
        b"workspace-read",
        request.permissions().workspace_read(),
    );
    write_bool(
        &mut hasher,
        b"workspace-write",
        request.permissions().workspace_write(),
    );
    write_bool(&mut hasher, b"network", request.permissions().network());
    ExecutionRequestDigest::from_bytes(*hasher.finalize().as_bytes())
}

fn write_bool(hasher: &mut blake3::Hasher, label: &[u8], value: bool) {
    write_field(hasher, label, &[u8::from(value)]);
}

fn write_u64(hasher: &mut blake3::Hasher, label: &[u8], value: u64) {
    write_field(hasher, label, &value.to_le_bytes());
}

fn write_field(hasher: &mut blake3::Hasher, label: &[u8], value: &[u8]) {
    hasher.update(&u64::try_from(label.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(label);
    hasher.update(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(value);
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use forge_domain::{
        ActivityId, ExecutionArgument, ExecutionAttribution, ExecutionId, ExecutionLimits,
        ExecutionOutputLimit, ExecutionPermissions, ExecutionProgram, ExecutionScript,
        ExecutionTimeoutMillis, WorkspaceId,
    };
    use uuid::Uuid;

    use super::*;

    fn request(kind: ExecutionKind) -> Result<ExecutionRequest, Box<dyn std::error::Error>> {
        Ok(ExecutionRequest::new(
            ExecutionAttribution::new(
                ExecutionId::from_uuid(Uuid::from_u128(1)),
                WorkspaceId::from_uuid(Uuid::from_u128(2)),
                ActivityId::from_uuid(Uuid::from_u128(3)),
            ),
            kind,
            None,
            ExecutionLimits::new(
                ExecutionTimeoutMillis::new(1_000)?,
                ExecutionOutputLimit::new(64)?,
            ),
            ExecutionPermissions::new(true, false, false),
        )?)
    }

    #[test]
    fn digest_changes_for_argument_boundaries_and_shell_mode()
    -> Result<(), Box<dyn std::error::Error>> {
        let structured = request(ExecutionKind::Structured {
            program: ExecutionProgram::new(PathBuf::from("/usr/bin/printf"))?,
            arguments: vec![
                ExecutionArgument::new(OsString::from("ab"))?,
                ExecutionArgument::new(OsString::from("c"))?,
            ],
        })?;
        let regrouped = request(ExecutionKind::Structured {
            program: ExecutionProgram::new(PathBuf::from("/usr/bin/printf"))?,
            arguments: vec![
                ExecutionArgument::new(OsString::from("a"))?,
                ExecutionArgument::new(OsString::from("bc"))?,
            ],
        })?;
        let shell = request(ExecutionKind::Shell {
            script: ExecutionScript::new("printf abc".to_owned())?,
        })?;
        assert_ne!(
            execution_request_digest(&structured),
            execution_request_digest(&regrouped)
        );
        assert_ne!(
            execution_request_digest(&structured),
            execution_request_digest(&shell)
        );
        assert!(!format!("{:?}", execution_request_digest(&shell)).contains("printf"));
        Ok(())
    }
}
