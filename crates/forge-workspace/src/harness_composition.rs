//! Explicit optional-Skill composition into a real local Harness Bundle source.
//!
//! Composition never mutates a Workspace. It publishes a new immutable source
//! directory under a caller-provided product-owned root, then re-inspects the
//! result through the normal Harness Bundle inspector. Existing Preview/Apply /
//! Update/Switch therefore remain the only Workspace mutation authority.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};

use forge_domain::{
    HarnessBundleId, HarnessName, HarnessVersion, MAX_HARNESS_MANAGED_FILES, MAX_HARNESS_SKILLS,
};
use thiserror::Error;
use toml::Value as TomlValue;

use crate::{
    HARNESS_MANIFEST_FILE_NAME, HarnessBundleInspectionError, InspectedHarnessBundle,
    InspectedHarnessSkill, MAX_HARNESS_TOTAL_MANAGED_BYTES, inspect_harness_bundle,
};

const AGENTS_TEMPLATE_FILE_NAME: &str = "AGENTS.md.template";
const STAGING_SUFFIX: &str = ".staging";

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessCompositionIdentity {
    id: HarnessBundleId,
    name: HarnessName,
    version: HarnessVersion,
}

impl HarnessCompositionIdentity {
    pub const fn new(id: HarnessBundleId, name: HarnessName, version: HarnessVersion) -> Self {
        Self { id, name, version }
    }

    pub const fn id(&self) -> HarnessBundleId {
        self.id
    }

    pub const fn name(&self) -> &HarnessName {
        &self.name
    }

    pub const fn version(&self) -> &HarnessVersion {
        &self.version
    }
}

#[derive(Debug, Error)]
pub enum HarnessCompositionError {
    #[error("saved Harness Bundle root is missing or not a regular directory")]
    InvalidDestinationRoot,
    #[error("saved Harness Bundle destination already exists")]
    DestinationExists,
    #[error("Harness composition contains duplicate Skill names or managed paths")]
    Collision,
    #[error("Harness composition exceeds managed-file or Skill capacity")]
    CapacityExceeded,
    #[error("Harness composition contains an invalid relative path")]
    InvalidPath,
    #[error("Harness composition manifest serialization failed")]
    ManifestSerialization,
    #[error("Harness composition filesystem effect failed")]
    Io(#[source] std::io::Error),
    #[error("saved Harness Bundle failed normal Bundle inspection")]
    Inspection(#[source] HarnessBundleInspectionError),
}

impl From<std::io::Error> for HarnessCompositionError {
    fn from(source: std::io::Error) -> Self {
        Self::Io(source)
    }
}

/// Save one explicit Base Harness + selected optional Skills as a real Bundle.
///
/// The returned Bundle has already passed the normal strict Bundle inspector.
pub fn save_harness_composition(
    destination_root: &Path,
    identity: &HarnessCompositionIdentity,
    base: &InspectedHarnessBundle,
    selected_skills: &[InspectedHarnessSkill],
) -> Result<InspectedHarnessBundle, HarnessCompositionError> {
    let destination_root = canonical_destination_root(destination_root)?;
    let selected_skills = canonical_skill_order(selected_skills);
    validate_composition(base, &selected_skills)?;
    let directory_name = identity.id().to_string();
    let destination = destination_root.join(&directory_name);
    let staging = destination_root.join(format!("{directory_name}{STAGING_SUFFIX}"));
    if fs::symlink_metadata(&destination).is_ok() || fs::symlink_metadata(&staging).is_ok() {
        return Err(HarnessCompositionError::DestinationExists);
    }
    fs::create_dir(&staging)?;
    let result = (|| {
        publish_composition(&staging, identity, base, &selected_skills)?;
        // Validate the complete tree while it is still private staging state.
        // A failed inspection must never be promoted to the published path.
        let _staged_bundle =
            inspect_harness_bundle(&staging).map_err(HarnessCompositionError::Inspection)?;
        fs::rename(&staging, &destination).map_err(HarnessCompositionError::Io)?;
        if let Err(error) = sync_directory(&destination_root) {
            let _ignored = fs::remove_dir_all(&destination);
            let _ignored = sync_directory(&destination_root);
            return Err(error);
        }
        match inspect_harness_bundle(&destination) {
            Ok(inspected) => Ok(inspected),
            Err(error) => {
                let _ignored = fs::remove_dir_all(&destination);
                let _ignored = sync_directory(&destination_root);
                Err(HarnessCompositionError::Inspection(error))
            }
        }
    })();
    if result.is_err() {
        let _ignored = fs::remove_dir_all(&staging);
    }
    result
}

fn canonical_skill_order(selected_skills: &[InspectedHarnessSkill]) -> Vec<&InspectedHarnessSkill> {
    let mut ordered = selected_skills.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        left.descriptor()
            .name()
            .as_str()
            .cmp(right.descriptor().name().as_str())
            .then_with(|| left.descriptor().id().cmp(&right.descriptor().id()))
    });
    ordered
}

fn canonical_destination_root(path: &Path) -> Result<PathBuf, HarnessCompositionError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| HarnessCompositionError::InvalidDestinationRoot)?;
    if !metadata.file_type().is_dir() {
        return Err(HarnessCompositionError::InvalidDestinationRoot);
    }
    fs::canonicalize(path).map_err(|_| HarnessCompositionError::InvalidDestinationRoot)
}

fn validate_composition(
    base: &InspectedHarnessBundle,
    selected_skills: &[&InspectedHarnessSkill],
) -> Result<(), HarnessCompositionError> {
    let mut labels = base.skills().iter().cloned().collect::<BTreeSet<_>>();
    let mut paths = base
        .managed_files()
        .iter()
        .map(|asset| asset.relative_path().to_path_buf())
        .collect::<BTreeSet<_>>();
    let mut total_bytes = base
        .managed_files()
        .iter()
        .try_fold(0_u64, |total, asset| {
            total
                .checked_add(
                    u64::try_from(asset.bytes().len())
                        .map_err(|_| HarnessCompositionError::CapacityExceeded)?,
                )
                .ok_or(HarnessCompositionError::CapacityExceeded)
        })?;
    for skill in selected_skills {
        let name = skill.descriptor().name().as_str();
        if !labels.insert(name.to_owned()) {
            return Err(HarnessCompositionError::Collision);
        }
        let namespace = PathBuf::from("skills").join(name);
        if paths
            .iter()
            .any(|path| path.starts_with(&namespace) || namespace.starts_with(path))
        {
            return Err(HarnessCompositionError::Collision);
        }
        for asset in skill.assets() {
            total_bytes = total_bytes
                .checked_add(
                    u64::try_from(asset.bytes().len())
                        .map_err(|_| HarnessCompositionError::CapacityExceeded)?,
                )
                .ok_or(HarnessCompositionError::CapacityExceeded)?;
            let path = skill_target_path(name, asset.relative_path())?;
            if !paths.insert(path) {
                return Err(HarnessCompositionError::Collision);
            }
        }
    }
    if total_bytes > MAX_HARNESS_TOTAL_MANAGED_BYTES {
        return Err(HarnessCompositionError::CapacityExceeded);
    }
    if paths.len() > usize::from(MAX_HARNESS_MANAGED_FILES)
        || labels.len() > usize::from(MAX_HARNESS_SKILLS)
    {
        return Err(HarnessCompositionError::CapacityExceeded);
    }
    Ok(())
}

fn publish_composition(
    staging: &Path,
    identity: &HarnessCompositionIdentity,
    base: &InspectedHarnessBundle,
    selected_skills: &[&InspectedHarnessSkill],
) -> Result<(), HarnessCompositionError> {
    let mut managed_paths = Vec::new();
    for asset in base.managed_files() {
        write_asset(staging, asset.relative_path(), asset.bytes())?;
        managed_paths.push(asset.relative_path().to_path_buf());
    }
    for skill in selected_skills {
        let name = skill.descriptor().name().as_str();
        for asset in skill.assets() {
            let target = skill_target_path(name, asset.relative_path())?;
            write_asset(staging, &target, asset.bytes())?;
            managed_paths.push(target);
        }
    }
    if let Some(template) = base.agents_template() {
        write_asset(
            staging,
            Path::new(AGENTS_TEMPLATE_FILE_NAME),
            template.bytes(),
        )?;
    }
    let manifest = composition_manifest(identity, base, selected_skills, &managed_paths)?;
    write_asset(
        staging,
        Path::new(HARNESS_MANIFEST_FILE_NAME),
        manifest.as_bytes(),
    )?;
    sync_directory(staging)?;
    Ok(())
}

fn composition_manifest(
    identity: &HarnessCompositionIdentity,
    base: &InspectedHarnessBundle,
    selected_skills: &[&InspectedHarnessSkill],
    managed_paths: &[PathBuf],
) -> Result<String, HarnessCompositionError> {
    let install_root = path_text(base.install_root())?;
    let mut harness = toml::map::Map::new();
    harness.insert(
        "id".to_owned(),
        TomlValue::String(identity.id().to_string()),
    );
    harness.insert(
        "name".to_owned(),
        TomlValue::String(identity.name().as_str().to_owned()),
    );
    harness.insert(
        "version".to_owned(),
        TomlValue::String(identity.version().as_str().to_owned()),
    );
    harness.insert("install_root".to_owned(), TomlValue::String(install_root));
    if base.agents_template().is_some() {
        harness.insert(
            "agents_template".to_owned(),
            TomlValue::String(AGENTS_TEMPLATE_FILE_NAME.to_owned()),
        );
    }
    harness.insert(
        "managed_files".to_owned(),
        TomlValue::Array(
            managed_paths
                .iter()
                .map(|path| path_text(path).map(TomlValue::String))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    );
    let mut skills = base.skills().to_vec();
    skills.extend(
        selected_skills
            .iter()
            .map(|skill| skill.descriptor().name().as_str().to_owned()),
    );
    harness.insert(
        "skills".to_owned(),
        TomlValue::Array(skills.into_iter().map(TomlValue::String).collect()),
    );

    let mut root = toml::map::Map::new();
    root.insert("harness".to_owned(), TomlValue::Table(harness));
    if !base.verifiers().is_empty() {
        let verifiers = base
            .verifiers()
            .iter()
            .map(|verifier| {
                let mut table = toml::map::Map::new();
                table.insert(
                    "name".to_owned(),
                    TomlValue::String(verifier.name().to_owned()),
                );
                table.insert(
                    "program".to_owned(),
                    TomlValue::String(verifier.program().to_owned()),
                );
                table.insert(
                    "args".to_owned(),
                    TomlValue::Array(
                        verifier
                            .arguments()
                            .iter()
                            .cloned()
                            .map(TomlValue::String)
                            .collect(),
                    ),
                );
                TomlValue::Table(table)
            })
            .collect();
        root.insert("verifiers".to_owned(), TomlValue::Array(verifiers));
    }
    toml::to_string(&TomlValue::Table(root))
        .map_err(|_| HarnessCompositionError::ManifestSerialization)
}

fn skill_target_path(name: &str, relative: &Path) -> Result<PathBuf, HarnessCompositionError> {
    let path = PathBuf::from("skills").join(name).join(relative);
    validate_relative_path(&path)?;
    Ok(path)
}

fn path_text(path: &Path) -> Result<String, HarnessCompositionError> {
    validate_relative_path(path)?;
    path.to_str()
        .map(str::to_owned)
        .ok_or(HarnessCompositionError::InvalidPath)
}

fn validate_relative_path(path: &Path) -> Result<(), HarnessCompositionError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(HarnessCompositionError::InvalidPath);
    }
    Ok(())
}

fn write_asset(root: &Path, relative: &Path, bytes: &[u8]) -> Result<(), HarnessCompositionError> {
    validate_relative_path(relative)?;
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        create_owned_directories(root, parent)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn create_owned_directories(root: &Path, target: &Path) -> Result<(), HarnessCompositionError> {
    let relative = target
        .strip_prefix(root)
        .map_err(|_| HarnessCompositionError::InvalidPath)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(HarnessCompositionError::InvalidPath);
        };
        current.push(component);
        match fs::create_dir(&current) {
            Ok(()) => {}
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = fs::symlink_metadata(&current)?;
                if !metadata.file_type().is_dir() {
                    return Err(HarnessCompositionError::InvalidPath);
                }
            }
            Err(source) => return Err(HarnessCompositionError::Io(source)),
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), HarnessCompositionError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use forge_domain::{HarnessSkillId, HarnessSkillName};
    use uuid::Uuid;

    use super::*;
    use crate::{HARNESS_SKILL_ENTRY_FILE, inspect_harness_skill};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    fn roots() -> Result<(PathBuf, PathBuf, PathBuf), Box<dyn std::error::Error>> {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-composition-{}-{serial}",
            std::process::id()
        ));
        let base = root.join("base");
        let skill = root.join("fastapi-skill");
        let saved = root.join("saved");
        fs::create_dir_all(base.join("rules"))?;
        fs::create_dir_all(&skill)?;
        fs::create_dir_all(skill.join("references"))?;
        fs::create_dir_all(skill.join("scripts"))?;
        fs::create_dir_all(&saved)?;
        fs::write(base.join("rules/base.md"), b"# Base\n")?;
        fs::write(base.join("AGENTS.md.template"), b"Read base rules.\n")?;
        fs::write(
            base.join(HARNESS_MANIFEST_FILE_NAME),
            r#"[harness]
id = "00000000-0000-0000-0000-000000004601"
name = "Base Harness"
version = "1.0.0"
install_root = ".agents/base_harness"
agents_template = "AGENTS.md.template"
managed_files = ["rules/base.md"]
skills = []
"#,
        )?;
        fs::write(skill.join(HARNESS_SKILL_ENTRY_FILE), b"# FastAPI Skill\n")?;
        fs::write(skill.join("references/guide.md"), b"# Guide\n")?;
        fs::write(skill.join("scripts/check.sh"), b"#!/bin/sh\n")?;
        Ok((root, base, saved))
    }

    #[test]
    fn composition_saves_real_reinspectable_bundle_with_explicit_skill()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, base_root, saved_root) = roots()?;
        let skill_root = root.join("fastapi-skill");
        let base = inspect_harness_bundle(&base_root)?;
        let skill = inspect_harness_skill(
            &skill_root,
            HarnessSkillId::from_uuid(Uuid::from_u128(0x4602)),
        )?;
        let identity = HarnessCompositionIdentity::new(
            HarnessBundleId::from_uuid(Uuid::from_u128(0x4603)),
            HarnessName::new("Composed Harness".to_owned())?,
            HarnessVersion::new("2.0.0".to_owned())?,
        );
        let saved = save_harness_composition(&saved_root, &identity, &base, &[skill])?;
        assert_eq!(saved.descriptor().id(), identity.id());
        assert_eq!(
            saved.skills(),
            &[HarnessSkillName::new("fastapi-skill".to_owned())?.as_str()]
        );
        assert!(
            saved
                .managed_files()
                .iter()
                .any(|asset| asset.relative_path() == Path::new("skills/fastapi-skill/SKILL.md"))
        );
        for (path, contents) in [
            (
                "skills/fastapi-skill/SKILL.md",
                b"# FastAPI Skill\n".as_slice(),
            ),
            (
                "skills/fastapi-skill/references/guide.md",
                b"# Guide\n".as_slice(),
            ),
            (
                "skills/fastapi-skill/scripts/check.sh",
                b"#!/bin/sh\n".as_slice(),
            ),
        ] {
            assert_eq!(fs::read(saved.source_root().join(path))?, contents);
        }
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn composition_copies_only_explicitly_selected_skills() -> Result<(), Box<dyn std::error::Error>>
    {
        let (root, base_root, saved_root) = roots()?;
        let second_skill_root = root.join("omitted-skill");
        fs::create_dir_all(&second_skill_root)?;
        fs::write(
            second_skill_root.join(HARNESS_SKILL_ENTRY_FILE),
            b"# Omitted\n",
        )?;
        let base = inspect_harness_bundle(&base_root)?;
        let selected = inspect_harness_skill(
            &root.join("fastapi-skill"),
            HarnessSkillId::from_uuid(Uuid::from_u128(0x4610)),
        )?;
        let _omitted = inspect_harness_skill(
            &second_skill_root,
            HarnessSkillId::from_uuid(Uuid::from_u128(0x4611)),
        )?;
        let identity = HarnessCompositionIdentity::new(
            HarnessBundleId::from_uuid(Uuid::from_u128(0x4612)),
            HarnessName::new("Selected Only".to_owned())?,
            HarnessVersion::new("1.0.0".to_owned())?,
        );
        let saved = save_harness_composition(&saved_root, &identity, &base, &[selected])?;
        assert_eq!(saved.skills(), &["fastapi-skill"]);
        assert!(
            !saved
                .source_root()
                .join("skills/omitted-skill/SKILL.md")
                .exists()
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn composition_rejects_duplicate_skill_and_leaves_no_publish_residue()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, base_root, saved_root) = roots()?;
        let base = inspect_harness_bundle(&base_root)?;
        let skill = inspect_harness_skill(
            &root.join("fastapi-skill"),
            HarnessSkillId::from_uuid(Uuid::from_u128(0x4620)),
        )?;
        let identity = HarnessCompositionIdentity::new(
            HarnessBundleId::from_uuid(Uuid::from_u128(0x4621)),
            HarnessName::new("Duplicate Selection".to_owned())?,
            HarnessVersion::new("1.0.0".to_owned())?,
        );
        assert!(matches!(
            save_harness_composition(&saved_root, &identity, &base, &[skill.clone(), skill]),
            Err(HarnessCompositionError::Collision)
        ));
        let destination = saved_root.join(identity.id().to_string());
        assert!(!destination.exists());
        assert!(
            !saved_root
                .join(format!("{}{}", identity.id(), STAGING_SUFFIX))
                .exists()
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn composition_rejects_base_managed_skill_namespace_collision()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, base_root, saved_root) = roots()?;
        let base_skill_path = base_root.join("skills/fastapi-skill");
        fs::create_dir_all(&base_skill_path)?;
        fs::write(
            base_skill_path.join("owned.md"),
            b"# Base-owned Skill content\n",
        )?;
        fs::write(
            base_root.join(HARNESS_MANIFEST_FILE_NAME),
            r#"[harness]
id = "00000000-0000-0000-0000-000000004601"
name = "Base Harness"
version = "1.0.0"
install_root = ".agents/base_harness"
agents_template = "AGENTS.md.template"
managed_files = ["rules/base.md", "skills/fastapi-skill/owned.md"]
skills = []
"#,
        )?;
        let base = inspect_harness_bundle(&base_root)?;
        let skill = inspect_harness_skill(
            &root.join("fastapi-skill"),
            HarnessSkillId::from_uuid(Uuid::from_u128(0x4622)),
        )?;
        let identity = HarnessCompositionIdentity::new(
            HarnessBundleId::from_uuid(Uuid::from_u128(0x4623)),
            HarnessName::new("Namespace Collision".to_owned())?,
            HarnessVersion::new("1.0.0".to_owned())?,
        );
        assert!(matches!(
            save_harness_composition(&saved_root, &identity, &base, &[skill]),
            Err(HarnessCompositionError::Collision)
        ));
        assert!(!saved_root.join(identity.id().to_string()).exists());
        assert!(
            !saved_root
                .join(format!("{}{}", identity.id(), STAGING_SUFFIX))
                .exists()
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn composition_canonicalizes_selected_skill_order() -> Result<(), Box<dyn std::error::Error>> {
        let (root, base_root, saved_root) = roots()?;
        let alpha_root = root.join("alpha-skill");
        let zeta_root = root.join("zeta-skill");
        fs::create_dir_all(&alpha_root)?;
        fs::create_dir_all(&zeta_root)?;
        fs::write(alpha_root.join(HARNESS_SKILL_ENTRY_FILE), b"# Alpha\n")?;
        fs::write(zeta_root.join(HARNESS_SKILL_ENTRY_FILE), b"# Zeta\n")?;
        let base = inspect_harness_bundle(&base_root)?;
        let alpha = inspect_harness_skill(
            &alpha_root,
            HarnessSkillId::from_uuid(Uuid::from_u128(0x4624)),
        )?;
        let zeta = inspect_harness_skill(
            &zeta_root,
            HarnessSkillId::from_uuid(Uuid::from_u128(0x4625)),
        )?;
        let identity = HarnessCompositionIdentity::new(
            HarnessBundleId::from_uuid(Uuid::from_u128(0x4626)),
            HarnessName::new("Canonical Skill Order".to_owned())?,
            HarnessVersion::new("1.0.0".to_owned())?,
        );
        let saved = save_harness_composition(&saved_root, &identity, &base, &[zeta, alpha])?;
        assert_eq!(saved.skills(), &["alpha-skill", "zeta-skill"]);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn composition_rejects_aggregate_managed_bytes_before_staging()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, base_root, saved_root) = roots()?;
        let large_skill_root = root.join("large-skill");
        fs::create_dir_all(&large_skill_root)?;
        fs::write(
            large_skill_root.join(HARNESS_SKILL_ENTRY_FILE),
            b"# Large\n",
        )?;
        let chunk = vec![b'x'; 2 * 1024 * 1024];
        for index in 0..8 {
            let bytes = if index == 7 {
                &chunk[..chunk.len() - 8]
            } else {
                &chunk[..]
            };
            fs::write(large_skill_root.join(format!("part-{index}.bin")), bytes)?;
        }
        let base = inspect_harness_bundle(&base_root)?;
        let skill = inspect_harness_skill(
            &large_skill_root,
            HarnessSkillId::from_uuid(Uuid::from_u128(0x4630)),
        )?;
        let skill_bytes = skill
            .assets()
            .iter()
            .map(|asset| asset.bytes().len())
            .sum::<usize>();
        assert_eq!(
            u64::try_from(skill_bytes),
            Ok(MAX_HARNESS_TOTAL_MANAGED_BYTES)
        );
        let identity = HarnessCompositionIdentity::new(
            HarnessBundleId::from_uuid(Uuid::from_u128(0x4631)),
            HarnessName::new("Over Budget".to_owned())?,
            HarnessVersion::new("1.0.0".to_owned())?,
        );
        assert!(matches!(
            save_harness_composition(&saved_root, &identity, &base, &[skill]),
            Err(HarnessCompositionError::CapacityExceeded)
        ));
        assert!(!saved_root.join(identity.id().to_string()).exists());
        assert!(
            !saved_root
                .join(format!("{}{}", identity.id(), STAGING_SUFFIX))
                .exists()
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
