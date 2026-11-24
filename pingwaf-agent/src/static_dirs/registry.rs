use super::{content_base, registered_roots, scan_directory, scan_root};
use anyhow::{ensure, Context};
use rustix::fs::{open, openat, Mode, OFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

#[derive(Default, Serialize, Deserialize)]
struct Overrides {
    generation: u64,
    // None masks an identifier provided by the operator's legacy file.
    entries: BTreeMap<String, Option<String>>,
}

pub(super) struct Registry {
    legacy: BTreeMap<String, String>,
    managed: Overrides,
    public_root: PathBuf,
}

impl Registry {
    pub(super) fn load() -> anyhow::Result<Self> {
        let managed =
            match File::open(content_base().join("directory-registry.json")) {
                Ok(file) => {
                    let mut bytes = Vec::new();
                    file.take(65537).read_to_end(&mut bytes)?;
                    ensure!(
                        bytes.len() <= 65536,
                        "node directory registry too large"
                    );
                    serde_json::from_slice(&bytes)?
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    Overrides::default()
                },
                Err(e) => return Err(e.into()),
            };
        let public_root = std::env::var_os("PINGWAF_STATIC_PUBLIC_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/srv/www"));
        Ok(Self {
            legacy: registered_roots()?,
            managed,
            public_root,
        })
    }

    pub(super) fn paths(&self) -> BTreeMap<String, String> {
        let mut paths = self.legacy.clone();
        for (id, path) in &self.managed.entries {
            if let Some(path) = path {
                paths.insert(id.clone(), path.clone());
            } else {
                paths.remove(id);
            }
        }
        paths
    }

    fn revision(&self) -> anyhow::Result<String> {
        let bytes = serde_json::to_vec(&(
            &self.legacy,
            &self.managed,
            &self.public_root,
        ))?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    pub(super) fn scan(
        &self,
        id: &str,
        output: Option<&Path>,
    ) -> anyhow::Result<String> {
        match self.managed.entries.get(id) {
            Some(Some(path)) => scan_directory(
                open_public(&self.public_root, Path::new(path))?,
                output,
            ),
            Some(None) => anyhow::bail!("static directory was removed"),
            None => scan_root(
                Path::new(
                    self.legacy.get(id).context("unknown static directory")?,
                ),
                output,
            ),
        }
    }
}

fn open_public(base: &Path, path: &Path) -> anyhow::Result<File> {
    ensure!(
        base.is_absolute()
            && base.parent().is_some()
            && path.starts_with(base)
            && path != base,
        "choose a directory below the configured static content root"
    );
    let flags =
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mut dir = File::from(open("/", flags, Mode::empty())?);
    for component in path.components().skip(1) {
        let Component::Normal(name) = component else {
            anyhow::bail!("invalid directory component");
        };
        dir = File::from(openat(&dir, name, flags, Mode::empty())?);
    }
    Ok(dir)
}

/// Absolute paths are privileged inventory, separate from site-facing digests.
fn directory_registry(
) -> anyhow::Result<(String, BTreeMap<String, String>, String)> {
    let registry = Registry::load()?;
    Ok((
        registry.revision()?,
        registry.paths(),
        registry.public_root.to_string_lossy().into_owned(),
    ))
}

fn update_directory_registry(
    revision: &str,
    id: &str,
    path: Option<&str>,
) -> anyhow::Result<()> {
    ensure!(
        !id.is_empty()
            && id.len() <= 64
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')),
        "invalid directory identifier"
    );
    let storage = content_base();
    ensure!(storage.is_absolute(), "node storage must be absolute");
    std::fs::create_dir_all(&storage)?;
    let lock = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(storage.join("directory-registry.lock"))?;
    lock.lock()?;
    let mut registry = Registry::load()?;
    ensure!(
        registry.revision()? == revision,
        "directory registry changed; refresh before saving"
    );
    registry.managed.entries.retain(|id, entry| {
        entry.is_some() || registry.legacy.contains_key(id)
    });
    if let Some(path) = path {
        ensure!(
            path.len() <= 1024 && !path.chars().any(char::is_control),
            "invalid public directory path"
        );
        scan_directory(
            open_public(&registry.public_root, Path::new(path))?,
            None,
        )?;
        registry
            .managed
            .entries
            .insert(id.into(), Some(path.into()));
    } else {
        ensure!(
            registry.paths().contains_key(id),
            "unknown static directory"
        );
        if registry.legacy.contains_key(id) {
            registry.managed.entries.insert(id.into(), None);
        } else {
            registry.managed.entries.remove(id);
        }
    }
    ensure!(registry.paths().len() <= 16, "too many static roots");
    registry.managed.generation = registry
        .managed
        .generation
        .checked_add(1)
        .context("registry generation exhausted")?;
    let mut file = tempfile::NamedTempFile::new_in(&storage)?;
    file.write_all(&serde_json::to_vec(&registry.managed)?)?;
    file.as_file().sync_all()?;
    file.persist(storage.join("directory-registry.json"))?;
    File::open(storage)?.sync_all()?;
    Ok(())
}

static RECEIPT: std::sync::Mutex<(String, String)> =
    std::sync::Mutex::new((String::new(), String::new()));
static CHANGED: tokio::sync::Notify = tokio::sync::Notify::const_new();

pub async fn registry_changed() {
    CHANGED.notified().await;
}

pub fn apply_directory_update(
    command_id: String,
    change: pingwaf_proto::UpdateStaticRoot,
) {
    let result = update_directory_registry(
        &change.revision,
        &change.identifier,
        change.path.as_deref(),
    );
    let error = result.err().map(|e| format!("{e:#}")).unwrap_or_default();
    *RECEIPT.lock().unwrap_or_else(|e| e.into_inner()) = (command_id, error);
    CHANGED.notify_one();
}

pub fn directory_report() -> pingwaf_proto::StaticRootRegistry {
    let (last_command, last_error) =
        RECEIPT.lock().unwrap_or_else(|e| e.into_inner()).clone();
    match directory_registry() {
        Ok((revision, paths, public_root)) => {
            pingwaf_proto::StaticRootRegistry {
                revision,
                paths: paths.into_iter().collect(),
                public_root,
                last_command,
                last_error,
            }
        },
        Err(error) => pingwaf_proto::StaticRootRegistry {
            last_command,
            last_error: format!("{error:#}"),
            ..Default::default()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_and_reopen_registry() {
        // Use a child process so environment overrides cannot affect parallel
        // agent tests. Both the inventory and release paths use production code.
        if std::env::var_os("PINGWAF_TEST_ROOT_REGISTRY_CHILD").is_none() {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().join("public");
            std::fs::create_dir_all(root.join("site")).unwrap();
            std::fs::write(root.join("site/index.html"), "first").unwrap();
            let legacy = tmp.path().join("legacy.json");
            std::fs::write(
                &legacy,
                serde_json::to_vec(
                    &serde_json::json!({"legacy":root.join("site")}),
                )
                .unwrap(),
            )
            .unwrap();
            let result = std::process::Command::new(
                std::env::current_exe().unwrap(),
            )
            .args([
                "--exact",
                "static_dirs::registry::tests::update_and_reopen_registry",
                "--nocapture",
            ])
            .env("PINGWAF_TEST_ROOT_REGISTRY_CHILD", "1")
            .env("PINGWAF_SITE_CONTENT_DIR", tmp.path().join("state"))
            .env("PINGWAF_STATIC_ROOTS_FILE", legacy)
            .env("PINGWAF_STATIC_PUBLIC_DIR", root)
            .status()
            .unwrap();
            assert!(result.success());
            return;
        }
        let (revision, paths, root) = directory_registry().unwrap();
        let site = paths["legacy"].clone();
        update_directory_registry(&revision, "public", Some(&site)).unwrap();
        assert!(
            update_directory_registry(&revision, "other", Some(&site)).is_err()
        );
        let report = directory_report();
        assert_eq!(report.paths.len(), 2);
        assert!(update_directory_registry(
            &report.revision,
            "outside",
            Some("/etc")
        )
        .is_err());
        let alias = Path::new(&root).join("alias");
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        assert!(update_directory_registry(
            &report.revision,
            "alias",
            alias.join("site").to_str()
        )
        .is_err());
        assert_eq!(report.revision, directory_report().revision);
        let inventory = super::super::inventory().unwrap();
        assert_eq!(inventory["public"], inventory["legacy"]);
        assert_eq!(inventory["public"].len(), 64);
        update_directory_registry(&report.revision, "legacy", None).unwrap();
        assert!(!directory_report().paths.contains_key("legacy"));
        update_directory_registry(&directory_report().revision, "public", None)
            .unwrap();
        assert!(directory_report().paths.is_empty());
        assert!(Path::new(&site).join("index.html").is_file());
    }
}
