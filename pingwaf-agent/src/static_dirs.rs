//! Inventory of operator-registered static roots, without exposing node paths.
use anyhow::{Context, ensure};
use rustix::fs::{Dir, Mode, OFlags, open, openat};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::{Read, Write},
    path::Path,
};

const MAX_BYTES: u64 = 32 * 1024 * 1024;
const MAX_ENTRIES: usize = 2048;

struct Manifest {
    files: BTreeMap<String, [u8; 32]>,
    bytes: u64,
    entries: usize,
}

impl Manifest {
    fn scan(
        &mut self,
        dir: &File,
        prefix: &str,
        output: Option<&Path>,
    ) -> anyhow::Result<()> {
        for entry in Dir::read_from(dir)? {
            let entry = entry?;
            let name = entry.file_name().to_str()?;
            if matches!(name, "." | "..") {
                continue;
            }
            self.entries += 1;
            ensure!(self.entries <= MAX_ENTRIES, "too many entries");
            let path = format!("{prefix}{name}");
            ensure!(
                path.len() <= 512
                    && !name.starts_with('.')
                    && !name.contains(['\\', ':'])
                    && !name.chars().any(char::is_control),
                "invalid static path"
            );
            // Refuse special files before opening; O_NOFOLLOW protects the lookup
            // if a directory entry changes between enumeration and open.
            ensure!(
                matches!(
                    entry.file_type(),
                    rustix::fs::FileType::RegularFile
                        | rustix::fs::FileType::Directory
                ),
                "unsupported entry type"
            );
            let child = File::from(openat(
                dir,
                entry.file_name(),
                OFlags::RDONLY
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC
                    | OFlags::NONBLOCK,
                Mode::empty(),
            )?);
            let meta = child.metadata()?;
            if meta.is_dir() {
                if let Some(output) = output {
                    std::fs::create_dir(output.join(&path))?;
                }
                self.scan(&child, &format!("{path}/"), output)?;
            } else {
                ensure!(
                    meta.is_file() && meta.len() <= MAX_BYTES - self.bytes,
                    "invalid static file or size"
                );
                let mut hash = Sha256::new();
                let mut reader = child.take(meta.len() + 1);
                let mut buf = [0; 16384];
                let mut size = 0u64;
                let mut target = output
                    .map(|out| File::create_new(out.join(&path)))
                    .transpose()?;
                loop {
                    let n = reader.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    hash.update(&buf[..n]);
                    if let Some(file) = &mut target {
                        file.write_all(&buf[..n])?;
                    }
                    size += n as u64;
                }
                ensure!(size == meta.len(), "file changed while hashing");
                self.bytes += size;
                self.files.insert(path, hash.finalize().into());
            }
        }
        Ok(())
    }
}

pub fn digest(root: &Path) -> anyhow::Result<String> {
    scan_root(root, None)
}

pub fn release_path(
    site: uuid::Uuid,
    digest: &str,
) -> anyhow::Result<std::path::PathBuf> {
    ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "invalid release digest"
    );
    let base = content_base();
    ensure!(
        base.is_absolute(),
        "site content directory must be absolute"
    );
    Ok(base.join(site.to_string()).join(digest))
}

fn content_base() -> std::path::PathBuf {
    std::env::var_os("PINGWAF_SITE_CONTENT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/var/lib/pingwaf/site-content".into())
}

/// Inventory contains only published release names. The content itself is
/// opened without following symlinks and rehashed before it is activated.
pub fn retained_directories() -> Vec<String> {
    let mut result = Vec::new();
    let Ok(sites) = std::fs::read_dir(content_base()) else {
        return result;
    };
    for site in sites.flatten() {
        let Ok(id) = uuid::Uuid::parse_str(&site.file_name().to_string_lossy())
        else {
            continue;
        };
        if !site.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(site.path()) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let digest = name.to_string_lossy();
            if digest.len() == 64
                && digest
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
                && entry.file_type().is_ok_and(|t| t.is_dir())
                && entry.path().join("index.html").is_file()
            {
                result.push(format!("{id}/{digest}"));
                if result.len() == 2048 {
                    break;
                }
            }
        }
        if result.len() == 2048 {
            break;
        }
    }
    result.sort_unstable();
    result
}

/// The manifest stays outside the visitor-visible tree. Both are made visible
/// by the same rename, after the archive digest and every entry have passed.
pub fn install_archive(
    target: &Path,
    expected: &str,
    archive: &[u8],
) -> anyhow::Result<()> {
    ensure!(
        hex::encode(Sha256::digest(archive)) == expected,
        "downloaded archive digest mismatch"
    );
    let parent = target.parent().context("invalid release path")?;
    std::fs::create_dir_all(parent)?;
    let stage = tempfile::Builder::new()
        .prefix(".zip-")
        .tempdir_in(parent)?;
    let tree = stage.path().join("public");
    std::fs::create_dir(&tree)?;
    pingwaf_content::inspect(archive, Some(&tree))?;
    let fingerprint = digest(&tree)?;
    std::fs::write(stage.path().join("tree.sha256"), &fingerprint)?;
    if let Err(err) = std::fs::rename(stage.path(), target) {
        if !target.is_dir() || digest(&target.join("public"))? != fingerprint {
            return Err(err.into());
        }
    }
    Ok(())
}

fn scan_root(root: &Path, output: Option<&Path>) -> anyhow::Result<String> {
    ensure!(root.is_absolute(), "root must be absolute");
    let dir = File::from(open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?);
    let mut manifest = Manifest {
        files: BTreeMap::new(),
        bytes: 0,
        entries: 0,
    };
    manifest.scan(&dir, "", output)?;
    ensure!(
        manifest.files.contains_key("index.html"),
        "missing index.html"
    );
    let mut hash = Sha256::new();
    for (name, content_hash) in manifest.files {
        hash.update((name.len() as u32).to_be_bytes());
        hash.update(name.as_bytes());
        hash.update(content_hash);
    }
    Ok(hex::encode(hash.finalize()))
}

fn registered_roots() -> anyhow::Result<BTreeMap<String, String>> {
    let registry = std::env::var_os("PINGWAF_STATIC_ROOTS_FILE")
        .unwrap_or_else(|| "/etc/pingwaf/static-roots.json".into());
    let file = match File::open(registry) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BTreeMap::new());
        },
        Err(error) => return Err(error.into()),
    };
    let mut raw = Vec::new();
    file.take(16385).read_to_end(&mut raw)?;
    ensure!(raw.len() <= 16384, "directory registry too large");
    let roots: BTreeMap<String, String> = serde_json::from_slice(&raw)
        .context("invalid static directory registry")?;
    ensure!(roots.len() <= 16, "too many static roots");
    for id in roots.keys() {
        ensure!(
            !id.is_empty()
                && id.len() <= 64
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric()
                        || matches!(b, b'-' | b'_')),
            "invalid static root identifier"
        );
    }
    Ok(roots)
}

pub fn inventory() -> anyhow::Result<HashMap<String, String>> {
    let mut report = HashMap::new();
    for (id, root) in registered_roots()? {
        let digest = digest(Path::new(&root)).unwrap_or_else(|error| {
            tracing::warn!(directory = %id, %error, "static root unavailable");
            String::new()
        });
        report.insert(id, digest);
    }
    Ok(report)
}

/// Copy registered files to a private staging tree. Only fully verified trees
/// acquire their release name, so a failed rescan cannot replace serving files.
pub fn prepare_registered(
    id: &str,
    expected: &str,
    target: &Path,
) -> anyhow::Result<()> {
    if target.is_dir() {
        ensure!(
            digest(target)? == expected,
            "stored static release failed integrity check"
        );
        return Ok(());
    }
    let roots = registered_roots()?;
    let root = roots
        .get(id)
        .context("static directory is no longer registered")?;
    let parent = target.parent().context("invalid release path")?;
    std::fs::create_dir_all(parent)?;
    let stage = tempfile::Builder::new()
        .prefix(".prepare-")
        .tempdir_in(parent)?;
    ensure!(
        scan_root(Path::new(root), Some(stage.path()))? == expected,
        "registered directory digest changed"
    );
    if let Err(err) = std::fs::rename(stage.path(), target) {
        if !target.is_dir() || digest(target)? != expected {
            return Err(err.into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_digest_tracks_paths_and_contents_and_rejects_links() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        for root in [first.path(), second.path()] {
            std::fs::write(root.join("index.html"), "hello").unwrap();
            std::fs::create_dir(root.join("css")).unwrap();
            std::fs::write(root.join("css/base.css"), "body{}").unwrap();
        }
        let approved = digest(first.path()).unwrap();
        assert_eq!(digest(second.path()).unwrap(), approved);
        std::fs::write(second.path().join("index.html"), "changed").unwrap();
        assert_ne!(digest(second.path()).unwrap(), approved);
        std::os::unix::fs::symlink(second.path(), first.path().join("other"))
            .unwrap();
        assert!(digest(first.path()).is_err());
    }
}
