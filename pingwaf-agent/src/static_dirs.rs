//! Inventory of operator-registered static roots, without exposing node paths.
use anyhow::{Context, ensure};
use rustix::fs::{Dir, Mode, OFlags, open, openat};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::Read,
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
    fn scan(&mut self, dir: &File, prefix: &str) -> anyhow::Result<()> {
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
                self.scan(&child, &format!("{path}/"))?;
            } else {
                ensure!(
                    meta.is_file() && meta.len() <= MAX_BYTES - self.bytes,
                    "invalid static file or size"
                );
                let mut hash = Sha256::new();
                let mut reader = child.take(meta.len() + 1);
                let mut buf = [0; 16384];
                let mut size = 0u64;
                loop {
                    let n = reader.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    hash.update(&buf[..n]);
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
    manifest.scan(&dir, "")?;
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

pub fn inventory() -> anyhow::Result<HashMap<String, String>> {
    let file = match File::open("/etc/pingwaf/static-roots.json") {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(HashMap::new());
        },
        Err(error) => return Err(error.into()),
    };
    let mut raw = Vec::new();
    file.take(16385).read_to_end(&mut raw)?;
    ensure!(raw.len() <= 16384, "directory registry too large");
    let roots: BTreeMap<String, String> = serde_json::from_slice(&raw)
        .context("invalid static directory registry")?;
    ensure!(roots.len() <= 16, "too many static roots");
    let mut report = HashMap::new();
    for (id, root) in roots {
        ensure!(
            !id.is_empty()
                && id.len() <= 64
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric()
                        || matches!(b, b'-' | b'_')),
            "invalid static root identifier"
        );
        let digest = digest(Path::new(&root)).unwrap_or_else(|error| {
            tracing::warn!(directory = %id, %error, "static root unavailable");
            String::new()
        });
        report.insert(id, digest);
    }
    Ok(report)
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
        std::os::unix::fs::symlink(second.path(), first.path().join("other")).unwrap();
        assert!(digest(first.path()).is_err());
    }
}
