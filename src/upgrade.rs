//! Version reporting and self-update for the shipped binaries.
//!
//! `version` answers "what am I running, and is there something newer?";
//! `upgrade` replaces this binary with a release from GitHub. Both are
//! deliberately dependency-light:
//!
//! * the download goes through `curl`, which the installer already requires
//!   (and which the container healthcheck uses), so the agent build does not
//!   grow an HTTP client or a second TLS stack;
//! * the archive is `.tar.gz`, decoded with the `flate2`/`tar` pair the build
//!   already carries;
//! * the release's `.sha256` sidecar is verified **before** anything is
//!   extracted, and the extracted binary is asked for its version before it
//!   replaces the installed one — a truncated download or a swapped artifact
//!   fails the upgrade instead of bricking the node.
//!
//! The replacement is staged next to the target and renamed over it, so an
//! interrupted upgrade leaves the old binary in place. A running process keeps
//! its inode; the new binary takes effect on the next start, which is why the
//! command restarts the systemd unit unless told not to.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use flate2::read::GzDecoder;

/// Where releases are published. `--repo` overrides it for a fork or a mirror.
pub const DEFAULT_REPO: &str = "shuaiZend/PingWAF";

/// Binary name of this build: the release archive is named after it.
pub fn program() -> &'static str {
    if cfg!(feature = "edge") {
        "pingwaf-agent"
    } else {
        "pingwaf"
    }
}

/// The version this binary was built from.
pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// `amd64` / `arm64`, the two architectures the release pipeline publishes.
fn release_arch() -> Result<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("amd64"),
        "aarch64" => Ok("arm64"),
        other => bail!(
            "no prebuilt release for architecture {other}: the pipeline publishes \
             linux/amd64 and linux/arm64 only; build from source instead"
        ),
    }
}

fn release_api(repo: &str) -> String {
    format!("https://api.github.com/repos/{repo}/releases/latest")
}

fn asset_url(repo: &str, tag: &str, arch: &str) -> String {
    format!(
        "https://github.com/{repo}/releases/download/{tag}/{}-linux-{arch}.tar.gz",
        program()
    )
}

/// Runs `curl` and returns what it wrote to stdout.
fn curl(url: &str) -> Result<Vec<u8>> {
    let output = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--retry",
            "3",
            "--connect-timeout",
            "10",
            "--max-time",
            "300",
            "--proto",
            "=https",
            url,
        ])
        .output()
        .map_err(|err| {
            anyhow!("cannot run curl ({err}); install curl or download the release manually")
        })?;
    if !output.status.success() {
        bail!(
            "curl {url} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

/// Downloads `url` into `path`, refusing a non-HTTPS or failed transfer.
fn curl_to(url: &str, path: &Path) -> Result<()> {
    let status = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--retry",
            "3",
            "--connect-timeout",
            "10",
            "--max-time",
            "900",
            "--proto",
            "=https",
            "--output",
        ])
        .arg(path)
        .arg(url)
        .status()
        .map_err(|err| {
            anyhow!("cannot run curl ({err}); install curl or download the release manually")
        })?;
    if !status.success() {
        bail!("downloading {url} failed");
    }
    Ok(())
}

/// The newest published version, without the leading `v`.
pub fn latest_version(repo: &str) -> Result<String> {
    let body = curl(&release_api(repo))?;
    let json: serde_json::Value = serde_json::from_slice(&body)
        .context("parse the GitHub release response")?;
    let tag = json
        .get("tag_name")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            anyhow!("the GitHub release response has no tag_name")
        })?;
    Ok(normalize_version(tag))
}

fn normalize_version(raw: &str) -> String {
    raw.trim().trim_start_matches('v').to_string()
}

/// Whether `candidate` is newer than `current`.
///
/// Numeric comparison, so `0.33.10` sorts after `0.33.9` (string comparison
/// would not). A pre-release (`1.2.3-rc.1`) sorts before its release, which is
/// what an upgrade decision needs.
pub fn is_newer(candidate: &str, current: &str) -> bool {
    let split = |value: &str| -> (Vec<u64>, bool) {
        let (core, pre) = match value.split_once('-') {
            Some((core, _pre)) => (core, true),
            None => (value, false),
        };
        let numbers = core
            .split('.')
            .map(|part| part.parse::<u64>().unwrap_or(0))
            .collect();
        (numbers, pre)
    };
    let (left, left_pre) = split(normalize_version(candidate).as_str());
    let (right, right_pre) = split(normalize_version(current).as_str());
    for index in 0..left.len().max(right.len()) {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        if a != b {
            return a > b;
        }
    }
    // Same numbers: a release outranks its pre-release.
    right_pre && !left_pre
}

/// `pingwaf-agent version [--check]`.
pub fn print_version(check: bool) -> Result<()> {
    println!("{} {}", program(), crate::version::version_banner());
    let config = std::path::Path::new("/etc/pingwaf/pingwaf.toml");
    if config.is_file() {
        println!("  config : {}", config.display());
    }
    println!(
        "  target : {}/{}",
        std::env::consts::OS,
        release_arch().unwrap_or("unsupported")
    );
    if !check {
        return Ok(());
    }
    match latest_version(DEFAULT_REPO) {
        Ok(latest) => {
            if is_newer(&latest, current_version()) {
                println!(
                    "  latest : {latest} (update available: {} upgrade)",
                    program()
                );
            } else {
                println!("  latest : {latest} (up to date)");
            }
            Ok(())
        },
        Err(err) => {
            println!("  latest : unavailable ({err})");
            Err(err)
        },
    }
}

/// Reads a `.sha256` sidecar (`<hash>  <file>`) and returns the hash.
fn expected_hash(sidecar: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(sidecar)
        .context("the .sha256 sidecar is not UTF-8")?;
    let hash = text
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow!("the .sha256 sidecar is empty"))?;
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("the .sha256 sidecar does not start with a SHA-256 digest");
    }
    Ok(hash.to_ascii_lowercase())
}

fn sha256_hex(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("cannot read {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Extracts one file from a `.tar.gz` archive.
fn extract_from_targz(
    archive: &Path,
    name: &str,
    destination: &Path,
) -> Result<()> {
    let file = std::fs::File::open(archive)
        .with_context(|| format!("cannot open {}", archive.display()))?;
    let mut tar = tar::Archive::new(GzDecoder::new(file));
    for entry in tar.entries().context("read the release archive")? {
        let mut entry = entry.context("read a release archive entry")?;
        let path = entry.path().context("read an archive entry path")?;
        if path.file_name().and_then(|value| value.to_str()) != Some(name) {
            continue;
        }
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let mut out =
            std::fs::File::create(destination).with_context(|| {
                format!("cannot create {}", destination.display())
            })?;
        std::io::copy(&mut entry, &mut out)
            .context("extract the release binary")?;
        return Ok(());
    }
    bail!("the archive does not contain {name}")
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

/// Where the new binary goes: the running one unless `--binary` says otherwise.
fn target_binary(override_path: Option<&Path>) -> Result<PathBuf> {
    match override_path {
        Some(path) => Ok(path.to_path_buf()),
        None => std::env::current_exe()
            .context("cannot locate the running binary; pass --binary <path>"),
    }
}

/// Restarts the systemd unit that serves this binary, when there is one.
fn restart_service(service: &str) {
    let active = Command::new("systemctl")
        .args(["is-active", "--quiet", service])
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if !active {
        println!(
            "not running under systemd; start it with: systemctl restart {service}"
        );
        return;
    }
    match Command::new("systemctl")
        .args(["restart", service])
        .status()
    {
        Ok(status) if status.success() => {
            println!("restarted {service}");
        },
        Ok(_) => println!(
            "could not restart {service} (permission denied?); run: sudo systemctl restart {service}"
        ),
        Err(err) => println!(
            "could not run systemctl ({err}); run: sudo systemctl restart {service}"
        ),
    }
}

/// `pingwaf-agent upgrade [--check]`.
pub fn upgrade(opts: &crate::cli::UpgradeOpts) -> Result<()> {
    let repo = opts.repo.trim();
    if !repo.contains('/') {
        bail!("--repo must be owner/name (got '{repo}')");
    }
    let target = match opts.version.as_deref() {
        Some(version) => normalize_version(version),
        None => latest_version(repo)?,
    };
    let current = current_version();
    let newer = is_newer(&target, current);
    if opts.check {
        if newer {
            println!("{}: update available ({current} -> {target})", program());
        } else {
            println!(
                "{}: {current} is up to date (latest {target})",
                program()
            );
        }
        return Ok(());
    }
    if !newer && !opts.force {
        println!(
            "{}: {current} is already the newest release (use --force to reinstall)",
            program()
        );
        return Ok(());
    }

    let arch = release_arch()?;
    let tag = format!("v{target}");
    let url = asset_url(repo, &tag, arch);
    let binary = target_binary(opts.binary.as_deref())?;
    let binary = std::fs::canonicalize(&binary)
        .with_context(|| format!("cannot resolve {}", binary.display()))?;
    let directory = binary
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", binary.display()))?
        .to_path_buf();

    // Work next to the target: the staged binary is renamed over it, which is
    // only atomic on the same filesystem.
    let work =
        directory.join(format!(".pingwaf-upgrade-{}", std::process::id()));
    std::fs::create_dir_all(&work).with_context(|| {
        format!(
            "cannot create {}: is {} writable? run with sudo",
            work.display(),
            directory.display()
        )
    })?;
    let result = install_into(&work, &url, &target, &binary);
    let _ = std::fs::remove_dir_all(&work);
    result?;
    println!(
        "upgraded {} {current} -> {target} ({})",
        program(),
        binary.display()
    );
    if !opts.no_restart {
        let service = opts
            .service
            .clone()
            .unwrap_or_else(|| program().to_string());
        restart_service(&service);
    }
    Ok(())
}

fn install_into(
    work: &Path,
    url: &str,
    target: &str,
    binary: &Path,
) -> Result<()> {
    let archive = work.join("release.tar.gz");
    curl_to(url, &archive)?;
    let sidecar = curl(&format!("{url}.sha256"))?;
    let expected = expected_hash(&sidecar)?;
    let actual = sha256_hex(&archive)?;
    if expected != actual {
        bail!(
            "the release archive does not match its .sha256 sidecar \
             (expected {expected}, got {actual}); nothing was replaced"
        );
    }

    let extracted = work.join(program());
    extract_from_targz(&archive, program(), &extracted)?;
    make_executable(&extracted)?;

    // Prove the artifact is the version it claims to be before it replaces
    // anything: a wrong-architecture or truncated binary fails here.
    let probe = Command::new(&extracted)
        .arg("--version")
        .output()
        .with_context(|| {
            format!(
                "the downloaded binary does not run on this host ({}/{});                  the release ships linux/amd64 and linux/arm64 only",
                std::env::consts::OS,
                std::env::consts::ARCH
            )
        })?;
    if !probe.status.success() {
        bail!("the downloaded binary exited non-zero for --version");
    }
    let banner = String::from_utf8_lossy(&probe.stdout);
    if !banner.contains(target) {
        bail!(
            "the downloaded binary reports '{}', expected version {target}; nothing was replaced",
            banner.trim()
        );
    }

    let staged = binary.with_file_name(format!(
        ".{}.new",
        binary
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("binary")
    ));
    std::fs::copy(&extracted, &staged)
        .with_context(|| format!("cannot write {}", staged.display()))?;
    make_executable(&staged)?;
    std::fs::rename(&staged, binary).with_context(|| {
        format!("cannot replace {}: run with sudo", binary.display())
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_numerically() {
        assert!(is_newer("0.33.10", "0.33.9"));
        assert!(is_newer("0.34.0", "0.33.99"));
        assert!(!is_newer("0.33.1", "0.33.1"));
        assert!(!is_newer("0.33.0", "0.33.1"));
        // A pre-release sorts before its release.
        assert!(is_newer("0.33.1", "0.33.1-rc.1"));
        assert!(!is_newer("0.33.1-rc.1", "0.33.1"));
        // A leading v is accepted on either side.
        assert!(is_newer("v0.34.0", "0.33.9"));
    }

    #[test]
    fn a_sidecar_yields_its_digest() {
        let digest = "a".repeat(64);
        let sidecar = format!("{digest}  pingwaf-agent-linux-amd64.tar.gz\n");
        assert_eq!(expected_hash(sidecar.as_bytes()).unwrap(), digest);
        assert!(expected_hash(b"").is_err());
        assert!(expected_hash(b"not-a-digest  file").is_err());
    }

    /// Builds a `.tar.gz` in `dir` with one file per entry.
    fn write_archive(dir: &Path, files: &[(&str, &[u8])]) -> PathBuf {
        let path = dir.join("release.tar.gz");
        let file = std::fs::File::create(&path).unwrap();
        let encoder =
            flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        let mut builder = tar::Builder::new(encoder);
        for (name, body) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, name, std::io::Cursor::new(body))
                .unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();
        path
    }

    #[test]
    fn the_binary_is_extracted_from_the_archive() {
        let dir = std::env::temp_dir()
            .join(format!("pingwaf-upgrade-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // A directory entry first: the extractor must skip non-files.
        let archive = write_archive(
            &dir,
            &[
                ("pingwaf-agent-linux-amd64/", b""),
                ("pingwaf-agent-linux-amd64/README.md", b"notes"),
                ("pingwaf-agent-linux-amd64/pingwaf-agent", b"#!/bin/sh\n"),
            ],
        );
        let out = dir.join("extracted");
        extract_from_targz(&archive, "pingwaf-agent", &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"#!/bin/sh\n");
        // Asking for something the archive does not carry is an error, not an
        // empty file.
        assert!(
            extract_from_targz(&archive, "pingwaf", &dir.join("missing"))
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn asset_names_match_the_release_pipeline() {
        // The workflow publishes `pingwaf-agent-linux-{amd64,arm64}.tar.gz`;
        // a rename there must fail this test rather than 404 an upgrade.
        assert_eq!(
            asset_url("shuaiZend/PingWAF", "v0.33.1", "amd64"),
            format!(
                "https://github.com/shuaiZend/PingWAF/releases/download/v0.33.1/{}-linux-amd64.tar.gz",
                program()
            )
        );
        assert_eq!(
            release_api("shuaiZend/PingWAF"),
            "https://api.github.com/repos/shuaiZend/PingWAF/releases/latest"
        );
    }
}
