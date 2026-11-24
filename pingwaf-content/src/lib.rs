//! Bounded ZIP validation shared by the static draft API and release installer.
use std::{
    collections::BTreeMap,
    io::{self, Cursor, Read},
    path::Path,
};
use zip::ZipArchive;

pub const MAX_UPLOAD: usize = 8 * 1024 * 1024;
pub const MAX_EXPANDED: u64 = 32 * 1024 * 1024;
const MAX_FILES: usize = 2048;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Validate a draft, or materialize it in a newly created private staging tree.
/// The caller publishes the tree only after this function succeeds.
pub fn inspect(input: &[u8], stage: Option<&Path>) -> io::Result<Vec<String>> {
    if input.len() > MAX_UPLOAD {
        return Err(invalid("archive exceeds upload limit"));
    }
    if let Some(root) = stage {
        if std::fs::read_dir(root)?.next().is_some() {
            return Err(invalid("staging directory must be empty"));
        }
    }
    // Limit the central directory before the ZIP reader allocates its index.
    // These small static bundles never need ZIP64 or multiple disks.
    let search_start = input.len().saturating_sub(22 + u16::MAX as usize);
    let end = input[search_start..]
        .windows(22)
        .enumerate()
        .rev()
        .find(|(offset, end)| {
            end.starts_with(b"PK\x05\x06") && {
                let comment =
                    usize::from(u16::from_le_bytes([end[20], end[21]]));
                search_start + offset + 22 + comment == input.len()
            }
        })
        .map(|(_, end)| end)
        .ok_or_else(|| invalid("invalid ZIP directory"))?;
    let count = usize::from(u16::from_le_bytes([end[10], end[11]]));
    if count > MAX_FILES || end[4..8] != [0; 4] || end[8..10] != end[10..12] {
        return Err(invalid("unsupported ZIP directory"));
    }
    // Reject a forged entry count before the ZIP library builds its map.
    let start = u32::from_le_bytes(end[16..20].try_into().unwrap()) as usize;
    let size = u32::from_le_bytes(end[12..16].try_into().unwrap()) as usize;
    let eocd =
        input.len() - 22 - usize::from(u16::from_le_bytes([end[20], end[21]]));
    if start.checked_add(size) != Some(eocd) {
        return Err(invalid("invalid ZIP directory bounds"));
    }
    let mut directory = &input[start..eocd];
    for _ in 0..count {
        let entry = directory
            .get(..46)
            .filter(|e| e.starts_with(b"PK\x01\x02"))
            .ok_or_else(|| invalid("invalid ZIP directory entry"))?;
        let field_size =
            |i| usize::from(u16::from_le_bytes([entry[i], entry[i + 1]]));
        directory = directory
            .get(46 + field_size(28) + field_size(30) + field_size(32)..)
            .ok_or_else(|| invalid("truncated ZIP directory"))?;
    }
    if !directory.is_empty() {
        return Err(invalid("incorrect ZIP entry count"));
    }
    let mut archive = ZipArchive::new(Cursor::new(input))
        .map_err(|_| invalid("invalid ZIP"))?;
    if archive.len() != count
        || archive.zip64_comment().is_some()
        || archive.offset() != 0
        || archive
            .has_overlapping_files()
            .map_err(|_| invalid("invalid archive layout"))?
    {
        return Err(invalid("ambiguous ZIP entries"));
    }
    let mut entries = BTreeMap::new();
    let mut total = 0u64;
    for index in 0..archive.len() {
        let file = archive
            .by_index(index)
            .map_err(|_| invalid("unreadable ZIP entry"))?;
        let directory = file.is_dir();
        let name = file
            .name()
            .strip_suffix('/')
            .unwrap_or(file.name())
            .to_owned();
        if name.len() > 512
            || name.contains(['\\', ':'])
            || name.chars().any(char::is_control)
            || name
                .split('/')
                .any(|part| part.is_empty() || part.starts_with('.'))
        {
            return Err(invalid("invalid archive path"));
        }
        let kind = file.unix_mode().unwrap_or(0) & 0o170000;
        if kind != 0 && kind != if directory { 0o040000 } else { 0o100000 } {
            return Err(invalid(
                "only regular files and directories are supported",
            ));
        }
        if entries.insert(name.clone(), directory).is_some()
            || directory && file.size() != 0
        {
            return Err(invalid("conflicting archive entry"));
        }
        let expected = file.size();
        if expected > MAX_EXPANDED - total {
            return Err(invalid("expanded archive exceeds size limit"));
        }
        let mut reader = file.take(expected + 1);
        let actual = if let Some(root) = stage {
            let path = root.join(name);
            if directory {
                std::fs::create_dir_all(path)?;
                0
            } else {
                std::fs::create_dir_all(
                    path.parent()
                        .ok_or_else(|| invalid("invalid archive path"))?,
                )?;
                let mut output = std::fs::File::create_new(path)?;
                io::copy(&mut reader, &mut output)?
            }
        } else {
            io::copy(&mut reader, &mut io::sink())?
        };
        if actual != expected {
            return Err(invalid("unexpected ZIP entry size"));
        }
        total += actual;
    }
    if entries.get("index.html") != Some(&false) {
        return Err(invalid("archive requires an index.html at its root"));
    }
    for name in entries.keys() {
        for (i, _) in name.match_indices('/') {
            if entries.get(&name[..i]) == Some(&false) {
                return Err(invalid("file used as a directory"));
            }
        }
    }
    Ok(entries
        .into_iter()
        .filter_map(|(name, directory)| (!directory).then_some(name))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn private_staging_matches_preview_and_refuses_overwriting_files() {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (path, body) in
            [("index.html", "hello"), ("assets/site.css", "body{}")]
        {
            zip.start_file(path, zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(body.as_bytes()).unwrap();
        }
        let bytes = zip.finish().unwrap().into_inner();
        let stage = tempfile::tempdir().unwrap();
        let expected = inspect(&bytes, None).unwrap();
        assert_eq!(inspect(&bytes, Some(stage.path())).unwrap(), expected);
        assert_eq!(
            std::fs::read(stage.path().join("assets/site.css")).unwrap(),
            b"body{}"
        );
        assert!(inspect(&bytes, Some(stage.path())).is_err());
        assert!(inspect(&bytes[..bytes.len() - 1], None).is_err());
    }
}
