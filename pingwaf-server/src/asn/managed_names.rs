use super::{
    parse_asn, MAX_ENTRIES, MAX_FILE_BYTES, MAX_NAME_CHARS, NAMES_FILE_ENV,
};
use crate::api::error::ApiError;
use serde::Serialize;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{LazyLock, RwLock};

const PATH: &str = "/var/lib/pingwaf/asn-names.tsv";

struct Table {
    names: HashMap<u32, String>,
    error: Option<String>,
}

static TABLE: LazyLock<RwLock<Table>> = LazyLock::new(|| {
    let result = read_saved(Path::new(PATH));
    let (names, error) = match result {
        Ok(names) => (names, None),
        Err(error) => (HashMap::new(), Some(error)),
    };
    RwLock::new(Table { names, error })
});

fn read_saved(path: &Path) -> Result<HashMap<u32, String>, String> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(HashMap::new())
        },
        Err(e) => return Err(e.to_string()),
    };
    let mut data = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    parse(&data)
}

fn parse(bytes: &[u8]) -> Result<HashMap<u32, String>, String> {
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err("文件超过 16 MiB".into());
    }
    let source = std::str::from_utf8(bytes).map_err(|_| "文件必须为 UTF-8")?;
    let mut names = HashMap::new();
    for (index, line) in
        source.trim_start_matches('\u{feff}').lines().enumerate()
    {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (number, name) = line
            .split_once('\t')
            .ok_or_else(|| format!("第 {} 行缺少制表符", index + 1))?;
        let asn = parse_asn(number)
            .ok_or_else(|| format!("第 {} 行 AS 编号无效", index + 1))?;
        let name = name.trim();
        if name.is_empty()
            || name.chars().count() > MAX_NAME_CHARS
            || name.chars().any(char::is_control)
        {
            return Err(format!("第 {} 行机构名称无效", index + 1));
        }
        if names.insert(asn, name.to_owned()).is_some() {
            return Err(format!("第 {} 行 AS{asn} 重复", index + 1));
        }
        if names.len() > MAX_ENTRIES {
            return Err("超过 200000 条记录".into());
        }
    }
    if names.is_empty() {
        return Err("至少需要一条名称记录".into());
    }
    Ok(names)
}

pub fn lookup(asn: u32) -> Option<String> {
    TABLE
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .names
        .get(&asn)
        .cloned()
}

#[derive(Serialize)]
pub struct Status {
    entries: usize,
    error: Option<String>,
    path: &'static str,
    operator_path: Option<String>,
}

pub fn status() -> Status {
    let table = TABLE.read().unwrap_or_else(|e| e.into_inner());
    Status {
        entries: table.names.len(),
        error: table.error.clone(),
        path: PATH,
        operator_path: super::operator_names_path().map(|path| path.display().to_string()),
    }
}

pub fn preview(data: &[u8]) -> Result<usize, ApiError> {
    Ok(parse(data).map_err(ApiError::BadRequest)?.len())
}

pub fn replace(data: Option<&[u8]>) -> Result<Status, ApiError> {
    let names = data
        .map(parse)
        .transpose()
        .map_err(ApiError::BadRequest)?
        .unwrap_or_default();
    let file = Path::new(PATH);
    if let Some(operator) = std::env::var_os(NAMES_FILE_ENV) {
        let operator = Path::new(&operator);
        if operator == file
            || operator
                .canonicalize()
                .ok()
                .zip(file.canonicalize().ok())
                .is_some_and(|(a, b)| a == b)
        {
            return Err(ApiError::Conflict(
                "运维名称表与控制台文件路径重合，请先分开配置".into(),
            ));
        }
    }
    let mut table = TABLE.write().unwrap_or_else(|e| e.into_inner());
    let io = |e: std::io::Error| ApiError::Internal(e.to_string());
    if let Some(data) = data {
        let parent = file.parent().expect("fixed data directory");
        std::fs::create_dir_all(parent).map_err(io)?;
        let mut pending =
            tempfile::NamedTempFile::new_in(parent).map_err(io)?;
        pending.write_all(data).map_err(io)?;
        pending.as_file().sync_all().map_err(io)?;
        pending.persist(file).map_err(|e| io(e.error))?;
    } else if let Err(e) = std::fs::remove_file(file) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(io(e));
        }
    }
    *table = Table { names, error: None };
    drop(table);
    Ok(status())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_import_and_reload() {
        assert!(parse(b"AS1\tone\n1\ttwo").is_err());
        assert!(parse(b"AS1\tone\ninvalid").is_err());
        assert!(parse(b"# no rows").is_err());
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"# names\nAS42\tExample\n").unwrap();
        assert_eq!(read_saved(file.path()).unwrap()[&42], "Example");
    }
}
