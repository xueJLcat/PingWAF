use crate::models::instance_setting;
use sea_orm::{sea_query::OnConflict, DatabaseConnection, EntityTrait, Set};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const KEY: &str = "elasticsearch_buffer_directory";
pub fn root() -> PathBuf {
    std::env::var_os("PINGWAF_ES_BUFFER_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/pingwaf/buffer"))
}

#[derive(Serialize, Deserialize)]
pub struct Choice {
    pub previous: Option<String>,
    pub directory: Option<String>,
}

pub async fn load(db: &DatabaseConnection) -> anyhow::Result<Option<Choice>> {
    let row = instance_setting::Entity::find_by_id(KEY).one(db).await?;
    row.map(|r| serde_json::from_str(&r.value))
        .transpose()
        .map_err(Into::into)
}

pub async fn save(
    db: &DatabaseConnection,
    choice: &Choice,
) -> anyhow::Result<()> {
    use instance_setting::Column;
    instance_setting::Entity::insert(instance_setting::ActiveModel {
        key: Set(KEY.into()),
        value: Set(serde_json::to_string(choice)?),
        updated_at: Set(chrono::Utc::now()),
    })
    .on_conflict(
        OnConflict::column(Column::Key)
            .update_columns([Column::Value, Column::UpdatedAt])
            .to_owned(),
    )
    .exec_without_returning(db)
    .await?;
    Ok(())
}

fn check_path(path: &Path, root: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        path.is_absolute() && root.is_absolute(),
        "缓冲目录须为绝对路径"
    );
    let relative = path
        .strip_prefix(root)
        .map_err(|_| anyhow::anyhow!("目录必须位于 {} 下", root.display()))?;
    anyhow::ensure!(
        relative
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_))),
        "目录不能包含上级路径"
    );
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match current.symlink_metadata() {
            Ok(meta) => anyhow::ensure!(
                meta.is_dir() && !meta.is_symlink(),
                "路径必须为真实目录"
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub fn prepare(choice: &Choice) -> anyhow::Result<()> {
    if choice.previous != choice.directory {
        if let Some(old) = &choice.previous {
            match std::fs::read_dir(old) {
                Ok(entries) => {
                    for entry in entries {
                        let name = entry?.file_name();
                        let name = name.to_string_lossy();
                        anyhow::ensure!(
                            !(name.starts_with("pingwaf-es-")
                                && name.ends_with(".ndjson")),
                            "原目录仍有待发送日志，请排空后切换"
                        );
                    }
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(e.into()),
            }
        }
    }
    if let Some(new) = &choice.directory {
        let path = Path::new(new);
        check_path(path, &root())?;
        std::fs::create_dir_all(path)?;
        tempfile::NamedTempFile::new_in(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn limits_paths_and_preserves_pending_segments() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(check_path(&tmp.path().join("a"), tmp.path()).is_ok());
        assert!(
            check_path(&tmp.path().join("../external"), tmp.path()).is_err()
        );
        std::fs::write(tmp.path().join("pingwaf-es-1.ndjson"), "pending")
            .unwrap();
        assert!(prepare(&Choice {
            previous: Some(tmp.path().display().to_string()),
            directory: None
        })
        .is_err());
    }
}
