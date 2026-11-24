use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared("
            CREATE TABLE static_directory_versions (
                site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
                directory_id text NOT NULL, digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
                published_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(site_id,directory_id,digest)
            );
            INSERT INTO static_directory_versions(site_id,directory_id,digest)
                SELECT id,site_handler->>'directory_id',site_handler->>'digest' FROM sites
                WHERE site_handler->>'kind'='static';
        ").await?;
        Ok(())
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared("
            UPDATE sites SET site_handler=site_handler-'rollback' WHERE site_handler ? 'rollback';
            DROP TABLE static_directory_versions;
        ").await?;
        Ok(())
    }
}
